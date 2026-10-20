// Security middleware: CSRF protection, authentication, authorization (RBAC),
// session idle-timeout, and centralized validation-error handling.
const crypto = require('crypto');
const { validationResult } = require('express-validator');
const { audit } = require('./logger');
const config = require('./config');

// CSRF: synchronizer token stored in the session, sent by the client in a header.
function issueCsrf(req) {
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(32).toString('hex');
  return req.session.csrf;
}

function csrfProtect(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const sent = req.get('X-CSRF-Token') || '';
  const real = req.session.csrf || '';
  const ok = sent.length === real.length && real.length > 0 &&
    crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(real));
  if (!ok) {
    audit('ALERT', 'CSRF_REJECTED', { path: req.path }, req);
    return res.status(403).json({ error: 'Your session token is invalid. Refresh the page and try again.' });
  }
  next();
}

// Session idle timeout (in addition to cookie maxAge).
function sessionTimeout(req, res, next) {
  const s = req.session;
  if (s.user) {
    if (Date.now() - (s.lastSeen || 0) > config.sessionTtlMs) {
      audit('WARN', 'SESSION_EXPIRED', { user: s.user.username }, req);
      return s.destroy(() => res.status(401).json({ error: 'Your session expired. Please sign in again.' }));
    }
    s.lastSeen = Date.now();
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    audit('WARN', 'UNAUTHENTICATED_ACCESS', { path: req.path }, req);
    return res.status(401).json({ error: 'Please sign in.' });
  }
  next();
}

// Authorization: role-based access control, enforced on the server.
const requireRole = (role) => (req, res, next) => {
  if (req.session.user?.role !== role) {
    audit('ALERT', 'AUTHORIZATION_DENIED', { path: req.path, needed: role, had: req.session.user?.role }, req);
    return res.status(403).json({ error: 'You do not have permission to do that.' });
  }
  next();
};

function validate(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const fields = errors.array().map((e) => e.path);
    audit('WARN', 'INPUT_REJECTED', { path: req.path, fields }, req);
    return res.status(400).json({ error: errors.array()[0].msg });
  }
  next();
}

module.exports = { issueCsrf, csrfProtect, sessionTimeout, requireAuth, requireRole, validate };
