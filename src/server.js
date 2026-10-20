// SecureBank - Secure Online Banking Web Application
// Web Application & Security (WAS) - Assignment 4
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { body } = require('express-validator');

const config = require('./config');
const db = require('./db');
const { audit, readRecent, verify } = require('./logger');
const { issueCsrf, csrfProtect, sessionTimeout, requireAuth, requireRole, validate } = require('./middleware');

const app = express();

// ---------- Deployment / configuration hardening ----------
app.disable('x-powered-by');
if (config.isProd) app.set('trust proxy', 1); // behind HTTPS proxy (Render/Railway)

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"], // clickjacking protection
      formAction: ["'self'"],
    },
  },
  hsts: config.isProd ? { maxAge: 31536000, includeSubDomains: true } : false,
  referrerPolicy: { policy: 'no-referrer' },
}));

app.use(express.json({ limit: '10kb' })); // limit body size

// ---------- Session management ----------
app.use(session({
  name: 'sb.sid',
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,            // not readable by JavaScript (XSS)
    secure: config.isProd,     // HTTPS only in production
    sameSite: 'strict',        // CSRF defence in depth
    maxAge: config.sessionTtlMs,
  },
}));
app.use(sessionTimeout);

app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html' }));

// Brute-force protection on login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => {
    audit('ALERT', 'RATE_LIMIT_LOGIN', {}, req);
    res.status(429).json({ error: 'Too many sign-in attempts. Wait 15 minutes and try again.' });
  },
});
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 100 });
app.use('/api', apiLimiter);

// ---------- Helpers ----------
const mask = (acc) => (acc ? '••••••' + acc.slice(-4) : null);
const publicUser = (u) => ({ name: u.name, username: u.username, role: u.role, account: mask(u.account), balance: u.balance });

// ---------- Routes ----------
app.get('/api/csrf', (req, res) => res.json({ token: issueCsrf(req) }));
app.use('/api', csrfProtect);

// Authentication
app.post('/api/login', loginLimiter,
  body('username').trim().toLowerCase().matches(/^[a-z0-9_]{3,20}$/).withMessage('Enter a valid username and password.'),
  body('password').isString().isLength({ min: 8, max: 64 }).withMessage('Enter a valid username and password.'),
  validate,
  async (req, res, next) => {
    try {
      const { username, password } = req.body;
      const user = db.findUserByName(username);
      const generic = 'Username or password is incorrect.';

      if (user && user.lockedUntil > Date.now()) {
        audit('WARN', 'LOGIN_BLOCKED_LOCKED', { user: username }, req);
        return res.status(423).json({ error: 'This account is temporarily locked. Try again later.' });
      }
      // Compare against a dummy hash when user doesn't exist (prevents user enumeration by timing)
      const hash = user ? user.password : '$2a$12$C6UzMDM.H6dfI/f/IKcEeO7s2P1b7l6zF1Jx3k9n0oR8l0z4l0p7a';
      const ok = await bcrypt.compare(password, hash);

      if (!user || !ok) {
        if (user) {
          user.failed += 1;
          if (user.failed >= config.maxLoginAttempts) {
            user.lockedUntil = Date.now() + config.lockMs;
            user.failed = 0;
            audit('ALERT', 'ACCOUNT_LOCKED', { user: username }, req);
          }
          db.save();
        }
        audit('WARN', 'LOGIN_FAILED', { user: username }, req);
        return res.status(401).json({ error: generic });
      }

      user.failed = 0; db.save();
      // Regenerate session ID on login (prevents session fixation)
      req.session.regenerate((err) => {
        if (err) return next(err);
        req.session.user = { id: user.id, username: user.username, role: user.role };
        req.session.lastSeen = Date.now();
        req.session.csrf = crypto.randomBytes(32).toString('hex');
        audit('INFO', 'LOGIN_SUCCESS', { role: user.role }, req);
        res.json({ user: publicUser(user), csrf: req.session.csrf });
      });
    } catch (e) { next(e); }
  });

app.post('/api/logout', requireAuth, (req, res) => {
  audit('INFO', 'LOGOUT', {}, req);
  req.session.destroy(() => {
    res.clearCookie('sb.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  const u = db.findUserById(req.session.user.id);
  res.json({ user: { ...publicUser(u), accountFull: u.account }, transactions: db.txFor(u.id) });
});

// Transfer: identity and source account always come from the SESSION,
// never from request parameters (prevents parameter manipulation / IDOR).
app.post('/api/transfer', requireAuth, requireRole('customer'),
  body('toAccount').trim().matches(/^\d{12}$/).withMessage('Beneficiary account must be 12 digits.'),
  body('ifsc').trim().toUpperCase().matches(/^[A-Z]{4}0[A-Z0-9]{6}$/).withMessage('IFSC must look like SBKD0001234.'),
  body('amount').isFloat({ min: 1, max: config.maxTransfer }).withMessage(`Amount must be between ₹1 and ₹${config.maxTransfer}.`),
  body('remark').optional().trim().matches(/^[A-Za-z0-9 .,-]{0,40}$/).withMessage('Remark can only use letters, numbers and basic punctuation.'),
  validate,
  (req, res, next) => {
    try {
      const allowed = ['toAccount', 'ifsc', 'amount', 'remark'];
      const extra = Object.keys(req.body).filter((k) => !allowed.includes(k));
      if (extra.length) {
        audit('ALERT', 'PARAMETER_TAMPERING', { extraFields: extra }, req);
        return res.status(400).json({ error: 'Request contained unexpected fields and was rejected.' });
      }
      const from = db.findUserById(req.session.user.id);
      const to = db.findUserByAccount(req.body.toAccount);
      const amount = Math.round(parseFloat(req.body.amount) * 100) / 100;

      if (!to) { audit('WARN', 'TRANSFER_UNKNOWN_BENEFICIARY', {}, req); return res.status(400).json({ error: 'Beneficiary account not found.' }); }
      if (to.id === from.id) return res.status(400).json({ error: 'You cannot transfer to your own account.' });
      if (amount > from.balance) { audit('WARN', 'TRANSFER_INSUFFICIENT_FUNDS', { amount }, req); return res.status(400).json({ error: 'Insufficient balance.' }); }

      from.balance = Math.round((from.balance - amount) * 100) / 100;
      to.balance = Math.round((to.balance + amount) * 100) / 100;
      const remark = req.body.remark || '';
      db.addTx({ userId: from.id, desc: `Transfer to ${mask(to.account)} ${remark}`.trim(), amount: -amount });
      db.addTx({ userId: to.id, desc: `Transfer from ${mask(from.account)} ${remark}`.trim(), amount });
      db.save();
      audit('INFO', 'TRANSFER_SUCCESS', { amount, to: mask(to.account) }, req);
      res.json({ ok: true, balance: from.balance });
    } catch (e) { next(e); }
  });

// Admin area (RBAC)
app.get('/api/admin/users', requireAuth, requireRole('admin'), (req, res) => {
  res.json(db.listUsers().map((u) => ({
    username: u.username, role: u.role, account: mask(u.account),
    locked: u.lockedUntil > Date.now(), hashPrefix: u.password.slice(0, 12) + '…',
  })));
});
app.get('/api/admin/audit', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ integrity: verify(), entries: readRecent(60) });
});

// ---------- Exception management ----------
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  const ref = crypto.randomBytes(4).toString('hex');
  audit('ALERT', 'UNHANDLED_ERROR', { ref, message: err.message, path: req.path }, req);
  // Never leak stack traces to the client
  res.status(err.status || 500).json({ error: `Something went wrong. Reference: ${ref}` });
});

app.listen(config.port, () => {
  audit('INFO', 'SERVER_START', { port: config.port, env: config.isProd ? 'production' : 'development' });
  console.log(`SecureBank running on http://localhost:${config.port}`);
});
