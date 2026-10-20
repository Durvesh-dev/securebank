// Configuration management: all settings come from environment variables,
// with safe defaults. Secrets are never hard-coded or committed.
require('dotenv').config();

const isProd = process.env.NODE_ENV === 'production';

if (isProd && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  console.error('FATAL: SESSION_SECRET must be set (32+ chars) in production.');
  process.exit(1);
}

module.exports = Object.freeze({
  isProd,
  port: parseInt(process.env.PORT, 10) || 3000,
  sessionSecret: process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex'),
  sessionTtlMs: (parseInt(process.env.SESSION_TTL_MIN, 10) || 10) * 60 * 1000,
  maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS, 10) || 5,
  lockMs: (parseInt(process.env.LOCK_MINUTES, 10) || 15) * 60 * 1000,
  maxTransfer: parseInt(process.env.MAX_TRANSFER, 10) || 50000,
  bcryptRounds: 12,
});
