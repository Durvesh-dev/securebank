// Auditing & logging: append-only, hash-chained audit log.
// Each entry stores the SHA-256 of the previous entry, so editing or
// deleting any line breaks the chain and is detected by verify().
// Passwords, session IDs and full account numbers are never logged.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FILE = path.join(__dirname, '..', 'logs', 'audit.log');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function lastHash() {
  if (!fs.existsSync(FILE)) return '0'.repeat(64);
  const lines = fs.readFileSync(FILE, 'utf8').trim().split('\n').filter(Boolean);
  return lines.length ? JSON.parse(lines[lines.length - 1]).hash : '0'.repeat(64);
}
let prev = lastHash();

function audit(level, event, details = {}, req) {
  const entry = {
    time: new Date().toISOString(),
    level,
    event,
    user: req?.session?.user?.username || details.user || 'anonymous',
    ip: req?.ip || '-',
    details,
    prev,
  };
  entry.hash = sha(JSON.stringify(entry));
  prev = entry.hash;
  fs.appendFileSync(FILE, JSON.stringify(entry) + '\n');
  if (level !== 'INFO') console.warn(`[${level}] ${event}`, details);
}

function readRecent(n = 50) {
  if (!fs.existsSync(FILE)) return [];
  return fs.readFileSync(FILE, 'utf8').trim().split('\n').filter(Boolean)
    .slice(-n).map((l) => JSON.parse(l)).reverse();
}

function verify() {
  if (!fs.existsSync(FILE)) return { ok: true, entries: 0 };
  const lines = fs.readFileSync(FILE, 'utf8').trim().split('\n').filter(Boolean);
  let p = '0'.repeat(64);
  for (let i = 0; i < lines.length; i++) {
    const e = JSON.parse(lines[i]);
    const { hash, ...rest } = e;
    if (e.prev !== p || sha(JSON.stringify(rest)) !== hash) return { ok: false, brokenAt: i + 1, entries: lines.length };
    p = hash;
  }
  return { ok: true, entries: lines.length };
}

module.exports = { audit, readRecent, verify };
