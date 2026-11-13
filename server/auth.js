'use strict';
// Passwords, one-time codes and sessions. Passwords are stored as scrypt hashes; every user must have an authenticator app (RFC 6238 codes, 6 digits, 30 seconds); a session is a random
// token whose hash is stored, sent as an HttpOnly SameSite=Strict cookie, with a separate CSRF token the page must send back on every change.
const crypto = require('crypto');

const MIN_PASSWORD = 12;
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const LOCK_AFTER = 5, LOCK_MINUTES = 15;

function hashPassword(pw) {
  const salt = crypto.randomBytes(16); const N = 16384;
  const h = crypto.scryptSync(pw, salt, 32, { N, r: 8, p: 1 });
  return ['scrypt', N, salt.toString('base64'), h.toString('base64')].join('$');
}
function checkPassword(pw, stored) {
  const [alg, N, salt, hash] = String(stored || '').split('$');
  if (alg !== 'scrypt') { crypto.scryptSync(String(pw), 'x'.repeat(16), 32); return false; }   // spend the same time for an unknown user
  const h = crypto.scryptSync(String(pw), Buffer.from(salt, 'base64'), 32, { N: +N, r: 8, p: 1 });
  const want = Buffer.from(hash, 'base64'); return want.length === h.length && crypto.timingSafeEqual(want, h);
}
const passwordProblem = (pw) => (typeof pw !== 'string' || pw.length < MIN_PASSWORD ? 'The password must be at least ' + MIN_PASSWORD + ' characters' : pw.length > 200 ? 'The password is too long' : null);

const b32encode = (buf) => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
const b32decode = (s) => { let bits = ''; for (const c of String(s).replace(/=+$/, '').toUpperCase()) { const i = B32.indexOf(c); if (i < 0) throw new Error('bad base32'); bits += i.toString(2).padStart(5, '0'); } const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const newTotpSecret = () => b32encode(crypto.randomBytes(20));
function totpAt(secret, step, digits = 6) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(msg).digest(); const o = h[19] & 15;
  const code = ((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 10 ** digits; return String(code).padStart(digits, '0');
}
// The step a code matches (within one step either side), or null. The caller refuses a step that is not newer than the last one used: a code works once.
function totpMatch(secret, code, now = new Date()) {
  if (!/^\d{6}$/.test(String(code || ''))) return null; const cur = Math.floor(now.getTime() / 30000);
  for (const s of [cur, cur - 1, cur + 1]) { const a = Buffer.from(totpAt(secret, s)), b = Buffer.from(String(code)); if (crypto.timingSafeEqual(a, b)) return s; }
  return null;
}
const otpauthUri = (user, secret) => 'otpauth://totp/ASIX%20Vendor:' + encodeURIComponent(user) + '?secret=' + secret + '&issuer=ASIX%20Vendor&digits=6&period=30';

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
function createSession(db, userId, hours, now = new Date()) {
  const token = crypto.randomBytes(32).toString('base64url'), csrf = crypto.randomBytes(24).toString('base64url');
  db.prepare('INSERT INTO sessions (id, user_id, csrf, created_at, expires_at) VALUES (?,?,?,?,?)').run(sha(token), userId, csrf, now.toISOString(), new Date(now.getTime() + hours * 3600000).toISOString());
  return { token, csrf };
}
function sessionUser(db, token, now = new Date()) {
  if (!token || typeof token !== 'string') return null;
  const s = db.prepare('SELECT s.csrf, s.expires_at, u.id, u.username, u.name, u.email, u.role, u.active FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?').get(sha(token));
  if (!s || !s.active || new Date(s.expires_at) <= now) return null;
  return { id: s.id, username: s.username, name: s.name, email: s.email, role: s.role, csrf: s.csrf };
}
const endSession = (db, token) => { if (token) db.prepare('DELETE FROM sessions WHERE id = ?').run(sha(token)); };
const endAllSessions = (db, userId) => db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);

// Roles: viewer reads; issuer also manages clients and requests, sends and renews licenses; approver also approves or rejects; admin also manages users and settings.
const CAN = { read: ['viewer', 'issuer', 'approver', 'admin'], issue: ['issuer', 'admin'], approve: ['approver', 'admin'], admin: ['admin'] };
const can = (user, what) => !!user && CAN[what].includes(user.role);

module.exports = { MIN_PASSWORD, LOCK_AFTER, LOCK_MINUTES, hashPassword, checkPassword, passwordProblem, newTotpSecret, totpAt, totpMatch, otpauthUri, b32encode, b32decode, createSession, sessionUser, endSession, endAllSessions, can, sha };
