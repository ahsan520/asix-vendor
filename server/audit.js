'use strict';
// The audit log: every sign-in, change, request, approval, signing and e-mail is one row. Each row carries the hash of the row before it, so an edited, removed or reordered row is detected by
// verify(). Nothing secret is ever written here (no passwords, no license text, no keys).
const crypto = require('crypto');
const ZERO = '0'.repeat(64);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const rowText = (r) => [r.prev_hash, r.at, r.actor, r.action, r.target || '', r.detail || ''].join('\u241f');

function log(db, actor, action, target, detail, now = new Date()) {
  const last = db.prepare('SELECT hash FROM audit ORDER BY id DESC LIMIT 1').get();
  const row = { prev_hash: last ? last.hash : ZERO, at: now.toISOString(), actor: String(actor || 'system'), action, target: target === undefined || target === null ? null : String(target), detail: detail === undefined ? null : JSON.stringify(detail) };
  row.hash = sha(rowText(row));
  db.prepare('INSERT INTO audit (at, actor, action, target, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)').run(row.at, row.actor, row.action, row.target, row.detail, row.prev_hash, row.hash);
}
function verify(db) {
  const problems = []; let prev = ZERO, n = 0;
  for (const r of db.prepare('SELECT * FROM audit ORDER BY id').all()) {
    n += 1;
    if (r.prev_hash !== prev) problems.push('row ' + r.id + ': the chain is broken (a row before it was edited, removed or reordered)');
    if (sha(rowText(r)) !== r.hash) problems.push('row ' + r.id + ': the row itself was changed');
    prev = r.hash;
  }
  return { ok: problems.length === 0, count: n, problems };
}
function list(db, limit = 100) {
  return db.prepare('SELECT id, at, actor, action, target, detail FROM audit ORDER BY id DESC LIMIT ?').all(Math.max(1, Math.min(500, limit | 0 || 100))).map((r) => ({ ...r, detail: r.detail ? JSON.parse(r.detail) : null }));
}
module.exports = { log, verify, list, ZERO };
