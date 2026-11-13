#!/usr/bin/env node
'use strict';
// The ASIX vendor server (README-SERVER.md).
//   node server/index.js                      run the server
//   node server/index.js create-user --username NAME --name "Full Name" --role admin|issuer|approver|viewer [--email ADDR]
//                                             make a staff user (the password comes from the ASIX_VENDOR_NEW_PASSWORD variable, or is asked for); prints the authenticator secret ONCE
//   node server/index.js verify-audit         check the audit log's chain
//   node server/index.js signer-info          show the signing key's public half and the line to paste into the ASIX product
// Options for every command: --config FILE
const config = require('./config');
const { open } = require('./db');
const signerMod = require('./signer');
const { createApp } = require('./app');
const auth = require('./auth');
const audit = require('./audit');
const lic = require('./license');
const reminders = require('./reminders');

function build(cfg, extra = {}) {
  const db = extra.db || open(cfg.dataDir); const signer = extra.signer || signerMod.create(cfg);
  const ctx = { cfg, db, signer, now: extra.now, send: extra.send }; const app = createApp(ctx); return { app, ctx, db, signer };
}
async function listen(cfg, extra) {
  const b = build(cfg, extra);
  if (!cfg.cookieSecure && cfg.bind !== '127.0.0.1' && cfg.bind !== 'localhost') console.warn('WARNING: cookieSecure is off and the server listens beyond this machine: put it behind TLS and set cookieSecure to true.');
  const server = await new Promise((resolve, reject) => { const s = b.app.listen(cfg.port, cfg.bind, () => resolve(s)); s.on('error', reject); });
  const timer = reminders.start(b.ctx);
  const renew = () => { if (b.signer.renew) b.signer.renew().catch((e) => console.error('could not renew the signing service token:', e.message)); };
  renew(); const renewTimer = setInterval(renew, 12 * 3600000); renewTimer.unref();
  return { ...b, server, close: () => new Promise((r) => { clearInterval(timer); clearInterval(renewTimer); server.close(() => r()); }) };
}
function createUser(db, { username, name, role, email, password }, now = new Date()) {
  if (!/^[a-z0-9._-]{3,40}$/i.test(username || '')) throw new Error('the username is 3 to 40 letters, digits, . _ -'); if (!['admin', 'issuer', 'approver', 'viewer'].includes(role)) throw new Error('role must be admin, issuer, approver or viewer');
  const p = auth.passwordProblem(password); if (p) throw new Error(p); if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) throw new Error('that username is taken');
  const secret = auth.newTotpSecret(); db.prepare('INSERT INTO users (username, name, email, role, password_hash, totp_secret, created_at) VALUES (?,?,?,?,?,?,?)').run(username, name || username, email || null, role, auth.hashPassword(password), secret, now.toISOString());
  audit.log(db, 'cli', 'user.create', username, { role }, now); return { secret, uri: auth.otpauthUri(username, secret) };
}
function ask(promptText) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) { let d = ''; process.stdin.on('data', (c) => { d += c; }); process.stdin.on('end', () => resolve(d.split('\n')[0])); return; }
    process.stdout.write(promptText); process.stdin.setRawMode(true); process.stdin.resume(); let s = '';
    process.stdin.on('data', function on(c) { for (const ch of c.toString()) { if (ch === '\r' || ch === '\n') { process.stdin.setRawMode(false); process.stdin.pause(); process.stdin.removeListener('data', on); process.stdout.write('\n'); return resolve(s); } if (ch === '\u0003') process.exit(1); if (ch === '\u007f') s = s.slice(0, -1); else s += ch; } });
  });
}
function args(argv) { const o = { _: [] }; for (let i = 0; i < argv.length; i++) { if (argv[i].startsWith('--')) o[argv[i].slice(2)] = argv[++i]; else o._.push(argv[i]); } return o; }

async function main(argv) {
  const o = args(argv); const cmd = o._[0] || 'serve'; const cfg = config.load(o.config);
  if (cmd === 'serve') { const s = await listen(cfg); const sg = await s.signer.health(); console.log('ASIX vendor server on http://' + cfg.bind + ':' + cfg.port + ' (signer: ' + s.signer.type + ', key id ' + s.signer.kid + '; ' + sg.detail + ')'); return; }
  const db = open(cfg.dataDir);
  if (cmd === 'create-user') {
    const password = process.env.ASIX_VENDOR_NEW_PASSWORD || await ask('Password for the new user (at least ' + auth.MIN_PASSWORD + ' characters): ');
    const r = createUser(db, { username: o.username, name: o.name, role: o.role, email: o.email, password });
    console.log('User created. Add this to an authenticator app (shown ONCE):\n  secret: ' + r.secret + '\n  link:   ' + r.uri); return;
  }
  if (cmd === 'verify-audit') { const v = audit.verify(db); console.log(v.ok ? 'Audit log OK: ' + v.count + ' row(s), chain intact.' : 'AUDIT LOG PROBLEMS:\n' + v.problems.map((p) => '  - ' + p).join('\n')); process.exitCode = v.ok ? 0 : 1; return; }
  if (cmd === 'signer-info') { const s = signerMod.create(cfg); console.log((await s.health()).detail); const pem = await s.publicKeyPem(); console.log('\nPaste this into KEYS in src/licensing/vendor-keys.js of the ASIX product:\n\n  ' + lic.vendorKeysLine(s.kid, pem)); return; }
  throw new Error('unknown command "' + cmd + '" (see the top of server/index.js)');
}
module.exports = { build, listen, createUser };
if (require.main === module) main(process.argv.slice(2)).catch((e) => { console.error('ERROR: ' + e.message); process.exit(1); });
