'use strict';
// Test helpers: a whole vendor server on a random port with a throwaway database and a throwaway signing key, a fake clock, and a small HTTP client that keeps the cookie and CSRF token.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const config = require('../server/config');
const { build, createUser } = require('../server/index');
const auth = require('../server/auth');

const PW = 'correct horse battery staple';
let keyFile;
function localKey() {
  if (keyFile) return keyFile;
  const { privateKey } = crypto.generateKeyPairSync('ed25519'); keyFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vsrv-key-')), 'k.pem'); fs.writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' })); return keyFile;
}
async function makeEnv(over = {}) {
  const clock = { t: Date.parse('2026-11-11T12:00:00Z') }; const sent = [];
  const cfg = config.load('/nonexistent.json', { dataDir: ':memory:', cookieSecure: false, port: 8443, signer: { type: 'local', keyFile: localKey(), kid: 'test-1' }, smtp: { host: 'smtp.example.test', from: 'ASIX <lic@example.test>' }, ...over });
  const extra = { now: () => new Date(clock.t), send: over.realMail ? undefined : (over.send || (async (c, m) => { sent.push(m); return { message_id: '<test@x>' }; })), signer: over.signerObj };
  const b = build(cfg, extra); const server = await new Promise((r) => { const s = b.app.listen(0, '127.0.0.1', () => r(s)); });
  const base = 'http://127.0.0.1:' + server.address().port; const secrets = {};
  const mk = (username, role) => { const r = createUser(b.db, { username, name: username[0].toUpperCase() + username.slice(1), role, email: username + '@vendor.test', password: PW }, new Date(clock.t)); secrets[username] = r.secret; };
  for (const [u, r] of [['admin', 'admin'], ['ash', 'issuer'], ['bob', 'approver'], ['vera', 'viewer']]) mk(u, r);
  const env = { ...b, cfg, clock, sent, base, secrets, close: () => new Promise((r) => server.close(() => r())), mk };
  env.client = () => makeClient(env); return env;
}
function makeClient(env) {
  const c = { cookie: null, csrf: null, last: null };
  c.req = (method, p, body, opts = {}) => new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body); const headers = { ...(data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {}), ...(c.cookie && !opts.nocookie ? { cookie: c.cookie } : {}), ...(c.csrf && opts.csrf !== false ? { 'x-csrf-token': opts.csrf || c.csrf } : {}), ...(opts.headers || {}) };
    const r = http.request(env.base + p, { method, headers }, (res) => { let b = ''; res.on('data', (x) => { b += x; }); res.on('end', () => { let json = null; try { json = JSON.parse(b); } catch { /* text */ } c.last = res; resolve({ status: res.statusCode, json, text: b, headers: res.headers }); }); });
    r.on('error', reject); if (data) r.write(data); r.end();
  });
  c.login = async (u, pw = PW, code) => {
    const step = Math.floor(env.clock.t / 30000); const r = await c.req('POST', '/api/login', { username: u, password: pw, code: code === undefined ? auth.totpAt(env.secrets[u], step) : code });
    env.clock.t += 31000;   // a code works once: move to the next 30-second step for the next sign-in
    if (r.status === 200) { const sc = r.headers['set-cookie']; c.cookie = sc[0].split(';')[0]; c.csrf = r.json.csrf; } return r;
  };
  for (const m of ['get', 'post', 'put', 'delete']) c[m] = (p, b, o) => c.req(m.toUpperCase(), p, b, o);
  return c;
}
const UUID1 = '11111111-2222-4333-8444-555555555555', UUID2 = '99999999-2222-4333-8444-555555555555';
async function asUser(env, u) { const c = env.client(); const r = await c.login(u); if (r.status !== 200) throw new Error('login failed for ' + u + ': ' + JSON.stringify(r.json)); return c; }
// a client with one installation, made by the issuer
async function seedClient(ash, name = 'Acme Corp', iid = UUID1, contacts) {
  const c = await ash.post('/api/clients', { name, reference: 'INV-1', contacts: contacts || [{ name: 'Pat', email: 'pat@acme.test', license: true, renewals: true }] });
  const i = await ash.post('/api/clients/' + c.json.id + '/installations', { label: 'Head office', installation_id: iid });
  return { client_id: c.json.id, installation_pk: i.json.id };
}
module.exports = { makeEnv, makeClient, asUser, seedClient, PW, UUID1, UUID2 };
