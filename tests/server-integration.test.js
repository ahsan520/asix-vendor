'use strict';
// Against a REAL OpenBao (set ASIX_TEST_OPENBAO_ADDR and ASIX_TEST_OPENBAO_TOKEN to run: `bao server -dev -dev-root-token-id=devroot`), a REAL SMTP conversation, and the ASIX product's own license
// check (set ASIX_PRODUCT_REPO). Without them these tests are skipped.
const { describe, it, afterEach, before } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const { jwtVerify, importSPKI } = require('jose');
const { makeEnv, asUser, seedClient, UUID1 } = require('./helpers');
const signerMod = require('../server/signer');
const lic = require('../server/license');

const ADDR = process.env.ASIX_TEST_OPENBAO_ADDR, ROOT = process.env.ASIX_TEST_OPENBAO_TOKEN, PRODUCT = process.env.ASIX_PRODUCT_REPO, BAO_BIN = process.env.ASIX_TEST_BAO_BIN;
const skipBao = !ADDR || !ROOT;
let env; afterEach(async () => { if (env) await env.close(); env = null; });
const bao = async (method, p, body, token = ROOT) => { const r = await fetch(ADDR + '/v1/' + p, { method, headers: { 'X-Vault-Token': token, 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined }); const t = await r.text(); return { status: r.status, json: t ? JSON.parse(t) : null }; };
const tmp = (name, text) => { const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vint-')), name); fs.writeFileSync(f, text, { mode: 0o600 }); return f; };
const rand = () => Math.random().toString(36).slice(2, 8);
const cfgFor = (key, tokenFile, extra = {}) => ({ signer: { type: 'openbao', addr: ADDR, tokenFile, mount: 'transit', key, kid: 'bao-test', ...extra } });
before(async () => { if (!skipBao) { await bao('POST', 'sys/mounts/transit', { type: 'transit' }); } });

describe('OpenBao as the signer', { skip: skipBao && 'needs a running OpenBao' }, () => {
  const mkKey = async (opts = {}) => { const name = 'k-' + rand(); const r = await bao('POST', 'transit/keys/' + name, { type: 'ed25519', ...opts }); assert.ok(r.status < 300, JSON.stringify(r.json)); return name; };
  const signerFor = (key, token = ROOT, extra) => signerMod.create({ signer: { type: 'openbao', addr: ADDR, tokenFile: tmp('t', token + '\n'), mount: 'transit', key, kid: 'bao-test', ...extra } });
  it('signs inside OpenBao: the signature verifies with the public key it publishes, and the key cannot be exported', async () => {
    const key = await mkKey(); const s = signerFor(key); const pem = await s.publicKeyPem(); assert.match(pem, /BEGIN PUBLIC KEY/); const bytes = Buffer.from('header.payload'); const sig = await s.sign(bytes); assert.strictEqual(sig.length, 64);
    assert.strictEqual(require('crypto').verify(null, bytes, pem, sig), true); assert.strictEqual(require('crypto').verify(null, Buffer.from('header.payloaX'), pem, sig), false);
    assert.strictEqual((await bao('GET', 'transit/export/signing-key/' + key + '/1')).status, 400, 'a non-exportable key refuses export'); assert.deepStrictEqual(await s.health(), { ok: true, detail: 'OpenBao is up and unsealed' });
  });
  it('refuses a key that is not safe or not the right kind, and says so plainly', async () => {
    const exp = await mkKey({ exportable: true }); await assert.rejects(() => signerFor(exp).publicKeyPem(), /exportable: create it again with exportable=false/);
    const ec = 'ec-' + rand(); await bao('POST', 'transit/keys/' + ec, { type: 'ecdsa-p256' }); await assert.rejects(() => signerFor(ec).publicKeyPem(), /must be type ed25519, it is ecdsa-p256/);
    await assert.rejects(() => signerFor('nope-' + rand()).publicKeyPem(), /was not found in transit/);
  });
  it('explains an unreachable server, a refused token and a missing token file', async () => {
    const key = await mkKey(); await assert.rejects(() => signerMod.create({ signer: { type: 'openbao', addr: 'http://127.0.0.1:1', tokenFile: tmp('t', 'x'), mount: 'transit', key, kid: 'k' } }).sign(Buffer.from('x')), /cannot be reached/);
    await assert.rejects(() => signerFor(key, 'bogus-token').sign(Buffer.from('x')), /refused this server's token/); await assert.rejects(() => signerMod.create({ signer: { type: 'openbao', addr: ADDR, tokenFile: '/nonexistent/token', mount: 'transit', key, kid: 'k' } }).sign(Buffer.from('x')), /ENOENT/);
    const h = await signerMod.create({ signer: { type: 'openbao', addr: 'http://127.0.0.1:1', tokenFile: tmp('t', 'x'), mount: 'transit', key, kid: 'k' } }).health(); assert.strictEqual(h.ok, false); assert.match(h.detail, /cannot reach OpenBao/);
  });
  it('our shipped policy lets the server sign and read the public key and NOTHING else (no export, rotate, delete, config or other keys)', async () => {
    const key = await mkKey(); const other = await mkKey(); const hcl = fs.readFileSync(path.join(__dirname, '..', 'deploy/openbao/asix-sign.hcl'), 'utf8').replace(/transit\/sign\/asix-license/g, 'transit/sign/' + key).replace(/transit\/keys\/asix-license/g, 'transit/keys/' + key);
    const pn = 'asix-sign-' + rand(); assert.ok((await bao('PUT', 'sys/policies/acl/' + pn, { policy: hcl })).status < 300); const tok = (await bao('POST', 'auth/token/create', { policies: [pn], period: '768h', no_parent: true })).json.auth.client_token;
    const s = signerFor(key, tok); assert.ok(await s.publicKeyPem()); assert.strictEqual((await s.sign(Buffer.from('ok'))).length, 64);
    for (const [m, p, b] of [['POST', 'transit/keys/' + key + '/rotate'], ['DELETE', 'transit/keys/' + key], ['GET', 'transit/export/signing-key/' + key + '/1'], ['POST', 'transit/keys/' + key + '/config', { deletion_allowed: true }], ['POST', 'transit/sign/' + other, { input: 'eA==' }], ['GET', 'transit/keys/' + other], ['GET', 'sys/policies/acl'], ['POST', 'transit/keys/new-' + rand(), {}]]) assert.strictEqual((await bao(m, p, b, tok)).status, 403, m + ' ' + p);
    await s.renew();   // the token renews itself
  });
  it('the setup script makes a working, locked-down key and a token the server can use', { skip: !BAO_BIN && 'set ASIX_TEST_BAO_BIN to the bao binary' }, async () => {
    const key = 'setup-' + rand(); const tf = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vset-')), 'bao.token'); const r = spawnSync('bash', [path.join(__dirname, '..', 'deploy/openbao/setup.sh'), '--key', key, '--token-file', tf], { encoding: 'utf8', env: { ...process.env, BAO_ADDR: ADDR, BAO_TOKEN: ROOT, BAO_BIN } });
    assert.strictEqual(r.status, 0, r.stderr + r.stdout); assert.strictEqual(fs.statSync(tf).mode & 0o777, 0o600); const info = (await bao('GET', 'transit/keys/' + key)).json.data; assert.strictEqual(info.type, 'ed25519'); assert.strictEqual(info.exportable, false); assert.strictEqual(info.allow_plaintext_backup, false);
    const s = signerMod.create({ signer: { type: 'openbao', addr: ADDR, tokenFile: tf, mount: 'transit', key, kid: 'k' } }); assert.ok(await s.publicKeyPem()); assert.strictEqual((await s.sign(Buffer.from('x'))).length, 64);
    assert.strictEqual(spawnSync('bash', [path.join(__dirname, '..', 'deploy/openbao/setup.sh'), '--key', key], { encoding: 'utf8', env: { ...process.env, BAO_ADDR: ADDR, BAO_TOKEN: ROOT, BAO_BIN } }).status, 0, 'safe to run again');
    assert.strictEqual(spawnSync('bash', [path.join(__dirname, '..', 'deploy/openbao/setup.sh'), '--key', 'bad key!'], { encoding: 'utf8', env: { ...process.env, BAO_ADDR: ADDR, BAO_TOKEN: ROOT, BAO_BIN } }).status, 2);
  });
  it('the whole server issues a license signed inside OpenBao, shows the public key and the line for the product, and the license verifies', async () => {
    const key = await mkKey(); env = await makeEnv({ ...cfgFor(key, tmp('t', ROOT + '\n')), signerObj: undefined }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash);
    const r = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', tenants: 2 }); assert.strictEqual(r.status, 201, JSON.stringify(r.json)); const token = env.db.prepare('SELECT token FROM licenses WHERE id = ?').get(r.json.id).token;
    const sg = (await ash.get('/api/signer')).json; assert.strictEqual(sg.type, 'openbao'); assert.strictEqual(sg.health.ok, true); assert.match(sg.vendor_keys_line, /^\{ kid: 'bao-test', pem: '-----BEGIN PUBLIC KEY-----\\n/); const { payload, protectedHeader } = await jwtVerify(token, await importSPKI(sg.public_key, 'EdDSA'), { issuer: 'asix' }); assert.strictEqual(protectedHeader.kid, 'bao-test'); assert.strictEqual(payload.sub, 'Acme Corp');
    assert.strictEqual((await bao('POST', 'transit/keys/' + key + '/rotate')).status, 200); const r2 = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', supersedes: r.json.id }); assert.strictEqual(r2.status, 201, 'after a key rotation the next license is checked against the new key version');
  });
  it('a sealed or unreachable OpenBao stops issuing with a plain message and leaves nothing half-done', async () => {
    const key = await mkKey(); env = await makeEnv({ ...cfgFor(key, tmp('t', ROOT + '\n'), { addr: 'http://127.0.0.1:1' }), signerObj: undefined }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const r = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' });
    assert.strictEqual(r.status, 502); assert.match(r.json.error.message, /signing service cannot be reached/); assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM licenses WHERE token IS NOT NULL').get().n, 0); const sg = (await ash.get('/api/signer')).json; assert.strictEqual(sg.health.ok, false); assert.match(sg.problem, /cannot be reached/);
  });
  it('a license signed in OpenBao is accepted by the ASIX product itself, with its grace period and limits (needs ASIX_PRODUCT_REPO)', { skip: !PRODUCT && 'set ASIX_PRODUCT_REPO' }, async () => {
    const key = await mkKey(); env = await makeEnv({ ...cfgFor(key, tmp('t', ROOT + '\n')), approval: 'none', signerObj: undefined }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const r = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'enterprise', tenants: 4, grace: 10, days: 30 });
    const token = env.db.prepare('SELECT token FROM licenses WHERE id = ?').get(r.json.id).token; const pem = (await ash.get('/api/signer')).json.public_key; const product = require(path.join(PRODUCT, 'src/licensing/license.js')); const keys = [{ kid: 'bao-test', pem }]; const at = (days) => new Date(env.clock.t + days * 86400000);
    const ok = await product.load({}, at(1), { keys, iid: UUID1, token }); assert.strictEqual(ok.status, 'valid'); assert.strictEqual(ok.kind, 'enterprise'); assert.deepStrictEqual(ok.limits, { tenants: 4 }); assert.strictEqual(ok.grace_days, 10); assert.strictEqual(ok.customer, 'Acme Corp');
    assert.strictEqual((await product.load({}, at(35), { keys, iid: UUID1, token })).status, 'grace'); assert.strictEqual((await product.load({}, at(45), { keys, iid: UUID1, token })).status, 'expired'); assert.strictEqual((await product.load({}, at(1), { keys, iid: '99999999-2222-4333-8444-555555555555', token })).status, 'wrong_install');
  });
});

describe('real e-mail over SMTP', () => {
  it('delivers the license as an attachment with the right headers, and a refused message is reported', async () => {
    const got = []; let reject = false;
    const smtp = new SMTPServer({ authOptional: true, disabledCommands: ['STARTTLS'], onRcptTo(a, s, cb) { if (reject && /bad@/.test(a.address)) return cb(Object.assign(new Error('550 mailbox unavailable'), { responseCode: 550 })); cb(); }, onData(stream, s, cb) { simpleParser(stream).then((m) => { got.push(m); cb(); }).catch(cb); } });
    await new Promise((r) => smtp.listen(0, '127.0.0.1', r)); const port = smtp.server.address().port;
    try {
      env = await makeEnv({ realMail: true, smtp: { host: '127.0.0.1', port, secure: false, from: 'ASIX Licensing <licenses@vendor.test>', replyTo: 'help@vendor.test' } }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const id = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' })).json.id; const token = env.db.prepare('SELECT token FROM licenses WHERE id = ?').get(id).token;
      const r = await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'], message: 'Welcome.' }); assert.strictEqual(r.status, 200, JSON.stringify(r.json)); const m = got[0]; assert.strictEqual(m.subject, 'Your ASIX license for Acme Corp'); assert.deepStrictEqual([m.from.value[0].name, m.from.value[0].address], ['ASIX Licensing', 'licenses@vendor.test']); assert.strictEqual(m.replyTo.value[0].address, 'help@vendor.test'); assert.strictEqual(m.to.text, 'pat@acme.test');
      assert.match(m.text, /Settings, then License/); assert.strictEqual(m.attachments.length, 1); assert.strictEqual(m.attachments[0].filename, 'asix-license-acme-corp.jwt'); assert.strictEqual(m.attachments[0].content.toString().trim(), token); assert.ok(!m.html, 'plain text only');
      reject = true; const bad = await ash.post('/api/licenses/' + id + '/send', { to: ['bad@acme.test'] }); assert.strictEqual(bad.status, 502); assert.match(bad.json.error.message, /550/); assert.strictEqual(env.db.prepare("SELECT COUNT(*) AS n FROM emails WHERE status = 'failed'").get().n, 1);
      const admin = await asUser(env, 'admin'); reject = false; assert.strictEqual((await admin.post('/api/settings/test-email', { to: 'me@vendor.test' })).status, 200); assert.strictEqual(got.at(-1).subject, 'ASIX vendor server: test message');
    } finally { await new Promise((r) => smtp.close(r)); }
  });
  it('an SMTP server that is down is a plain failure; unset SMTP is a clear message', async () => {
    env = await makeEnv({ realMail: true, smtp: { host: '127.0.0.1', port: 1, from: 'a@b.test' } }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const id = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' })).json.id;
    const r = await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'] }); assert.strictEqual(r.status, 502); assert.match(r.json.error.message, /could not be sent/); await env.close();
    env = await makeEnv({ realMail: true, smtp: { host: null, from: null } }); const a2 = await asUser(env, 'ash'); const s2 = await seedClient(a2); const id2 = (await a2.post('/api/licenses/request', { installation_pk: s2.installation_pk, template: 'residential' })).json.id; const r2 = await a2.post('/api/licenses/' + id2 + '/send', { to: ['pat@acme.test'] }); assert.strictEqual(r2.status, 400); assert.match(r2.json.error.message, /e-mail is not set up/);
  });
});

describe('the pages and the settings file', () => {
  const root = path.join(__dirname, '..');
  it('the page code sets nothing as HTML, uses no browser dialogs or eval, and talks only to its own /api', () => {
    const src = fs.readFileSync(path.join(root, 'public/app.js'), 'utf8').replace(/\/\/.*$/gm, ''); for (const b of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'alert(', 'confirm(', 'prompt(', 'localStorage', 'sessionStorage']) assert.ok(!src.includes(b), b);
    for (const m of src.matchAll(/fetch\(([^,)]+)/g)) assert.match(m[1], /'\/api'/); assert.ok(!/https?:\/\//.test(src), 'no outside address');
  });
  it('the page loads only its own script and style, with no inline script or style', () => { const h = fs.readFileSync(path.join(root, 'public/index.html'), 'utf8'); assert.deepStrictEqual([...h.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1]).sort(), ['/app.js', '/style.css']); assert.ok(!/<script(?![^>]*\ssrc=)/.test(h)); assert.ok(!/\sstyle=|\son\w+=/.test(h)); });
  it('the configuration is checked, merges over the defaults, and holds no secrets', () => {
    const config = require('../server/config'); assert.strictEqual(config.load('/nonexistent.json', {}).approval, 'enterprise'); for (const bad of [{ approval: 'sometimes' }, { port: 0 }, { signer: { type: 'magic' } }, { signer: { kid: 'bad kid!' } }, { reminderDays: [0] }, { sessionHours: 100 }, { signer: { type: 'openbao', addr: 'ftp://x' } }]) assert.throws(() => config.load('/nonexistent.json', bad), /configuration/, JSON.stringify(bad));
    const f = tmp('c.json', JSON.stringify({ port: 9000, approval: 'all', signer: { key: 'mykey' } })); const c = config.load(f); assert.strictEqual(c.port, 9000); assert.strictEqual(c.approval, 'all'); assert.strictEqual(c.signer.key, 'mykey'); assert.strictEqual(c.signer.mount, 'transit'); assert.throws(() => config.load(tmp('bad.json', '{nope')), /not valid JSON/);
    const ex = JSON.parse(fs.readFileSync(path.join(root, 'config.example.json'), 'utf8')); assert.ok(!/token"|password"|secret/i.test(Object.keys({ ...ex.signer, ...ex.smtp }).join(' ').replace(/tokenFile|passFile/g, '')), 'the example names files, never secrets'); config.load(path.join(root, 'config.example.json'), { dataDir: ':memory:' });
  });
  it('the service file drops privileges and writes only to the data directory', () => { const u = fs.readFileSync(path.join(root, 'deploy/systemd/asix-vendor.service'), 'utf8'); for (const w of ['User=asixvendor', 'NoPrivilegeses'.slice(0, 0) + 'NoNewPrivileges=true', 'ProtectSystem=strict', 'ReadWritePaths=/var/lib/asix-vendor', 'UMask=0077']) assert.ok(u.includes(w), w); });
});
