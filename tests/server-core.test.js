'use strict';
// Sign-in, sessions, roles, clients and installations.
const { describe, it, afterEach } = require('node:test');
const assert = require('assert');
const { makeEnv, asUser, seedClient, PW, UUID1, UUID2 } = require('./helpers');
const auth = require('../server/auth');
const audit = require('../server/audit');

let env; afterEach(async () => { if (env) await env.close(); env = null; });

describe('sign-in', () => {
  it('signs in with password and authenticator code, sets an HttpOnly SameSite=Strict cookie, never returns a hash or secret', async () => {
    env = await makeEnv(); const c = env.client(); const r = await c.login('ash'); assert.strictEqual(r.status, 200); assert.strictEqual(r.json.user.role, 'issuer'); assert.ok(r.json.csrf);
    const sc = r.headers['set-cookie'][0]; assert.match(sc, /asix_vendor_sid=/); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/); assert.doesNotMatch(sc, /Secure/);
    assert.ok(!/hash|secret|scrypt/i.test(r.text)); const me = await c.get('/api/me'); assert.strictEqual(me.json.user.username, 'ash'); assert.ok(!/password|totp/i.test(me.text));
  });
  it('the cookie is Secure when the server is configured for TLS', async () => { env = await makeEnv({ cookieSecure: true }); const r = await env.client().login('ash'); assert.match(r.headers['set-cookie'][0], /; Secure/); });
  it('every failure gives the same plain answer: wrong password, wrong code, unknown user, missing fields, a code used twice', async () => {
    env = await makeEnv(); const c = env.client(); const step = () => Math.floor(env.clock.t / 30000);
    const answers = [await c.req('POST', '/api/login', { username: 'ash', password: 'wrong wrong wrong', code: auth.totpAt(env.secrets.ash, step()) }), await c.req('POST', '/api/login', { username: 'ash', password: PW, code: '000000' }), await c.req('POST', '/api/login', { username: 'nobody', password: PW, code: '123456' }), await c.req('POST', '/api/login', {}), await c.req('POST', '/api/login', { username: 'ash', password: PW })];
    for (const a of answers) { assert.strictEqual(a.status, 401); assert.strictEqual(a.json.error.message, 'Sign-in failed'); }
    const code = auth.totpAt(env.secrets.ash, step()); assert.strictEqual((await c.req('POST', '/api/login', { username: 'ash', password: PW, code })).status, 200);
    assert.strictEqual((await env.client().req('POST', '/api/login', { username: 'ash', password: PW, code })).status, 401, 'the same code a second time');
  });
  it('locks an account for 15 minutes after 5 wrong tries, even for the right password, then lets it in again', async () => {
    env = await makeEnv(); const c = env.client(); for (let i = 0; i < 5; i++) assert.strictEqual((await c.login('bob', 'wrong wrong wrong')).status, 401);
    assert.strictEqual((await c.login('bob')).status, 401); env.clock.t += 16 * 60000; assert.strictEqual((await c.login('bob')).status, 200);
  });
  it('a disabled user cannot sign in and an open session ends at once', async () => {
    env = await makeEnv(); const admin = await asUser(env, 'admin'); const vi = await asUser(env, 'vera'); const id = (await admin.get('/api/users')).json.users.find((u) => u.username === 'vera').id;
    assert.strictEqual((await admin.put('/api/users/' + id, { name: 'Vi', role: 'viewer', active: false })).status, 200); assert.strictEqual((await vi.get('/api/me')).status, 401); assert.strictEqual((await env.client().login('vera')).status, 401);
  });
  it('every other call needs a session; a session ends at logout and after its hours', async () => {
    env = await makeEnv(); const anon = env.client(); for (const p of ['/api/me', '/api/clients', '/api/licenses', '/api/dashboard', '/api/audit', '/api/users']) assert.strictEqual((await anon.get(p)).status, 401, p);
    assert.strictEqual((await anon.get('/api/health')).json.status, 'up'); const c = await asUser(env, 'ash'); assert.strictEqual((await c.post('/api/logout', {})).status, 200); assert.strictEqual((await c.get('/api/me')).status, 401);
    const d = await asUser(env, 'ash'); env.clock.t += 9 * 3600000; assert.strictEqual((await d.get('/api/me')).status, 401);
  });
  it('changes need the CSRF token the page was given: without it, or with another, the change is refused', async () => {
    env = await makeEnv(); const c = await asUser(env, 'ash'); assert.strictEqual((await c.post('/api/clients', { name: 'X' }, { csrf: false })).status, 403); assert.strictEqual((await c.post('/api/clients', { name: 'X' }, { csrf: 'nope' })).status, 403); assert.strictEqual((await c.post('/api/clients', { name: 'X' })).status, 201);
  });
  it('a user can change their own password (the current one is needed; other sessions end); a weak one is refused', async () => {
    env = await makeEnv(); const a = await asUser(env, 'ash'), other = await asUser(env, 'ash');
    assert.strictEqual((await a.post('/api/me/password', { current: 'wrong wrong wrong', next: 'a brand new password' })).status, 400); assert.strictEqual((await a.post('/api/me/password', { current: PW, next: 'short' })).status, 400);
    assert.strictEqual((await a.post('/api/me/password', { current: PW, next: 'a brand new password' })).status, 200); assert.strictEqual((await other.get('/api/me')).status, 401); assert.strictEqual((await a.get('/api/me')).status, 200); assert.strictEqual((await env.client().login('ash', 'a brand new password')).status, 200);
  });
  it('sets safe headers and a strict content policy on every answer', async () => {
    env = await makeEnv(); const r = await env.client().get('/api/health'); assert.strictEqual(r.headers['x-content-type-options'], 'nosniff'); assert.strictEqual(r.headers['x-frame-options'], 'DENY'); assert.match(r.headers['content-security-policy'], /default-src 'self'/); assert.match(r.headers['content-security-policy'], /script-src 'self'/); assert.doesNotMatch(r.headers['content-security-policy'], /unsafe/); assert.strictEqual(r.headers['cache-control'], 'no-store'); assert.ok(!r.headers['x-powered-by']);
    const page = await env.client().get('/'); assert.strictEqual(page.status, 200); assert.match(page.text, /<script type="module" src="\/app\.js">/);
  });
  it('a request body that is not JSON is a plain 400, not a crash', async () => { env = await makeEnv(); const r = await env.client().req('POST', '/api/login', undefined, { headers: { 'content-type': 'application/json' } }); assert.ok([400, 401].includes(r.status)); });
});

describe('roles', () => {
  it('a viewer can look but not change; an issuer cannot approve or run admin pages; an approver cannot create clients; an admin can do all', async () => {
    env = await makeEnv(); const vi = await asUser(env, 'vera'), ash = await asUser(env, 'ash'), bob = await asUser(env, 'bob'), admin = await asUser(env, 'admin');
    assert.strictEqual((await vi.get('/api/clients')).status, 200); assert.strictEqual((await vi.post('/api/clients', { name: 'X' })).status, 403); assert.strictEqual((await vi.get('/api/audit')).status, 403); assert.strictEqual((await vi.get('/api/users')).status, 403);
    assert.strictEqual((await ash.get('/api/users')).status, 403); assert.strictEqual((await ash.get('/api/settings')).status, 403); assert.strictEqual((await ash.get('/api/audit')).status, 403);
    assert.strictEqual((await bob.post('/api/clients', { name: 'X' })).status, 403); assert.strictEqual((await bob.get('/api/audit')).status, 200); assert.strictEqual((await admin.get('/api/users')).status, 200); assert.strictEqual((await admin.post('/api/clients', { name: 'Y' })).status, 201);
  });
});

describe('clients and installations', () => {
  it('creates, edits, searches and archives a client; contacts are checked; the name is unique ignoring case', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const c = await ash.post('/api/clients', { name: 'Acme Corp', reference: 'C-77', notes: 'n', contacts: [{ name: 'Pat', email: ' PAT@Acme.test ' }] }); assert.strictEqual(c.status, 201);
    assert.strictEqual((await ash.post('/api/clients', { name: 'acme corp' })).status, 409); const g = await ash.get('/api/clients/' + c.json.id); assert.strictEqual(g.json.client.contacts[0].email, 'pat@acme.test'); assert.strictEqual(g.json.client.contacts[0].license, true);
    assert.strictEqual((await ash.put('/api/clients/' + c.json.id, { name: 'Acme Corporation', reference: 'C-78', contacts: [] })).status, 200); assert.strictEqual((await ash.get('/api/clients?q=corporation')).json.clients.length, 1); assert.strictEqual((await ash.get('/api/clients?q=zzz')).json.clients.length, 0);
    assert.strictEqual((await ash.post('/api/clients/' + c.json.id + '/archive', {})).status, 200); assert.strictEqual((await ash.get('/api/clients')).json.clients.length, 0); assert.strictEqual((await ash.get('/api/clients?archived=1')).json.clients.length, 1);
    assert.strictEqual((await ash.get('/api/clients/9999')).status, 404);
  });
  it('refuses a client with no name, a bad contact e-mail, or too many contacts', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash');
    for (const b of [{}, { name: ' ' }, { name: 'x'.repeat(121) }, { name: 'A', contacts: [{ email: 'not-an-email' }] }, { name: 'A', contacts: 'x' }, { name: 'A', contacts: Array.from({ length: 21 }, (_, i) => ({ email: 'a' + i + '@x.test' })) }]) assert.strictEqual((await ash.post('/api/clients', b)).status, 400, JSON.stringify(b).slice(0, 50));
  });
  it('stores text that looks like markup exactly as typed (it is only ever drawn as text)', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const n = '<img src=x onerror=alert(1)> & "Co"'; const c = await ash.post('/api/clients', { name: n }); assert.strictEqual((await ash.get('/api/clients/' + c.json.id)).json.client.name, n);
  });
  it('adds installations only with a real installation id or *, once per client, with a label', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const c = (await ash.post('/api/clients', { name: 'A' })).json.id; const add = (b) => ash.post('/api/clients/' + c + '/installations', b);
    assert.strictEqual((await add({ label: 'HQ', installation_id: UUID1.toUpperCase() })).status, 201); assert.strictEqual((await add({ label: 'HQ2', installation_id: UUID1 })).status, 409); assert.strictEqual((await add({ label: 'Any', installation_id: '*' })).status, 201);
    for (const b of [{ label: 'x', installation_id: 'not-a-uuid' }, { label: '', installation_id: UUID2 }, { installation_id: UUID2 }, { label: 'x', installation_id: UUID2 + 'z' }, { label: 'x'.repeat(81), installation_id: UUID2 }]) assert.strictEqual((await add(b)).status, 400, JSON.stringify(b));
    assert.strictEqual((await ash.get('/api/clients/' + c)).json.installations.length, 2); assert.strictEqual((await ash.post('/api/clients/999/installations', { label: 'x', installation_id: UUID2 })).status, 404);
  });
  it('writes who did it to the audit log', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); await seedClient(ash); const bob = await asUser(env, 'bob'); const a = (await bob.get('/api/audit')).json.entries.map((e) => e.action + ':' + e.actor);
    for (const w of ['login:ash', 'client.create:ash', 'installation.create:ash']) assert.ok(a.includes(w), w); assert.strictEqual(audit.verify(env.db).ok, true);
  });
});
