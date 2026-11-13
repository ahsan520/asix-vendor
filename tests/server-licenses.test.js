'use strict';
// Requests, approval, signing, renewal, e-mail, reminders, settings, audit, users, export.
const { describe, it, afterEach } = require('node:test');
const assert = require('assert');
const { jwtVerify, importSPKI, decodeJwt } = require('jose');
const { makeEnv, asUser, seedClient, PW, UUID1, UUID2 } = require('./helpers');
const audit = require('../server/audit');
const reminders = require('../server/reminders');
const lic = require('../server/license');
const features = require('../features');

let env; afterEach(async () => { if (env) await env.close(); env = null; });
const verifyToken = async (token) => jwtVerify(token, await importSPKI(await env.signer.publicKeyPem(), 'EdDSA'), { algorithms: ['EdDSA'], issuer: 'asix', currentDate: new Date(env.clock.t) });
const tokenOf = (id) => env.db.prepare('SELECT token FROM licenses WHERE id = ?').get(id).token;

describe('requesting and issuing', () => {
  it('a residential license needs no approval: it is signed at once, verifies against the signing key, and carries exactly what was asked', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const s = await seedClient(ash);
    const r = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', tenants: '1', retention: 365, note: 'INV-1042' }); assert.strictEqual(r.status, 201); assert.strictEqual(r.json.status, 'issued');
    const { payload, protectedHeader } = await verifyToken(tokenOf(r.json.id)); assert.strictEqual(protectedHeader.kid, 'test-1'); assert.strictEqual(payload.sub, 'Acme Corp'); assert.strictEqual(payload.iid, UUID1); assert.strictEqual(payload.kind, 'residential'); assert.deepStrictEqual(payload.features, features.BUNDLES['@residential']); assert.deepStrictEqual(payload.limits, { tenants: 1, retention_days_max: 365 }); assert.strictEqual(payload.grace_days, undefined);
    assert.strictEqual(payload.exp - payload.iat, 365 * 86400); const g = await ash.get('/api/licenses/' + r.json.id); assert.strictEqual(g.json.license.state, 'active'); assert.strictEqual(g.json.license.days_left, 365); assert.ok(!('token' in g.json.license)); assert.ok(!/eyJ/.test(g.text), 'the license text is only in the file download');
  });
  it('the file download is the license text and is recorded; a viewer cannot download it', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const id = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' })).json.id;
    const f = await ash.get('/api/licenses/' + id + '/file'); assert.strictEqual(f.text.trim(), tokenOf(id)); assert.match(f.headers['content-disposition'], /attachment; filename="asix-license-acme-corp-L-/); assert.strictEqual((await (await asUser(env, 'vera')).get('/api/licenses/' + id + '/file')).status, 403);
    assert.ok(audit.list(env.db).some((e) => e.action === 'license.download' && e.target === id));
  });
  it('the trial is 30 days with no grace; a custom list of features works; enterprise features make it enterprise', async () => {
    env = await makeEnv({ approval: 'none' }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash);
    const t = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'trial' }); let p = (await verifyToken(tokenOf(t.json.id))).payload; assert.strictEqual(p.exp - p.iat, 30 * 86400); assert.strictEqual(p.grace_days, 0); assert.strictEqual(p.kind, 'enterprise');
    const c = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'custom', features: ['search', 'alerts', 'detections'], days: 90, grace: 7 }); p = (await verifyToken(tokenOf(c.json.id))).payload; assert.deepStrictEqual(p.features, ['search', 'detections', 'alerts']); assert.strictEqual(p.kind, 'residential'); assert.strictEqual(p.grace_days, 7);
  });
  it('refuses what is wrong, with a plain message, and stores nothing', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const q = (b) => ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', ...b });
    for (const [b, re] of [[{ template: 'bogus' }, /unknown template/], [{ days: 0 }, /days/], [{ days: 5000 }, /days/], [{ days: 1.5 }, /days/], [{ grace: 91 }, /grace/], [{ tenants: 'many' }, /tenants/], [{ retention: -1 }, /retention/], [{ template: 'custom', features: [] }, /template or at least one feature/], [{ template: 'custom', features: ['nope'] }, /unknown feature/], [{ template: 'custom', features: [5] }, /list of names/], [{ installation_pk: 999 }, /installations/]]) { const r = await q(b); assert.ok([400, 404].includes(r.status), JSON.stringify(b)); assert.match(r.json.error.message, re, JSON.stringify(b)); }
    assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM licenses').get().n, 0);
  });
  it('one request at a time per installation; an archived client gets none', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const q = () => ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'enterprise' });
    assert.strictEqual((await q()).status, 202); assert.strictEqual((await q()).status, 409); await ash.post('/api/clients/' + s.client_id + '/archive', {}); assert.strictEqual((await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' })).status, 400);
  });
});

describe('approval', () => {
  it('an enterprise license waits for a second person: no signature exists until someone else approves, and the requester cannot', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'), bob = await asUser(env, 'bob'), admin = await asUser(env, 'admin'); const s = await seedClient(ash);
    const r = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'enterprise' }); assert.strictEqual(r.status, 202); assert.strictEqual(r.json.needs_approval, true);
    assert.strictEqual(env.db.prepare('SELECT token FROM licenses WHERE id = ?').get(r.json.id).token, null); assert.strictEqual((await ash.get('/api/licenses/' + r.json.id + '/file')).status, 404); assert.strictEqual((await ash.post('/api/licenses/' + r.json.id + '/send', { to: ['a@b.test'] })).status, 404);
    assert.strictEqual((await ash.post('/api/licenses/' + r.json.id + '/approve', {})).status, 403, 'an issuer is not an approver'); const own = await admin.post('/api/clients', { name: 'B' }); void own;
    assert.strictEqual((await bob.post('/api/licenses/' + r.json.id + '/approve', {})).status, 200); const g = (await bob.get('/api/licenses/' + r.json.id)).json.license; assert.strictEqual(g.status, 'issued'); assert.strictEqual(g.requested_by, 'ash'); assert.strictEqual(g.approved_by, 'bob'); assert.ok(tokenOf(r.json.id));
    assert.strictEqual((await bob.post('/api/licenses/' + r.json.id + '/approve', {})).status, 409, 'not twice');
  });
  it('an admin who made the request cannot approve it themselves, but another approver can', async () => {
    env = await makeEnv(); const admin = await asUser(env, 'admin'), bob = await asUser(env, 'bob'); const s = await seedClient(admin);
    const r = await admin.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'enterprise' }); const own = await admin.post('/api/licenses/' + r.json.id + '/approve', {}); assert.strictEqual(own.status, 403); assert.match(own.json.error.message, /second person/); assert.strictEqual((await bob.post('/api/licenses/' + r.json.id + '/approve', {})).status, 200);
  });
  it('a request can be rejected with a reason, or cancelled by the person who asked; nothing is signed either way', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'), bob = await asUser(env, 'bob'); const s = await seedClient(ash); const mk = async () => (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'enterprise' })).json.id;
    let id = await mk(); assert.strictEqual((await bob.post('/api/licenses/' + id + '/reject', {})).status, 400); assert.strictEqual((await bob.post('/api/licenses/' + id + '/reject', { reason: 'no contract yet' })).status, 200); assert.strictEqual((await bob.get('/api/licenses/' + id)).json.license.status, 'rejected');
    id = await mk(); assert.strictEqual((await bob.post('/api/licenses/' + id + '/cancel', {})).status, 403); assert.strictEqual((await ash.post('/api/licenses/' + id + '/cancel', {})).status, 200); assert.strictEqual(env.db.prepare("SELECT COUNT(*) AS n FROM licenses WHERE token IS NOT NULL").get().n, 0);
  });
  it('the policy decides: none issues everything at once, all asks for everything, enterprise asks for enterprise, long terms and any-installation', async () => {
    const cases = [['none', 'enterprise', 365, UUID1, 201], ['all', 'residential', 365, UUID1, 202], ['enterprise', 'residential', 365, UUID1, 201], ['enterprise', 'enterprise', 365, UUID1, 202], ['enterprise', 'residential', 401, UUID1, 202], ['enterprise', 'residential', 400, UUID1, 201], ['enterprise', 'residential', 365, '*', 202]];
    for (const [policy, tpl, days, iid, want] of cases) { env = await makeEnv({ approval: policy }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash, 'C', iid); assert.strictEqual((await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: tpl, days })).status, want, [policy, tpl, days, iid].join(' ')); await env.close(); env = null; }
    assert.strictEqual(lic.needsApproval('enterprise', { kind: 'residential', days: 365 }, UUID1), false);
  });
});

describe('signing failures', () => {
  it('if the signer is down nothing is issued, the request is closed with the reason, and the person is told plainly', async () => {
    const signerObj = { type: 'x', kid: 'k', async publicKeyPem() { return '-'; }, async sign() { throw new Error('the signing service is sealed or not ready: unseal it first'); }, async health() { return { ok: false, detail: 'sealed' }; } };
    env = await makeEnv({ signerObj }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const r = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' });
    assert.strictEqual(r.status, 502); assert.match(r.json.error.message, /could not be signed: the signing service is sealed/); const row = env.db.prepare('SELECT status, token, decision_note FROM licenses').get(); assert.strictEqual(row.status, 'cancelled'); assert.strictEqual(row.token, null); assert.match(row.decision_note, /not issued/);
    assert.ok(audit.list(env.db).some((e) => e.action === 'license.sign_failed'));
  });
  it('a signature that does not verify against the signing key is never released', async () => {
    const real = (await makeEnv()); const good = real.signer; await real.close();
    const wrong = { type: 'x', kid: 'k', async publicKeyPem() { return good.publicKeyPem(); }, async sign() { return Buffer.alloc(64, 7); }, async health() { return { ok: true, detail: '' }; } };
    env = await makeEnv({ signerObj: wrong }); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const r = await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' });
    assert.strictEqual(r.status, 502); assert.match(r.json.error.message, /did not verify against the signing key: nothing was issued/); assert.strictEqual(env.db.prepare("SELECT COUNT(*) AS n FROM licenses WHERE token IS NOT NULL").get().n, 0);
  });
  it('an approver whose approval fails to sign can try again: the request stays waiting', async () => {
    let fail = true; const inner = (await makeEnv()); const good = inner.signer; await inner.close();
    const flaky = { type: 'x', kid: 'test-1', publicKeyPem: () => good.publicKeyPem(), sign: async (b) => { if (fail) throw new Error('temporarily down'); return good.sign(b); }, health: async () => ({ ok: true, detail: '' }) };
    env = await makeEnv({ signerObj: flaky }); const ash = await asUser(env, 'ash'), bob = await asUser(env, 'bob'); const s = await seedClient(ash); const id = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'enterprise' })).json.id;
    assert.strictEqual((await bob.post('/api/licenses/' + id + '/approve', {})).status, 502); assert.strictEqual((await bob.get('/api/licenses/' + id)).json.license.status, 'pending'); fail = false; assert.strictEqual((await bob.post('/api/licenses/' + id + '/approve', {})).status, 200);
  });
});

describe('renewing and the renewal list', () => {
  it('a renewal replaces the old license for that installation and records what it replaces; one for another installation is refused', async () => {
    env = await makeEnv(); let ash = await asUser(env, 'ash'); const s = await seedClient(ash); const first = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', tenants: 3 })).json.id;
    env.clock.t += 320 * 86400000; ash = await asUser(env, "ash"); const ren = await ash.get('/api/renewals?days=90'); assert.strictEqual(ren.json.licenses.length, 1); assert.strictEqual(ren.json.licenses[0].id, first); assert.strictEqual(ren.json.licenses[0].state, 'expiring');
    const second = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', tenants: 3, supersedes: first })).json.id; assert.strictEqual((await ash.get('/api/licenses/' + second)).json.license.supersedes, first);
    assert.strictEqual((await ash.get('/api/renewals?days=90')).json.licenses.length, 0, 'the new license is far from expiry'); assert.strictEqual((await ash.get('/api/dashboard')).json.active, 1);
    const other = await ash.post('/api/clients/' + s.client_id + '/installations', { label: 'Site 2', installation_id: UUID2 }); assert.strictEqual((await ash.post('/api/licenses/request', { installation_pk: other.json.id, template: 'residential', supersedes: first })).status, 400);
    env.clock.t += 800 * 86400000; ash = await asUser(env, 'ash'); assert.strictEqual((await ash.get('/api/renewals?days=0')).json.licenses[0].state, 'expired');
  });
  it('the dashboard counts clients, active, expiring, expired and waiting', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const a = await seedClient(ash, 'A', UUID1), b = await seedClient(ash, 'B', UUID2); await ash.post('/api/licenses/request', { installation_pk: a.installation_pk, template: 'residential', days: 30 }); await ash.post('/api/licenses/request', { installation_pk: b.installation_pk, template: 'enterprise' });
    const d = (await ash.get('/api/dashboard')).json; assert.deepStrictEqual([d.clients, d.expiring, d.active, d.pending, d.signer.type], [2, 1, 0, 1, 'local']);
  });
});

describe('sending by e-mail', () => {
  const issued = async (over) => { env = await makeEnv(over); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); const id = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' })).json.id; return { ash, id, s }; };
  it('sends the license as an attachment with the instructions, records it, and can resend', async () => {
    const { ash, id } = await issued(); const r = await ash.post('/api/licenses/' + id + '/send', { to: ['Pat@Acme.test', 'it@acme.test'], message: 'Thanks for your business.' }); assert.strictEqual(r.status, 200); assert.deepStrictEqual(r.json.to, ['pat@acme.test', 'it@acme.test']);
    const m = env.sent[0]; assert.strictEqual(m.subject, 'Your ASIX license for Acme Corp'); assert.match(m.text, /Settings, then License/); assert.match(m.text, /installation 11111111-2222-4333-8444-555555555555/); assert.match(m.text, /Thanks for your business/); assert.strictEqual(m.attachments.length, 1); assert.strictEqual(m.attachments[0].content.trim(), tokenOf(id)); assert.match(m.attachments[0].filename, /^asix-license-acme-corp\.jwt$/);
    assert.strictEqual((await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'] })).status, 200); const rows = env.db.prepare('SELECT * FROM emails WHERE license_id = ?').all(id); assert.strictEqual(rows.length, 2); assert.ok(rows.every((e) => e.status === 'sent' && e.sent_by === 'ash'));
    assert.ok(!JSON.stringify(audit.list(env.db)).includes(tokenOf(id)), 'the license text is never in the audit log');
  });
  it('refuses no recipients, a bad address, too many, and someone who may not send', async () => {
    const { ash, id } = await issued(); for (const to of [[], ['not-an-email'], undefined, 'x@y.test', Array.from({ length: 11 }, (_, i) => 'a' + i + '@x.test'), ['a@b.test\nBcc: evil@x.test']]) assert.strictEqual((await ash.post('/api/licenses/' + id + '/send', { to })).status, 400, JSON.stringify(to)); assert.strictEqual(env.sent.length, 0);
    assert.strictEqual((await (await asUser(env, 'vera')).post('/api/licenses/' + id + '/send', { to: ['a@b.test'] })).status, 403);
  });
  it('a failed send is recorded as failed and reported; e-mail that is not set up says so', async () => {
    const { ash, id } = await issued({ send: async () => { throw new Error('the message could not be sent: 550 mailbox unavailable'); } }); const r = await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'] }); assert.strictEqual(r.status, 502); assert.match(r.json.error.message, /550 mailbox unavailable/);
    const row = env.db.prepare('SELECT status, error FROM emails').get(); assert.strictEqual(row.status, 'failed'); assert.match(row.error, /550/); await env.close();
    const ok = await issued({ smtp: { host: null, from: null }, send: undefined }); env.sent.length = 0; const real = require('../server/mail'); void real; const r2 = await ok.ash.post('/api/licenses/' + ok.id + '/send', { to: ['pat@acme.test'] }); assert.strictEqual(r2.status, 200);
  });
  it('slows a runaway sender: 30 e-mails an hour per person', async () => {
    const { ash, id } = await issued(); for (let i = 0; i < 30; i++) assert.strictEqual((await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'] })).status, 200); assert.strictEqual((await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'] })).status, 429); env.clock.t += 3600001; assert.strictEqual((await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'] })).status, 200);
  });
  it('uses the saved template and only the known placeholders', async () => {
    const { ash, id } = await issued(); const admin = await asUser(env, 'admin'); assert.strictEqual((await admin.put('/api/settings', { license_subject: 'License for {{customer}} until {{expires}}' })).status, 200); await ash.post('/api/licenses/' + id + '/send', { to: ['pat@acme.test'] }); assert.match(env.sent[0].subject, /^License for Acme Corp until 2027-11-11$/);
    for (const bad of [{ license_subject: 'Hello {{evil}}' }, { license_body: '' }, { license_body: 'x'.repeat(4001) }]) assert.strictEqual((await admin.put('/api/settings', bad)).status, 400, JSON.stringify(bad).slice(0, 40)); assert.strictEqual((await ash.put('/api/settings', { license_subject: 'x' })).status, 403);
    const mail = require('../server/mail'); assert.strictEqual(mail.render('{{customer}} {{unknown}} ${process.exit()} {{ customer }}', { customer: 'A' }), 'A {{unknown}} ${process.exit()} {{ customer }}');
  });
});

describe('renewal reminders', () => {
  const setup = async (over) => { env = await makeEnv(over); const ash = await asUser(env, 'ash'), admin = await asUser(env, 'admin'); const s = await seedClient(ash, 'Acme Corp', UUID1, [{ name: 'Pat', email: 'pat@acme.test', license: true, renewals: true }, { name: 'Lou', email: 'lou@acme.test', license: true, renewals: false }]); const id = (await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', days: 100 })).json.id; await admin.put('/api/settings', { remindersEnabled: true }); return { ash, admin, id, s }; };
  it('sends one reminder per stage (60, 30, 7 days) to the renewal contacts only, and never twice', async () => {
    const { id } = await setup(); const run = () => reminders.runReminders(env.ctx, new Date(env.clock.t)); assert.deepStrictEqual(await run(), { sent: 0, failed: 0, skipped: 0 });
    env.clock.t += 45 * 86400000; assert.strictEqual((await run()).sent, 1); assert.deepStrictEqual(JSON.parse(env.db.prepare("SELECT to_addrs FROM emails WHERE kind = 'reminder'").get().to_addrs), ['pat@acme.test']); assert.match(env.sent[0].subject, /expires in 55 days|expires in 54 days/); assert.strictEqual((await run()).sent, 0);
    env.clock.t += 25 * 86400000; assert.strictEqual((await run()).sent, 1); env.clock.t += 15 * 86400000; assert.strictEqual((await run()).sent, 0, 'still inside the 30 day stage'); env.clock.t += 8 * 86400000; assert.strictEqual((await run()).sent, 1); assert.strictEqual((await run()).sent, 0); assert.strictEqual(env.sent.length, 3); void id;
    env.clock.t += 40 * 86400000; assert.strictEqual((await run()).sent, 0, 'nothing after expiry'); assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM reminders').get().n, 3);
  });
  it('does nothing while reminders are off; a failed send is tried again next time; a client with no renewal contact is noted once', async () => {
    const { admin } = await setup(); await admin.put('/api/settings', { remindersEnabled: false }); env.clock.t += 50 * 86400000; assert.strictEqual((await reminders.runReminders(env.ctx, new Date(env.clock.t))).sent, 0); env.clock.t -= 50 * 86400000; await admin.put('/api/settings', { remindersEnabled: true }); env.clock.t += 50 * 86400000;
    env.ctx.send = async () => { throw new Error('smtp down'); }; assert.strictEqual((await reminders.runReminders(env.ctx, new Date(env.clock.t))).failed, 1); assert.strictEqual(env.db.prepare('SELECT COUNT(*) AS n FROM reminders').get().n, 0); env.ctx.send = async (c, m) => { env.sent.push(m); return { message_id: 'x' }; };
    assert.strictEqual((await reminders.runReminders(env.ctx, new Date(env.clock.t))).sent, 1); await env.close(); env = null;
    env = await makeEnv(); const ash = await asUser(env, 'ash'), admin2 = await asUser(env, 'admin'); const s = await seedClient(ash, 'NoContact', UUID1, []); await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', days: 20 }); await admin2.put('/api/settings', { remindersEnabled: true });
    assert.strictEqual((await reminders.runReminders(env.ctx, new Date(env.clock.t))).skipped, 1); assert.strictEqual((await reminders.runReminders(env.ctx, new Date(env.clock.t))).skipped, 0); assert.ok(audit.list(env.db).some((e) => e.action === 'reminder.no_recipients'));
  });
  it('a license that has been renewed is not reminded about', async () => {
    const { id, s } = await setup(); env.clock.t += 50 * 86400000; const ash = await asUser(env, 'ash'); assert.strictEqual((await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential', days: 365, supersedes: id })).status, 201); assert.strictEqual((await reminders.runReminders(env.ctx, new Date(env.clock.t))).sent, 0);
  });
});

describe('the audit log', () => {
  const some = async () => { env = await makeEnv(); const ash = await asUser(env, 'ash'); const s = await seedClient(ash); await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' }); };
  it('is chained: an untouched log verifies; an edited, deleted or reordered row is found', async () => {
    await some(); const v = audit.verify(env.db); assert.strictEqual(v.ok, true); assert.ok(v.count >= 5);
    const was = env.db.prepare('SELECT actor FROM audit WHERE id = 2').get().actor; env.db.exec("UPDATE audit SET actor = 'mallory' WHERE id = 2"); assert.match(audit.verify(env.db).problems.join(' '), /row 2: the row itself was changed/); env.db.prepare('UPDATE audit SET actor = ? WHERE id = 2').run(was); assert.strictEqual(audit.verify(env.db).ok, true);
    env.db.exec('DELETE FROM audit WHERE id = 3'); assert.match(audit.verify(env.db).problems.join(' '), /chain is broken/);
  });
  it('shows who signed what, with the license hash and never the license text, a password or a code', async () => {
    await some(); const all = JSON.stringify(audit.list(env.db, 500)); const row = audit.list(env.db, 500).find((e) => e.action === 'license.issue'); assert.ok(row.detail.token_sha256); assert.strictEqual(row.detail.kid, 'test-1'); assert.strictEqual(row.actor, 'ash');
    const id = row.target; assert.ok(!all.includes(tokenOf(id))); assert.ok(!all.includes(PW)); for (const u of ['ash', 'bob', 'admin', 'vera']) assert.ok(!all.includes(env.secrets[u]), 'no authenticator secret');
    const bob = await asUser(env, 'bob'); assert.strictEqual((await bob.get('/api/audit/verify')).json.ok, true);
  });
  it('a failed sign-in is logged without the password', async () => { env = await makeEnv(); await env.client().login('ash', 'my secret guess 123'); const all = JSON.stringify(audit.list(env.db)); assert.match(all, /login\.failed/); assert.ok(!all.includes('my secret guess 123')); });
});

describe('users', () => {
  it('an admin creates users (the authenticator secret is shown once, never listed), and weak passwords and duplicates are refused', async () => {
    env = await makeEnv(); const admin = await asUser(env, 'admin'); const r = await admin.post('/api/users', { username: 'newbie', name: 'New Bie', role: 'issuer', password: PW }); assert.strictEqual(r.status, 201); assert.match(r.json.totp_secret, /^[A-Z2-7]{32}$/); assert.match(r.json.otpauth, /^otpauth:\/\/totp\//);
    const list = (await admin.get('/api/users')).text; assert.ok(!list.includes(r.json.totp_secret) && !/scrypt/.test(list)); assert.strictEqual((await admin.post('/api/users', { username: 'newbie', name: 'x', role: 'viewer', password: PW })).status, 409);
    for (const b of [{ username: 'ab', name: 'x', role: 'viewer', password: PW }, { username: 'okname', name: 'x', role: 'root', password: PW }, { username: 'okname', name: 'x', role: 'viewer', password: 'short' }, { username: 'okname', name: '', role: 'viewer', password: PW }]) assert.strictEqual((await admin.post('/api/users', b)).status, 400, JSON.stringify(b));
  });
  it('the last active admin cannot be disabled or demoted; a reset ends sessions and makes a new code work', async () => {
    env = await makeEnv(); const admin = await asUser(env, 'admin'); const me = (await admin.get('/api/users')).json.users.find((u) => u.username === 'admin');
    assert.strictEqual((await admin.put('/api/users/' + me.id, { name: 'A', role: 'viewer', active: true })).status, 409); assert.strictEqual((await admin.put('/api/users/' + me.id, { name: 'A', role: 'admin', active: false })).status, 409);
    const ash = await asUser(env, 'ash'); const id = (await admin.get('/api/users')).json.users.find((u) => u.username === 'ash').id; const r = await admin.post('/api/users/' + id + '/reset', { password: 'a different long password' }); assert.strictEqual(r.status, 200);
    assert.strictEqual((await ash.get('/api/me')).status, 401); assert.strictEqual((await env.client().login('ash')).status, 401); env.secrets.ash = r.json.totp_secret; assert.strictEqual((await env.client().login('ash', 'a different long password')).status, 200);
  });
});

describe('the CSV export', () => {
  it('has no license text, and a client name that starts like a spreadsheet formula is made harmless', async () => {
    env = await makeEnv(); const ash = await asUser(env, 'ash'); const s = await seedClient(ash, '=HYPERLINK("http://evil","x"),Co'); await ash.post('/api/licenses/request', { installation_pk: s.installation_pk, template: 'residential' });
    const r = await ash.get('/api/export.csv'); assert.match(r.headers['content-type'], /text\/csv/); assert.ok(!/eyJ/.test(r.text)); const row = r.text.split('\n')[1]; assert.ok(row.includes('"\'=HYPERLINK(""http://evil"",""x""),Co"'), row); assert.ok(!/^=/.test(row.split(',')[1]));
  });
});
