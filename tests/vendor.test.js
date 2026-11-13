'use strict';
const { describe, it, before, beforeEach } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { jwtVerify, importSPKI, decodeJwt } = require('jose');
const tool = require('../license-vendor');
const features = require('../features');

const IID1 = '11111111-2222-4333-8444-555555555555', IID2 = '99999999-2222-4333-8444-555555555555';
let keys, dir;
const clock = (iso) => ({ dir, now: () => new Date(iso), user: 'ash' });
const run = (args, iso = '2026-11-08T12:00:00Z') => tool.run([...args], clock(iso));
const SIGN = (extra = []) => ['sign', '--key', path.join(keys, 'license-private.pem'), '--kid', 'k1', ...extra];
before(async () => { keys = fs.mkdtempSync(path.join(os.tmpdir(), 'vkeys-')); await tool.run(['keygen', keys, 'k1'], { dir: os.tmpdir(), now: () => new Date() }); });
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vledger-')); });
const ledger = () => tool.readLedger(dir);
const pubKey = async () => importSPKI(fs.readFileSync(path.join(keys, 'license-public.pem'), 'utf8'), 'EdDSA');
const err = async (args, re, iso) => assert.rejects(() => run(args, iso), (e) => { assert.ok(e.vendor, 'a person\'s mistake, not a crash: ' + e.stack); assert.match(e.message, re); return true; });

describe('keys', () => {
  it('keygen writes a private key (mode 600) and a public key, prints the line for vendor-keys.js, and never overwrites a private key', async () => {
    assert.strictEqual(fs.statSync(path.join(keys, 'license-private.pem')).mode & 0o777, 0o600);
    const k2 = fs.mkdtempSync(path.join(os.tmpdir(), 'vkeys2-')); const out = await tool.run(['keygen', k2, 'asix-test'], clock('2026-01-01T00:00:00Z')); assert.match(out, /kid: 'asix-test'/); assert.match(out, /OFFLINE/);
    await assert.rejects(() => tool.run(['keygen', k2], clock('2026-01-01T00:00:00Z')), /refusing to overwrite/);
  });
});

describe('signing and the ledger', () => {
  it('signs a license that verifies against the public key, writes the file, and records it in the ledger', async () => {
    const out = await run(SIGN(['--customer', 'Acme Corp', '--iid', IID1, '--days', '365', '--bundle', '@enterprise', '--tenants', '5', '--retention', 'unlimited', '--grace', '30', '--note', 'invoice 1042']));
    assert.match(out, /Issued L-20261108-[0-9a-f]{6} to Acme Corp \(enterprise\), expires 2027-11-08/); const [r] = ledger(); assert.strictEqual(ledger().length, 1);
    const token = fs.readFileSync(path.join(dir, r.file), 'utf8').trim(); const { payload } = await jwtVerify(token, await pubKey(), { issuer: 'asix', currentDate: new Date('2026-11-09T00:00:00Z') });
    assert.strictEqual(payload.sub, 'Acme Corp'); assert.strictEqual(payload.iid, IID1); assert.strictEqual(payload.kind, 'enterprise'); assert.deepStrictEqual(payload.features, features.BUNDLES['@enterprise']); assert.deepStrictEqual(payload.limits, { tenants: 5, retention_days_max: null }); assert.strictEqual(payload.grace_days, 30);
    assert.strictEqual(r.note, 'invoice 1042'); assert.strictEqual(r.issued_by, 'ash'); assert.strictEqual(r.kid, 'k1'); assert.strictEqual(r.expires_at, '2027-11-08T12:00:00.000Z'); assert.strictEqual(r.prev, '0'.repeat(64));
    assert.strictEqual(fs.statSync(path.join(dir, r.file)).mode & 0o777, 0o600); assert.strictEqual(fs.statSync(path.join(dir, 'ledger.jsonl')).mode & 0o777, 0o600);
  });
  it('the ledger never holds the license text or any key', async () => {
    await run(SIGN(['--customer', 'Acme', '--iid', IID1, '--days', '30', '--bundle', '@residential'])); const text = fs.readFileSync(path.join(dir, 'ledger.jsonl'), 'utf8'); const token = fs.readFileSync(path.join(dir, ledger()[0].file), 'utf8').trim();
    assert.ok(!text.includes(token)); assert.ok(!/eyJ/.test(text), 'no license text of any kind'); assert.ok(!('token' in ledger()[0])); assert.ok(!/PRIVATE|BEGIN/.test(text)); assert.ok(!text.includes(fs.readFileSync(path.join(keys, 'license-private.pem'), 'utf8').split('\n')[1]));
  });
  it('a residential feature list is residential, anything enterprise makes it enterprise; a trial can have grace 0', async () => {
    await run(SIGN(['--customer', 'Home', '--iid', IID1, '--days', '30', '--features', 'search,alerts,detections', '--grace', '0'])); await run(SIGN(['--customer', 'Big', '--iid', IID2, '--days', '30', '--features', 'search,endpoints']));
    const [a, b] = ledger(); assert.strictEqual(a.kind, 'residential'); assert.strictEqual(a.grace_days, 0); assert.strictEqual(b.kind, 'enterprise'); assert.strictEqual(b.grace_days, null);
    assert.strictEqual(decodeJwt(fs.readFileSync(path.join(dir, a.file), 'utf8').trim()).grace_days, 0); assert.strictEqual(decodeJwt(fs.readFileSync(path.join(dir, b.file), 'utf8').trim()).grace_days, undefined);
  });
  it('also writes the license where --out says, and the records chain to one another', async () => {
    const o = path.join(dir, 'send.jwt'); await run(SIGN(['--customer', 'A', '--iid', IID1, '--days', '10', '--bundle', '@residential', '--out', o])); await run(SIGN(['--customer', 'B', '--iid', IID2, '--days', '10', '--bundle', '@residential']));
    assert.ok(fs.existsSync(o)); const [a, b] = ledger(); assert.notStrictEqual(b.prev, a.prev); assert.match((tool.verifyLedger({ dir })).ok ? 'ok' : 'bad', /ok/);
  });
  it('refuses what is wrong, with a plain message, and writes nothing', async () => {
    const base = ['--customer', 'Acme', '--iid', IID1, '--days', '30', '--bundle', '@residential'];
    const set = (k, v) => { const a = [...base]; const i = a.indexOf(k); a[i + 1] = v; return a; };
    await err(SIGN(set('--iid', 'not-a-uuid')), /installation id/); await err(SIGN(set('--days', '0')), /--days/); await err(SIGN(set('--days', '30.5')), /--days/); await err(SIGN(set('--days', '9999')), /--days/); await err(SIGN(set('--bundle', '@bogus')), /unknown feature or bundle/);
    await err(SIGN(set('--customer', '  ')), /--customer/); await err(SIGN([...base, '--grace', '91']), /--grace/); await err(SIGN([...base, '--tenants', 'many']), /--tenants/); await err(SIGN([...base, '--retention', '-5']), /--retention/);
    await err(['sign', '--kid', 'k1', ...base], /--key/); await err(['sign', '--key', path.join(keys, 'license-private.pem'), ...base], /--kid/); await err(['sign', '--key', '/nonexistent.pem', '--kid', 'k1', ...base], /cannot read the private key/);
    await err(['sign', '--key', path.join(keys, 'license-public.pem'), '--kid', 'k1', ...base], /not an Ed25519 private key/); await err(SIGN(['--customer', 'A', '--iid', IID1, '--days', '5']), /at least one feature/);
    assert.strictEqual(ledger().length, 0); assert.ok(!fs.existsSync(path.join(dir, 'issued')) || fs.readdirSync(path.join(dir, 'issued')).length === 0);
  });
  it('refuses a private key that sits inside the ledger folder (it would end up in the repository) unless told', async () => {
    const inside = path.join(dir, 'oops.pem'); fs.copyFileSync(path.join(keys, 'license-private.pem'), inside);
    await err(['sign', '--key', inside, '--kid', 'k1', '--customer', 'A', '--iid', IID1, '--days', '5', '--bundle', '@residential'], /inside this folder/); assert.strictEqual(ledger().length, 0);
    await run(['sign', '--key', inside, '--kid', 'k1', '--customer', 'A', '--iid', IID1, '--days', '5', '--bundle', '@residential', '--allow-key-in-folder']); assert.strictEqual(ledger().length, 1);
  });
});

describe('reports', () => {
  beforeEach(async () => {
    await run(SIGN(['--customer', 'Acme Corp', '--iid', IID1, '--days', '365', '--bundle', '@enterprise']), '2026-01-10T00:00:00Z');
    await run(SIGN(['--customer', 'Smith Home', '--iid', IID2, '--days', '30', '--bundle', '@residential']), '2026-10-20T00:00:00Z');
    await run(SIGN(['--customer', 'Old Co', '--iid', '*', '--days', '90', '--features', 'search,alerts,detections']), '2026-06-01T00:00:00Z');
  });
  it('list shows each customer once, soonest expiry first, with plain status; --all shows every license ever issued', async () => {
    const t = await run(['list'], '2026-11-08T12:00:00Z'); const rows = t.split('\n').slice(2); assert.strictEqual(rows.length, 3); assert.match(rows[0], /^Old Co/); assert.match(rows[0], /EXPIRED \d+d ago/); assert.match(rows[1], /^Smith Home/); assert.match(rows[1], /expiring/); assert.match(rows[2], /^Acme Corp/); assert.match(rows[2], /active/);
    assert.match(rows[0], /\* \(any\)/); assert.match(rows[1], /99999999\.\.\./);
  });
  it('expiring lists those expiring inside the window or already expired, and says so when there are none', async () => {
    let t = await run(['expiring', '--days', '30'], '2026-11-08T12:00:00Z'); assert.match(t, /Old Co/); assert.match(t, /Smith Home/); assert.doesNotMatch(t, /Acme Corp/);
    t = await run(['expiring', '--days', '5'], '2026-11-08T12:00:00Z'); assert.match(t, /Old Co/); assert.doesNotMatch(t, /Smith Home/);
    assert.strictEqual(await run(['expiring', '--days', '5'], '2026-01-12T00:00:00Z'), 'Nothing expires within 5 days.'); await err(['expiring', '--days', 'x'], /--days/);
  });
  it('show prints a customer\'s whole history (partial, case-insensitive names work); an unknown name is a plain error', async () => {
    const t = await run(['show', 'acme']); assert.match(t, /Acme Corp {2}\(enterprise\)/); assert.match(t, /installation 11111111-/); assert.match(t, /features: search/); await err(['show', 'nobody'], /no license has been issued/);
  });
  it('export writes CSV with no license text, and quotes what needs quoting', async () => {
    await run(SIGN(['--customer', 'Quote, "Inc"', '--iid', IID1, '--days', '10', '--bundle', '@residential', '--note', 'line one']), '2026-11-01T00:00:00Z'); const csv = await run(['export']); const lines = csv.split('\n');
    assert.match(lines[0], /^id,issued_at,customer,kind/); assert.strictEqual(lines.length, 5); assert.ok(csv.includes('"Quote, ""Inc"""')); assert.ok(!/eyJ/.test(csv), 'no license text'); const f = path.join(dir, 'out.csv'); assert.match(await run(['export', '--out', f]), /Wrote/); assert.ok(fs.existsSync(f));
  });
});

describe('renewing', () => {
  beforeEach(async () => { await run(SIGN(['--customer', 'Acme Corp', '--iid', IID1, '--days', '365', '--features', 'search,alerts,detections', '--tenants', '3', '--retention', '400', '--grace', '45', '--note', 'first']), '2026-01-10T00:00:00Z'); });
  it('signs the same license again from today, keeps what was sold, and the new record replaces the old in list', async () => {
    const out = await run(['renew', '--customer', 'acme corp', '--key', path.join(keys, 'license-private.pem'), '--kid', 'k1'], '2027-01-05T00:00:00Z'); assert.match(out, /Renewed Acme Corp/); const [a, b] = ledger();
    assert.strictEqual(b.supersedes, a.id); assert.deepStrictEqual(b.features, a.features); assert.deepStrictEqual(b.limits, { tenants: 3, retention_days_max: 400 }); assert.strictEqual(b.grace_days, 45); assert.strictEqual(b.days, 365); assert.strictEqual(b.expires_at, '2028-01-05T00:00:00.000Z'); assert.strictEqual(b.installation_id, IID1);
    assert.strictEqual((await run(['list'], '2027-01-05T00:00:00Z')).split('\n').slice(2).length, 1); assert.strictEqual((await run(['list', '--all'], '2027-01-05T00:00:00Z')).split('\n').slice(2).length, 2);
    const { payload } = await jwtVerify(fs.readFileSync(path.join(dir, b.file), 'utf8').trim(), await pubKey(), { issuer: 'asix', currentDate: new Date('2027-02-01T00:00:00Z') }); assert.strictEqual(payload.grace_days, 45); assert.deepStrictEqual(payload.limits, { tenants: 3, retention_days_max: 400 });
  });
  it('can change what is sold or the term while renewing; unlimited stays unlimited', async () => {
    await run(SIGN(['--customer', 'Big', '--iid', IID2, '--days', '100', '--bundle', '@residential', '--tenants', 'unlimited']), '2026-02-01T00:00:00Z');
    await run(['renew', '--customer', 'Big', '--days', '30', '--bundle', '@enterprise', '--key', path.join(keys, 'license-private.pem'), '--kid', 'k1'], '2026-05-01T00:00:00Z'); const b = ledger().filter((r) => r.customer === 'Big')[1];
    assert.strictEqual(b.kind, 'enterprise'); assert.strictEqual(b.days, 30); assert.strictEqual(b.limits.tenants, null); assert.deepStrictEqual(b.features, features.BUNDLES['@enterprise']);
  });
  it('an unknown customer, and one with several installations and no --iid, are plain errors; --iid picks one', async () => {
    const k = ['--key', path.join(keys, 'license-private.pem'), '--kid', 'k1']; await err(['renew', '--customer', 'Nobody', ...k], /no license has been issued/); await err(['renew', ...k], /usage: renew/);
    await run(SIGN(['--customer', 'Acme Corp', '--iid', IID2, '--days', '30', '--bundle', '@residential']), '2026-03-01T00:00:00Z');
    await err(['renew', '--customer', 'Acme Corp', ...k], /2 installations; say which with --iid/); await err(['renew', '--customer', 'Acme Corp', '--iid', '00000000-0000-4000-8000-000000000000', ...k], /no license for installation/);
    await run(['renew', '--customer', 'Acme Corp', '--iid', IID2, ...k], '2026-04-01T00:00:00Z'); assert.strictEqual(ledger().filter((r) => r.installation_id === IID2).length, 2);
  });
});

describe('integrity', () => {
  beforeEach(async () => { for (const [c, iid] of [['A', IID1], ['B', IID2], ['C', '*']]) await run(SIGN(['--customer', c, '--iid', iid, '--days', '30', '--bundle', '@residential'])); });
  it('says OK for an untouched ledger', async () => { assert.match(await run(['verify-ledger']), /Ledger OK: 3 record\(s\)/); });
  it('finds an edited line, a removed line, a reordered ledger, a changed license file and a missing one', async () => {
    const f = path.join(dir, 'ledger.jsonl'); const orig = fs.readFileSync(f, 'utf8'); const lines = orig.trim().split('\n');
    fs.writeFileSync(f, [lines[0].replace('"customer":"A"', '"customer":"Z"'), lines[1], lines[2]].join('\n') + '\n'); assert.match(await run(['verify-ledger']), /line 2 .*chain is broken/);
    fs.writeFileSync(f, [lines[0], lines[2]].join('\n') + '\n'); assert.match(await run(['verify-ledger']), /chain is broken/);
    fs.writeFileSync(f, [lines[0], lines[2], lines[1]].join('\n') + '\n'); assert.match(await run(['verify-ledger']), /chain is broken/);
    fs.writeFileSync(f, orig); const r = JSON.parse(lines[1]); fs.appendFileSync(path.join(dir, r.file), 'x'); assert.match(await run(['verify-ledger']), new RegExp(r.id + '.* has been changed'));
    fs.rmSync(path.join(dir, r.file)); assert.match(await run(['verify-ledger']), /is missing/);
  });
  it('a ledger line that is not JSON stops every command with a plain message', async () => { fs.appendFileSync(path.join(dir, 'ledger.jsonl'), 'oops\n'); await err(['list'], /not valid JSON: do not edit the ledger by hand/); });
});

describe('inspect and verify', () => {
  it('inspect shows the claims; verify says VALID with the right key, INVALID with another, and EXPIRED after the date', async () => {
    await run(SIGN(['--customer', 'Acme', '--iid', IID1, '--days', '30', '--bundle', '@residential']), '2026-11-01T00:00:00Z'); const file = path.join(dir, ledger()[0].file);
    assert.match(await run(['inspect', file]), /"customer": "Acme"/); assert.match(await run(['inspect', file]), /default \(30\)/);
    const pub = path.join(keys, 'license-public.pem'); assert.match(await run(['verify', file, '--pub', pub], '2026-11-10T00:00:00Z'), /^VALID: signed by this key, customer Acme, expires 2026-12-01/); assert.match(await run(['verify', file, '--pub', pub], '2026-12-05T00:00:00Z'), /EXPIRED/);
    const k2 = fs.mkdtempSync(path.join(os.tmpdir(), 'vkeys3-')); await tool.run(['keygen', k2], clock('2026-01-01T00:00:00Z')); assert.match(await run(['verify', file, '--pub', path.join(k2, 'license-public.pem')], '2026-11-10T00:00:00Z'), /^INVALID/);
  });
});

describe('the command line', () => {
  it('runs from the shell, prints a plain message for a mistake and exits 2, and prints help with no command', () => {
    const bin = path.join(__dirname, '..', 'license-vendor.js'); let r = spawnSync('node', [bin, 'sign', '--dir', dir], { encoding: 'utf8' }); assert.strictEqual(r.status, 2); assert.match(r.stderr, /^ERROR: --customer is required/); assert.ok(!/at .*license-vendor\.js/.test(r.stderr), 'no stack trace for a mistake');
    r = spawnSync('node', [bin], { encoding: 'utf8' }); assert.strictEqual(r.status, 0); assert.match(r.stdout, /keygen <dir>/); r = spawnSync('node', [bin, 'list', '--dir', dir], { encoding: 'utf8' }); assert.match(r.stdout, /No licenses\./);
  });
});

describe('agreement with the ASIX product', () => {
  const product = process.env.ASIX_PRODUCT_REPO;
  it('check-features says the names and bundles match the product repo (set ASIX_PRODUCT_REPO to run this)', { skip: !product }, async () => { assert.match(await run(['check-features', '--product', product]), /match the product/); });
  it('a license made here is accepted by the product\'s own license check as valid, for the right installation, with the grace period and limits (needs ASIX_PRODUCT_REPO)', { skip: !product }, async () => {
    await run(SIGN(['--customer', 'Acme', '--iid', IID1, '--days', '30', '--bundle', '@enterprise', '--tenants', '4', '--grace', '10']), '2026-11-08T00:00:00Z'); const token = fs.readFileSync(path.join(dir, ledger()[0].file), 'utf8').trim();
    const lic = require(path.join(product, 'src/licensing/license.js')); const pem = fs.readFileSync(path.join(keys, 'license-public.pem'), 'utf8'); const keysArr = [{ kid: 'k1', pem }];
    const ok = await lic.load({}, new Date('2026-11-20T00:00:00Z'), { keys: keysArr, iid: IID1, token }); assert.strictEqual(ok.status, 'valid'); assert.strictEqual(ok.customer, 'Acme'); assert.strictEqual(ok.kind, 'enterprise'); assert.deepStrictEqual(ok.limits, { tenants: 4 }); assert.strictEqual(ok.grace_days, 10);
    assert.strictEqual((await lic.load({}, new Date('2026-12-12T00:00:00Z'), { keys: keysArr, iid: IID1, token })).status, 'grace'); assert.strictEqual((await lic.load({}, new Date('2026-12-30T00:00:00Z'), { keys: keysArr, iid: IID1, token })).status, 'expired');
    assert.strictEqual((await lic.load({}, new Date('2026-11-20T00:00:00Z'), { keys: keysArr, iid: IID2, token })).status, 'wrong_install');
  });
  it('the feature lists in features.js are the two bundles with no repeats and no overlap between the products', () => {
    assert.strictEqual(new Set(features.ALL).size, features.ALL.length); assert.deepStrictEqual(features.BUNDLES['@enterprise'], [...features.RESIDENTIAL, ...features.ENTERPRISE_ONLY]); assert.ok(features.RESIDENTIAL.every((f) => !features.ENTERPRISE_ONLY.includes(f)));
  });
});
