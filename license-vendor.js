#!/usr/bin/env node
'use strict';
// ASIX vendor tool: signs licenses AND keeps the ledger of every license you have issued (README.md). Keep this folder in a PRIVATE repository; never ship it to a customer.
//
//   keygen <dir> [kid]                 make the signing key pair (private key: keep it OFFLINE, outside this folder)
//   sign   --customer NAME --iid ID|* --days N (--bundle @residential|@enterprise | --features a,b) --key private.pem --kid KID
//          [--tenants N|unlimited] [--retention N|unlimited] [--grace 0-90] [--note TEXT] [--out FILE]
//   renew  --customer NAME [--iid ID] [--days N] --key private.pem --kid KID [same options to change something]
//   list [--all]                       every customer's current license, soonest expiry first
//   expiring [--days N]                licenses expiring within N days (default 60) or already expired
//   show   NAME                        the whole history of one customer
//   inspect FILE|TOKEN                 what a license says (not verified)
//   verify  FILE|TOKEN --pub public.pem   checks the signature and the dates
//   verify-ledger                      detects an edited, deleted or reordered ledger line and a changed or missing license file
//   export [--out FILE.csv]            the ledger as CSV (no license text)
//   check-features --product DIR       compares the feature names with the ASIX product repo
//
// Everything is written under --dir (default: this folder): ledger.jsonl (append-only, hash-chained) and issued/ (one file per license).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { generateKeyPair, exportPKCS8, exportSPKI, importPKCS8, importSPKI, SignJWT, jwtVerify, decodeJwt, decodeProtectedHeader } = require('jose');
const { BUNDLES, ENTERPRISE_ONLY, ALL } = require('./features');

const DAY = 86400000;
const ZERO = '0'.repeat(64);
const IID_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\*)$/;
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
const fail = (m) => { const e = new Error(m); e.vendor = true; throw e; };
const day = (d) => new Date(d).toISOString().slice(0, 10);

// ---- the ledger: one JSON line per license, each carrying the hash of the line before it ---------------------------------------------------------------------------------
const ledgerFile = (dir) => path.join(dir, 'ledger.jsonl');
function readLedger(dir) {
  const f = ledgerFile(dir); if (!fs.existsSync(f)) return [];
  const lines = fs.readFileSync(f, 'utf8').split('\n').filter((l) => l.trim() !== '');
  return lines.map((l, i) => { try { return JSON.parse(l); } catch { return fail('ledger line ' + (i + 1) + ' is not valid JSON: do not edit the ledger by hand'); } });
}
function appendRecord(dir, rec) {
  const f = ledgerFile(dir); fs.mkdirSync(dir, { recursive: true });
  const lines = fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\n').filter((l) => l.trim() !== '') : [];
  rec.prev = lines.length ? sha256(lines[lines.length - 1]) : ZERO;
  fs.appendFileSync(f, JSON.stringify(rec) + '\n', { mode: 0o600 });
  return rec;
}
// The current license of each customer installation = the latest record for that (customer, installation id).
function current(records) {
  const m = new Map(); for (const r of records) m.set(slug(r.customer) + '|' + r.installation_id, r);
  return [...m.values()];
}

// ---- features ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
function expandFeatures(spec) {
  const out = new Set();
  for (const part of String(spec).split(',').map((x) => x.trim()).filter(Boolean)) {
    if (BUNDLES[part]) BUNDLES[part].forEach((f) => out.add(f));
    else if (ALL.includes(part)) out.add(part);
    else fail('unknown feature or bundle "' + part + '" (bundles: ' + Object.keys(BUNDLES).join(', ') + '; features: ' + ALL.join(', ') + ')');
  }
  if (!out.size) fail('a license needs at least one feature: use --bundle or --features');
  return [...out];
}
const limitArg = (v, name) => { if (v === undefined) return undefined; if (v === 'unlimited') return null; const n = parseInt(v, 10); if (!(n > 0) || String(n) !== String(v)) fail(name + ' must be a positive number or "unlimited"'); return n; };

// ---- signing ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
async function issue(o, ctx) {
  const customer = String(o.customer || '').trim(); if (!customer || customer.length > 120) fail('--customer is required (up to 120 characters)');
  if (!IID_RE.test(String(o.iid || ''))) fail('--iid must be the installation id shown on the customer\'s License page (a UUID), or *');
  const days = parseInt(o.days, 10); if (!(days > 0 && days <= 3650) || String(days) !== String(o.days)) fail('--days must be a number from 1 to 3650');
  const features = expandFeatures(o.features || o.bundle || '');
  if (o.grace !== undefined && !(/^\d+$/.test(String(o.grace)) && +o.grace >= 0 && +o.grace <= 90)) fail('--grace must be 0 to 90');
  if (!o.key) fail('--key (the private key file) is required'); if (!o.kid) fail('--kid (the key id) is required');
  const keyPath = path.resolve(o.key); if (!fs.existsSync(keyPath)) fail('cannot read the private key ' + o.key);
  const dirReal = path.resolve(ctx.dir) + path.sep;
  if (keyPath.startsWith(dirReal) && !o.allowKeyHere) fail('the private key is inside this folder, which belongs in a repository. Keep it OFFLINE, outside this folder (or pass --allow-key-in-folder at your own risk)');
  const limits = {}; const t = limitArg(o.tenants, '--tenants'), r = limitArg(o.retention, '--retention'); if (t !== undefined) limits.tenants = t; if (r !== undefined) limits.retention_days_max = r;
  const kind = features.some((f) => ENTERPRISE_ONLY.includes(f)) ? 'enterprise' : 'residential';
  const claims = { features, limits, iid: o.iid, kind }; if (o.grace !== undefined) claims.grace_days = +o.grace;
  let key; try { key = await importPKCS8(fs.readFileSync(keyPath, 'utf8'), 'EdDSA'); } catch { fail('that is not an Ed25519 private key in PKCS8 PEM form'); }
  const now = ctx.now(), iat = Math.floor(now.getTime() / 1000), exp = iat + days * 86400;
  const token = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', kid: o.kid }).setIssuer('asix').setSubject(customer).setIssuedAt(iat).setExpirationTime(exp).sign(key);
  const id = 'L-' + day(now).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex');
  const file = path.join('issued', slug(customer) + '-' + id + '.jwt');
  fs.mkdirSync(path.join(ctx.dir, 'issued'), { recursive: true }); fs.writeFileSync(path.join(ctx.dir, file), token + '\n', { mode: 0o600 });
  const rec = { id, issued_at: now.toISOString(), customer, kind, installation_id: o.iid, features, limits, grace_days: o.grace === undefined ? null : +o.grace, kid: o.kid, days, expires_at: new Date(exp * 1000).toISOString(),
    license_sha256: sha256(token), file: file.split(path.sep).join('/'), note: o.note ? String(o.note).slice(0, 300) : null, issued_by: ctx.user, supersedes: o.supersedes || null };
  appendRecord(ctx.dir, rec);
  if (o.out) fs.writeFileSync(o.out, token + '\n', { mode: 0o600 });
  return { rec, token };
}

function findCurrent(ctx, customer, iid) {
  const want = slug(customer); const hits = current(readLedger(ctx.dir)).filter((r) => slug(r.customer) === want);
  if (!hits.length) fail('no license has been issued to "' + customer + '" (see: list)');
  if (iid) { const h = hits.find((r) => r.installation_id === iid); if (!h) fail('"' + customer + '" has no license for installation ' + iid); return h; }
  if (hits.length > 1) fail('"' + customer + '" has ' + hits.length + ' installations; say which with --iid: ' + hits.map((r) => r.installation_id).join(', '));
  return hits[0];
}

// ---- reports -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
const daysLeft = (r, now) => Math.floor((new Date(r.expires_at).getTime() - now.getTime()) / DAY);
const status = (r, now) => { const d = daysLeft(r, now); return d < 0 ? 'EXPIRED' : d <= 60 ? 'expiring' : 'active'; };
function table(rows, cols) {
  const w = cols.map((c, i) => Math.max(c.length, ...rows.map((r) => String(r[i]).length)));
  return [cols.map((c, i) => c.padEnd(w[i])).join('  '), w.map((n) => '-'.repeat(n)).join('  '), ...rows.map((r) => r.map((v, i) => String(v).padEnd(w[i])).join('  '))].join('\n');
}
function listText(ctx, all, only) {
  const now = ctx.now(); let recs = all ? readLedger(ctx.dir) : current(readLedger(ctx.dir));
  if (only) recs = recs.filter(only);
  recs = recs.slice().sort((a, b) => new Date(a.expires_at) - new Date(b.expires_at));
  if (!recs.length) return all ? 'The ledger is empty.' : 'No licenses.';
  return table(recs.map((r) => [r.customer, r.kind, r.installation_id === '*' ? '* (any)' : r.installation_id.slice(0, 8) + '...', day(r.expires_at), status(r, now) === 'EXPIRED' ? 'EXPIRED ' + (-daysLeft(r, now)) + 'd ago' : daysLeft(r, now) + ' days', status(r, now), r.features.length, r.id]),
    ['Customer', 'Kind', 'Installation', 'Expires', 'Left', 'Status', 'Features', 'Id']);
}

// ---- ledger integrity -------------------------------------------------------------------------------------------------------------------------------------------------------------
function verifyLedger(ctx) {
  const problems = []; const f = ledgerFile(ctx.dir);
  const lines = fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\n').filter((l) => l.trim() !== '') : [];
  let prev = ZERO, n = 0;
  for (const [i, l] of lines.entries()) {
    let r; try { r = JSON.parse(l); } catch { problems.push('line ' + (i + 1) + ': not valid JSON'); break; }
    if (r.prev !== prev) problems.push('line ' + (i + 1) + ' (' + r.id + '): the chain is broken: a line before it was edited, removed or reordered');
    prev = sha256(l); n += 1;
    const lf = path.join(ctx.dir, r.file || '');
    if (!r.file || !fs.existsSync(lf)) problems.push('line ' + (i + 1) + ' (' + r.id + '): the license file ' + r.file + ' is missing');
    else if (sha256(fs.readFileSync(lf, 'utf8').trim()) !== r.license_sha256) problems.push('line ' + (i + 1) + ' (' + r.id + '): the license file ' + r.file + ' has been changed');
  }
  return { ok: problems.length === 0, count: n, problems };
}

const readLicenseArg = (a) => { if (!a) fail('give a license file or the license text'); const t = fs.existsSync(a) ? fs.readFileSync(a, 'utf8') : a; return t.replace(/\s+/g, ''); };
const csvCell = (v) => { const s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join(' ') : typeof v === 'object' ? JSON.stringify(v) : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

// ---- the command line --------------------------------------------------------------------------------------------------------------------------------------------------------------------
function parse(argv) {
  const pos = [], o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--all') o.all = true; else if (a === '--allow-key-in-folder') o.allowKeyHere = true;
    else if (a.startsWith('--')) { const k = a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase()); if (i + 1 >= argv.length) fail('the option ' + a + ' needs a value'); o[k] = argv[++i]; }
    else pos.push(a);
  }
  return { pos, o };
}

// run(argv, { dir, now, user }) -> text to print. Throws an Error with .vendor = true for a mistake the person made.
async function run(argv, env = {}) {
  const { pos, o } = parse(argv); const cmd = pos[0];
  const ctx = { dir: path.resolve(o.dir || env.dir || __dirname), now: env.now || (() => new Date()), user: env.user || (process.env.USER || process.env.USERNAME || 'unknown') };
  switch (cmd) {
    case 'keygen': {
      if (!pos[1]) fail('usage: keygen <dir> [kid]'); const kid = pos[2] || 'asix-' + ctx.now().getFullYear() + '-1';
      const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
      fs.mkdirSync(pos[1], { recursive: true }); const pub = await exportSPKI(publicKey);
      if (fs.existsSync(path.join(pos[1], 'license-private.pem'))) fail('license-private.pem already exists there: refusing to overwrite a signing key');
      fs.writeFileSync(path.join(pos[1], 'license-private.pem'), await exportPKCS8(privateKey), { mode: 0o600 }); fs.writeFileSync(path.join(pos[1], 'license-public.pem'), pub);
      return 'Wrote license-private.pem (keep it OFFLINE: password manager + encrypted backup, never on a server, never in Git) and license-public.pem.\nPaste this line into KEYS in src/licensing/vendor-keys.js of the ASIX product repo:\n\n  { kid: \'' + kid + '\', pem: \'' + pub.trim().replace(/\n/g, '\\n') + '\\n\' },';
    }
    case 'sign': { const { rec } = await issue(o, ctx); return 'Issued ' + rec.id + ' to ' + rec.customer + ' (' + rec.kind + '), expires ' + day(rec.expires_at) + '.\nSend them: ' + path.join(ctx.dir, rec.file) + '\nThey store and activate it on the License page. Recorded in the ledger.'; }
    case 'renew': {
      if (!o.customer) fail('usage: renew --customer NAME [--iid ID] [--days N] --key FILE --kid KID'); const old = findCurrent(ctx, o.customer, o.iid);
      const merged = { customer: old.customer, iid: old.installation_id, days: o.days || old.days, features: o.features || o.bundle || old.features.join(','), grace: o.grace !== undefined ? o.grace : (old.grace_days === null ? undefined : old.grace_days),
        tenants: o.tenants !== undefined ? o.tenants : (old.limits.tenants === undefined ? undefined : old.limits.tenants === null ? 'unlimited' : old.limits.tenants),
        retention: o.retention !== undefined ? o.retention : (old.limits.retention_days_max === undefined ? undefined : old.limits.retention_days_max === null ? 'unlimited' : old.limits.retention_days_max),
        key: o.key, kid: o.kid, allowKeyHere: o.allowKeyHere, note: o.note || null, out: o.out, supersedes: old.id };
      const { rec } = await issue(merged, ctx); return 'Renewed ' + rec.customer + ': ' + rec.id + ' replaces ' + old.id + ', expires ' + day(rec.expires_at) + '.\nSend them: ' + path.join(ctx.dir, rec.file);
    }
    case 'list': return listText(ctx, !!o.all);
    case 'expiring': {
      const n = o.days === undefined ? 60 : parseInt(o.days, 10); if (!(n >= 0)) fail('--days must be a number'); const now = ctx.now();
      const t = listText(ctx, false, (r) => daysLeft(r, now) <= n); return t === 'No licenses.' ? 'Nothing expires within ' + n + ' days.' : t;
    }
    case 'show': {
      if (!pos[1]) fail('usage: show NAME'); const w = slug(pos[1]); const recs = readLedger(ctx.dir).filter((r) => slug(r.customer).includes(w));
      if (!recs.length) fail('no license has been issued to "' + pos[1] + '"');
      return recs.map((r) => [r.id + '  ' + r.customer + '  (' + r.kind + ')', '  issued ' + day(r.issued_at) + ' by ' + r.issued_by + ', expires ' + day(r.expires_at) + ', ' + r.days + ' days' + (r.grace_days === null ? '' : ', grace ' + r.grace_days), '  installation ' + r.installation_id,
        '  features: ' + r.features.join(', '), '  limits: ' + JSON.stringify(r.limits), '  file: ' + r.file + (r.supersedes ? '   replaces ' + r.supersedes : ''), r.note ? '  note: ' + r.note : null].filter(Boolean).join('\n')).join('\n\n');
    }
    case 'inspect': { const t = readLicenseArg(pos[1]); const p = decodeJwt(t); return JSON.stringify({ kid: decodeProtectedHeader(t).kid, customer: p.sub, kind: p.kind, installation: p.iid, features: p.features, limits: p.limits, grace_days: p.grace_days === undefined ? 'default (30)' : p.grace_days, issued: new Date(p.iat * 1000).toISOString(), expires: new Date(p.exp * 1000).toISOString() }, null, 2); }
    case 'verify': {
      if (!o.pub) fail('usage: verify FILE|TOKEN --pub license-public.pem'); const t = readLicenseArg(pos[1]); const key = await importSPKI(fs.readFileSync(o.pub, 'utf8'), 'EdDSA');
      try { const { payload } = await jwtVerify(t, key, { algorithms: ['EdDSA'], issuer: 'asix', currentDate: ctx.now() }); return 'VALID: signed by this key, customer ' + payload.sub + ', expires ' + day(payload.exp * 1000); }
      catch (e) { if (e && e.code === 'ERR_JWT_EXPIRED') return 'SIGNATURE OK but EXPIRED (grace applies on the customer side if the license allows it)'; return 'INVALID: ' + (e && e.code ? e.code : 'not a license signed by this key'); }
    }
    case 'verify-ledger': { const v = verifyLedger(ctx); return v.ok ? 'Ledger OK: ' + v.count + ' record(s), chain intact, every license file present and unchanged.' : 'LEDGER PROBLEMS:\n' + v.problems.map((p) => '  - ' + p).join('\n'); }
    case 'export': {
      const cols = ['id', 'issued_at', 'customer', 'kind', 'installation_id', 'features', 'limits', 'grace_days', 'kid', 'days', 'expires_at', 'license_sha256', 'file', 'note', 'issued_by', 'supersedes'];
      const csv = [cols.join(','), ...readLedger(ctx.dir).map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\n') + '\n';
      if (o.out) { fs.writeFileSync(o.out, csv); return 'Wrote ' + o.out; } return csv.trimEnd();
    }
    case 'check-features': {
      if (!o.product) fail('usage: check-features --product /path/to/ash-app-builder'); const f = path.join(o.product, 'src', 'licensing', 'bundles.js'); if (!fs.existsSync(f)) fail('cannot find ' + f);
      const p = require(path.resolve(f)); const mine = new Set(ALL), theirs = new Set(p.ALL);
      const onlyMine = [...mine].filter((x) => !theirs.has(x)), onlyTheirs = [...theirs].filter((x) => !mine.has(x));
      const same = (a, b) => a.length === b.length && a.every((x) => b.includes(x));
      const bundleDiff = !same(BUNDLES['@residential'], p.BUNDLES['@residential']) || !same(BUNDLES['@enterprise'], p.BUNDLES['@enterprise']);
      return !onlyMine.length && !onlyTheirs.length && !bundleDiff ? 'Feature names and bundles match the product.' : 'DIFFERENT from the product:\n' + (onlyMine.length ? '  only here: ' + onlyMine.join(', ') + '\n' : '') + (onlyTheirs.length ? '  only in the product: ' + onlyTheirs.join(', ') + '\n' : '') + (bundleDiff ? '  the @residential or @enterprise bundle differs\n' : '') + 'Update features.js before issuing licenses.';
    }
    default: return fs.readFileSync(__filename, 'utf8').split('\n').slice(2, 18).map((l) => l.replace(/^\/\/ ?/, '')).join('\n');
  }
}

module.exports = { run, readLedger, verifyLedger, current };
if (require.main === module) {
  run(process.argv.slice(2)).then((t) => { console.log(t); }).catch((e) => { console.error(e.vendor ? 'ERROR: ' + e.message : e.stack); process.exit(e.vendor ? 2 : 1); });
}
