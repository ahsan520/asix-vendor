'use strict';
// Building a license: validate what was asked for, make the signed token (a compact JWS, alg EdDSA, exactly the format the ASIX product checks), sign it through the signer, and check the
// signature with the public key BEFORE it is kept or sent. The claims are the same as the command-line tool's: features, limits, installation id, kind and an optional grace period.
const crypto = require('crypto');
const { importSPKI, jwtVerify } = require('jose');
const { RESIDENTIAL, ENTERPRISE_ONLY, BUNDLES, ALL } = require('../features');

const IID_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\*)$/;
const b64u = (b) => Buffer.from(b).toString('base64url');
const TEMPLATES = {
  residential: { label: 'Residential', features: BUNDLES['@residential'], days: 365, grace: null },
  enterprise: { label: 'Enterprise', features: BUNDLES['@enterprise'], days: 365, grace: null },
  trial: { label: 'Trial (30 days, no grace)', features: BUNDLES['@enterprise'], days: 30, grace: 0 },
};

const fail = (m) => { const e = new Error(m); e.invalid = true; throw e; };
const limitArg = (v, name) => { if (v === undefined || v === null || v === '') return undefined; if (v === 'unlimited') return null; const n = Number(v); if (!Number.isInteger(n) || n < 1 || n > 1e6) fail(name + ' must be a whole number from 1, or "unlimited"'); return n; };

// What a request may contain: { template?, features?, days, tenants?, retention?, grace?, note? } -> { features, limits, days, grace, kind, note }
function normalize(p) {
  if (!p || typeof p !== 'object') fail('the request is empty');
  const t = p.template && p.template !== 'custom' ? TEMPLATES[p.template] : null; if (p.template && p.template !== 'custom' && !t) fail('unknown template "' + String(p.template).slice(0, 20) + '"');
  let features = Array.isArray(p.features) && p.features.length ? p.features : t ? t.features : [];
  if (!Array.isArray(features) || features.some((f) => typeof f !== 'string')) fail('features must be a list of names');
  for (const f of features) if (!ALL.includes(f)) fail('unknown feature "' + f.slice(0, 40) + '"');
  features = ALL.filter((f) => features.includes(f)); if (!features.length) fail('choose a template or at least one feature');
  const days = p.days === undefined || p.days === '' ? (t ? t.days : undefined) : Number(p.days); if (!Number.isInteger(days) || days < 1 || days > 3650) fail('days must be a whole number from 1 to 3650');
  let grace = p.grace === undefined || p.grace === '' || p.grace === null ? (t ? t.grace : null) : Number(p.grace); if (grace !== null && (!Number.isInteger(grace) || grace < 0 || grace > 90)) fail('grace must be 0 to 90 days');
  const limits = {}; const tn = limitArg(p.tenants, 'tenants'), rt = limitArg(p.retention, 'retention'); if (tn !== undefined) limits.tenants = tn; if (rt !== undefined) limits.retention_days_max = rt;
  const note = p.note === undefined || p.note === null ? null : String(p.note).trim().slice(0, 300) || null;
  return { features, limits, days, grace, kind: features.some((f) => ENTERPRISE_ONLY.includes(f)) ? 'enterprise' : 'residential', note };
}
const validInstallationId = (s) => IID_RE.test(String(s || ''));

// Who must approve: policy none | enterprise | all. Under "enterprise" an enterprise license, a term over 400 days, or an any-installation license needs a second person.
function needsApproval(policy, norm, iid) { return policy === 'all' || (policy === 'enterprise' && (norm.kind === 'enterprise' || norm.days > 400 || iid === '*')); }

async function issue(signer, { customer, iid, norm, now = new Date() }) {
  const iat = Math.floor(now.getTime() / 1000), exp = iat + norm.days * 86400;
  const claims = { features: norm.features, limits: norm.limits, iid, kind: norm.kind }; if (norm.grace !== null) claims.grace_days = norm.grace;
  const header = b64u(JSON.stringify({ alg: 'EdDSA', kid: signer.kid })), payload = b64u(JSON.stringify({ ...claims, iss: 'asix', sub: customer, iat, exp }));
  const input = header + '.' + payload; const token = input + '.' + b64u(await signer.sign(Buffer.from(input)));
  // Never release a license that does not verify against the signer's own public key (wrong key, wrong version, a broken service).
  try { await jwtVerify(token, await importSPKI(await signer.publicKeyPem(), 'EdDSA'), { algorithms: ['EdDSA'], issuer: 'asix', currentDate: now }); }
  catch (e) { throw new Error('the signature did not verify against the signing key: nothing was issued (' + (e.code || e.message) + ')'); }
  return { token, issued_at: new Date(iat * 1000).toISOString(), expires_at: new Date(exp * 1000).toISOString(), token_sha256: crypto.createHash('sha256').update(token).digest('hex') };
}
const newLicenseId = (now = new Date()) => 'L-' + now.toISOString().slice(0, 10).replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex');
const vendorKeysLine = (kid, pem) => "{ kid: '" + kid + "', pem: '" + pem.trim().replace(/\n/g, '\\n') + "\\n' },";

module.exports = { TEMPLATES, normalize, validInstallationId, needsApproval, issue, newLicenseId, vendorKeysLine, IID_RE, RESIDENTIAL, ENTERPRISE_ONLY };
