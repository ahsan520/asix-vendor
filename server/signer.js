'use strict';
// The signer: the ONLY thing in this server that touches the license signing key, and it never sees the key.
//   openbao : the key lives inside OpenBao (transit secrets engine, type ed25519, not exportable); this server asks it to sign and gets a signature back. (HashiCorp Vault answers the same API.)
//   local   : a private key file on this machine. For tests and a break-glass fallback only: the key is on disk.
//   kms     : AWS KMS (Ed25519). The interface is here; the adapter is NOT built yet.
// sign(bytes) returns the raw 64-byte Ed25519 signature of exactly those bytes. publicKeyPem() returns the matching public key, so every license can be checked before it leaves this server.
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');

const SPKI_ED25519 = Buffer.from('302a300506032b6570032100', 'hex');
const pemFromRaw = (raw) => '-----BEGIN PUBLIC KEY-----\n' + Buffer.concat([SPKI_ED25519, raw]).toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END PUBLIC KEY-----\n';

function request(url, { method = 'GET', headers = {}, body, ca, timeoutMs = 10000 }) {
  return new Promise((resolve, reject) => {
    const u = new URL(url); const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, { method, headers: { ...headers, ...(body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } : {}) }, ca, timeout: timeoutMs }, (res) => {
      let b = ''; res.on('data', (c) => { b += c; if (b.length > 1e6) req.destroy(new Error('answer too large')); }); res.on('end', () => { let j = null; try { j = b ? JSON.parse(b) : null; } catch { /* not JSON */ } resolve({ status: res.statusCode, json: j, text: b }); });
    });
    req.on('timeout', () => req.destroy(new Error('the signing service did not answer in time'))); req.on('error', reject); if (body) req.write(body); req.end();
  });
}

function openbao(c) {
  const base = c.addr.replace(/\/+$/, ''), mount = c.mount.replace(/^\/+|\/+$/g, ''), key = encodeURIComponent(c.key);
  const ca = c.caFile ? fs.readFileSync(c.caFile) : undefined;
  const token = () => { const t = c.tokenFile ? fs.readFileSync(c.tokenFile, 'utf8').trim() : process.env.ASIX_VENDOR_BAO_TOKEN; if (!t) throw new Error('no OpenBao token: set signer.tokenFile'); return t; };
  const call = async (method, p, body) => {
    let r; try { r = await request(base + '/v1/' + p, { method, headers: { 'X-Vault-Token': token() }, body: body ? JSON.stringify(body) : undefined, ca }); } catch (e) { throw new Error('the signing service cannot be reached: ' + e.message); }
    if (r.status === 503) throw new Error('the signing service is sealed or not ready: unseal it first');
    if (r.status === 403) throw new Error('the signing service refused this server\'s token (check its policy)');
    if (r.status === 404) throw new Error('the signing key "' + c.key + '" was not found in ' + mount);
    if (r.status < 200 || r.status >= 300) throw new Error('the signing service answered ' + r.status + (r.json && r.json.errors ? ': ' + r.json.errors.join('; ') : ''));
    return r.json;
  };
  return {
    type: 'openbao', kid: c.kid,
    async publicKeyPem() {
      const d = (await call('GET', mount + '/keys/' + key)).data; if (d.type !== 'ed25519') throw new Error('the signing key must be type ed25519, it is ' + d.type);
      if (d.exportable) throw new Error('the signing key is exportable: create it again with exportable=false');
      const v = String(d.latest_version); const raw = Buffer.from(d.keys[v].public_key, 'base64'); if (raw.length !== 32) throw new Error('unexpected public key');
      return pemFromRaw(raw);   // fetched every time (no cache): after a key rotation the next license is checked against the key that signed it
    },
    async sign(bytes) {
      const d = (await call('POST', mount + '/sign/' + key, { input: Buffer.from(bytes).toString('base64') })).data;
      const parts = String(d.signature).split(':'); const sig = Buffer.from(parts[2] || '', 'base64'); if (parts[0] !== 'vault' || sig.length !== 64) throw new Error('unexpected signature from the signing service');
      return sig;
    },
    // A periodic token must be renewed before its period ends: the server does it at start and every 12 hours (index.js).
    async renew() { await call('POST', 'auth/token/renew-self', {}); },
    async health() { try { const r = await request(base + '/v1/sys/health', { ca }); if (r.status === 200) return { ok: true, detail: 'OpenBao is up and unsealed' }; if (r.status === 503) return { ok: false, detail: 'OpenBao is sealed: unseal it' }; return { ok: false, detail: 'OpenBao answered ' + r.status }; } catch (e) { return { ok: false, detail: 'cannot reach OpenBao: ' + e.message }; } },
  };
}

function local(c) {
  const priv = crypto.createPrivateKey(fs.readFileSync(c.keyFile)); const pem = crypto.createPublicKey(priv).export({ type: 'spki', format: 'pem' });
  return { type: 'local', kid: c.kid, async publicKeyPem() { return pem; }, async sign(bytes) { return crypto.sign(null, Buffer.from(bytes), priv); }, async health() { return { ok: true, detail: 'a private key file is in use: for testing only' }; } };
}
function kms() { return { type: 'kms', kid: '-', async publicKeyPem() { throw new Error('the AWS KMS adapter is not built yet'); }, async sign() { throw new Error('the AWS KMS adapter is not built yet'); }, async health() { return { ok: false, detail: 'the AWS KMS adapter is not built yet' }; } }; }

function create(cfg) { const c = cfg.signer; return c.type === 'openbao' ? openbao(c) : c.type === 'local' ? local(c) : kms(); }
module.exports = { create, pemFromRaw };
