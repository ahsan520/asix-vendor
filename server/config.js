'use strict';
// Server settings (README-SERVER.md). A JSON file (default ./config.json, or ASIX_VENDOR_CONFIG) merged over the defaults below. Secrets are never in the file: the OpenBao token and the SMTP
// password are read from the files the file names. Nothing here is ever sent to a browser.
const fs = require('fs');
const path = require('path');

const DEFAULTS = {
  port: 8443, bind: '127.0.0.1', dataDir: './data', baseUrl: 'http://localhost:8443',
  cookieSecure: true,                        // set false ONLY for local testing over plain http; production sits behind TLS
  signer: { type: 'openbao', addr: 'http://127.0.0.1:8200', tokenFile: null, mount: 'transit', key: 'asix-license', kid: 'asix-2026-1', caFile: null },
  smtp: { host: null, port: 587, secure: false, user: null, passFile: null, from: null, replyTo: null },
  approval: 'enterprise',                    // none | enterprise | all: which licenses need a second person to approve
  remindersEnabled: false, reminderDays: [60, 30, 7],
  sessionHours: 8,
};

function load(file, overrides = {}) {
  const f = file || process.env.ASIX_VENDOR_CONFIG || path.join(process.cwd(), 'config.json');
  let user = {};
  if (fs.existsSync(f)) { try { user = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { throw new Error('the configuration file ' + f + ' is not valid JSON: ' + e.message); } }
  const cfg = { ...DEFAULTS, ...user, ...overrides, signer: { ...DEFAULTS.signer, ...(user.signer || {}), ...(overrides.signer || {}) }, smtp: { ...DEFAULTS.smtp, ...(user.smtp || {}), ...(overrides.smtp || {}) } };
  cfg.dataDir = path.resolve(path.dirname(path.resolve(f)), cfg.dataDir);
  if (overrides.dataDir) cfg.dataDir = overrides.dataDir === ':memory:' ? ':memory:' : path.resolve(overrides.dataDir);
  validate(cfg); return cfg;
}
function validate(c) {
  const bad = (m) => { throw new Error('configuration: ' + m); };
  if (!Number.isInteger(c.port) || c.port < 1 || c.port > 65535) bad('port must be 1 to 65535');
  if (!['none', 'enterprise', 'all'].includes(c.approval)) bad('approval must be none, enterprise or all');
  if (!['openbao', 'local', 'kms'].includes(c.signer.type)) bad('signer.type must be openbao, local or kms');
  if (!/^[A-Za-z0-9._-]{1,40}$/.test(c.signer.kid || '')) bad('signer.kid must be letters, digits, . _ - (up to 40)');
  if (c.signer.type === 'openbao' && !/^https?:\/\//.test(c.signer.addr || '')) bad('signer.addr must be an http(s) address');
  if (!Array.isArray(c.reminderDays) || c.reminderDays.some((d) => !Number.isInteger(d) || d < 1 || d > 365)) bad('reminderDays must be a list of days from 1 to 365');
  if (!(c.sessionHours >= 1 && c.sessionHours <= 72)) bad('sessionHours must be 1 to 72');
}
module.exports = { load, DEFAULTS };
