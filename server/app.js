'use strict';
// The vendor server's API and pages. Everything here runs as a signed-in staff member with a role (auth.js), every change is written to the audit log, and nothing secret is ever returned.
const path = require('path');
const express = require('express');
const auth = require('./auth');
const audit = require('./audit');
const { tx } = require('./db');
const lic = require('./license');
const mail = require('./mail');
const { ALL } = require('../features');

const DAY = 86400000;
const COOKIE = 'asix_vendor_sid';
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 50) || 'license';
const bad = (m, status = 400) => { const e = new Error(m); e.invalid = true; e.status = status; return e; };
const j = (s) => (s ? JSON.parse(s) : null);
const PLACEHOLDERS = ['customer', 'kind', 'expires', 'installation', 'message', 'days'];

function createApp(ctx) {
  const { cfg, db, signer } = ctx; const now = ctx.now || (() => new Date());
  const app = express(); app.disable('x-powered-by');
  const ipFails = new Map(); const sendTimes = new Map(); const inflight = new Set();

  // ---- helpers ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  const ok = (res, body = {}, status = 200) => res.status(status).json({ success: true, ...body });
  const wrap = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch((e) => {
    if (e && e.invalid) return res.status(e.status || 400).json({ success: false, error: { code: 'INVALID', message: e.message } });
    console.error('API error:', e && e.stack || e); return res.status(500).json({ success: false, error: { code: 'ERROR', message: 'Something went wrong on the server' } });
  });
  const cookies = (req) => Object.fromEntries(String(req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((p) => p[0] && p[1]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
  const setCookie = (res, token, hours) => res.setHeader('Set-Cookie', COOKIE + '=' + encodeURIComponent(token) + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + Math.round(hours * 3600) + (cfg.cookieSecure ? '; Secure' : ''));
  const clearCookie = (res) => res.setHeader('Set-Cookie', COOKIE + '=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' + (cfg.cookieSecure ? '; Secure' : ''));
  const actor = (req) => (req.user ? req.user.username : 'anonymous');
  const A = (req, action, target, detail) => audit.log(db, actor(req), action, target, detail, now());

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if (req.path.startsWith('/api')) res.setHeader('Cache-Control', 'no-store'); next();
  });
  app.use(express.json({ limit: '64kb' }));
  app.use((err, req, res, next) => (err ? res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'The request could not be read' } }) : next()));

  // Everything under /api except login and health needs a session; every change needs the CSRF token the page was given.
  app.use('/api', (req, res, next) => {
    if (req.path === '/login' || req.path === '/health') return next();
    req.user = auth.sessionUser(db, cookies(req)[COOKIE], now());
    if (!req.user) return res.status(401).json({ success: false, error: { code: 'UNAUTHENTICATED', message: 'Sign in first' } });
    if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-csrf-token'] !== req.user.csrf) return res.status(403).json({ success: false, error: { code: 'CSRF', message: 'The page is out of date: reload it' } });
    next();
  });
  const need = (what) => (req, res, next) => (auth.can(req.user, what) ? next() : res.status(403).json({ success: false, error: { code: 'FORBIDDEN', message: 'Your role cannot do this' } }));

  app.get('/api/health', (req, res) => ok(res, { status: 'up' }));

  // ---- sign-in ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  app.post('/api/login', wrap(async (req, res) => {
    const { username, password, code } = req.body || {}; const ip = req.ip || 'x'; const t = now();
    const fails = (ipFails.get(ip) || []).filter((x) => t.getTime() - x < 15 * 60000); ipFails.set(ip, fails);
    const deny = (why) => { fails.push(t.getTime()); audit.log(db, String(username || '').slice(0, 60) || 'anonymous', 'login.failed', null, { why }, t); return res.status(401).json({ success: false, error: { code: 'LOGIN_FAILED', message: 'Sign-in failed' } }); };
    if (fails.length >= 20) return res.status(429).json({ success: false, error: { code: 'TOO_MANY', message: 'Too many attempts: wait a few minutes' } });
    if (typeof username !== 'string' || typeof password !== 'string' || typeof code !== 'string') return deny('missing fields');
    const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!u) { auth.checkPassword(password, null); return deny('unknown user'); }
    if (u.locked_until && new Date(u.locked_until) > t) { auth.checkPassword(password, null); return deny('locked'); }
    const passOk = auth.checkPassword(password, u.password_hash); const step = passOk ? auth.totpMatch(u.totp_secret, code, t) : null;
    if (!passOk || step === null || step <= u.totp_last || !u.active) {
      const failed = u.failed + 1; db.prepare('UPDATE users SET failed = ?, locked_until = ? WHERE id = ?').run(failed >= auth.LOCK_AFTER ? 0 : failed, failed >= auth.LOCK_AFTER ? new Date(t.getTime() + auth.LOCK_MINUTES * 60000).toISOString() : null, u.id);
      return deny(!u.active ? 'disabled' : !passOk ? 'password' : 'code');
    }
    db.prepare('UPDATE users SET failed = 0, locked_until = NULL, totp_last = ? WHERE id = ?').run(step, u.id);
    const s = auth.createSession(db, u.id, cfg.sessionHours, t); setCookie(res, s.token, cfg.sessionHours); audit.log(db, u.username, 'login', null, null, t);
    return ok(res, { user: { username: u.username, name: u.name, role: u.role }, csrf: s.csrf });
  }));
  app.post('/api/logout', wrap(async (req, res) => { auth.endSession(db, cookies(req)[COOKIE]); clearCookie(res); A(req, 'logout'); ok(res); }));
  app.get('/api/me', (req, res) => ok(res, { user: { username: req.user.username, name: req.user.name, email: req.user.email, role: req.user.role }, csrf: req.user.csrf }));
  app.post('/api/me/password', wrap(async (req, res) => {
    const { current, next: nw } = req.body || {}; const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!auth.checkPassword(String(current || ''), u.password_hash)) throw bad('The current password is not right'); const p = auth.passwordProblem(nw); if (p) throw bad(p);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(auth.hashPassword(nw), u.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND csrf <> ?').run(u.id, req.user.csrf); A(req, 'user.password_changed', u.username); ok(res);
  }));

  // ---- clients and installations --------------------------------------------------------------------------------------------------------------------------------------
  const cleanContacts = (list) => {
    if (list === undefined) return []; if (!Array.isArray(list) || list.length > 20) throw bad('contacts must be a list of up to 20 people');
    return list.map((c) => { const email = String((c && c.email) || '').trim().toLowerCase(); if (!mail.EMAIL_RE.test(email) || email.length > 200) throw bad('"' + email.slice(0, 60) + '" is not an e-mail address');
      return { name: String((c && c.name) || '').trim().slice(0, 120), email, license: c.license !== false, renewals: c.renewals !== false }; });
  };
  const clientRow = (r) => ({ id: r.id, name: r.name, reference: r.reference, notes: r.notes, contacts: j(r.contacts) || [], archived: !!r.archived, created_at: r.created_at });
  const clientFields = (b) => {
    const name = String(b.name || '').trim(); if (!name || name.length > 120) throw bad('the client needs a name (up to 120 characters)');
    return { name, reference: b.reference ? String(b.reference).trim().slice(0, 80) : null, notes: b.notes ? String(b.notes).slice(0, 2000) : null, contacts: JSON.stringify(cleanContacts(b.contacts)) };
  };
  const stateOf = (l) => { if (l.status !== 'issued') return l.status; const d = Math.floor((new Date(l.expires_at) - now()) / DAY); return d < 0 ? 'expired' : d <= 60 ? 'expiring' : 'active'; };
  const licenseView = (l, withClient) => ({ id: l.id, client_id: l.client_id, ...(withClient ? { client: l.client_name } : {}), installation_pk: l.installation_pk, installation_id: l.installation_id, installation_label: l.installation_label, status: l.status, state: stateOf(l),
    kind: l.kind, features: j(l.features), limits: j(l.limits), grace_days: l.grace_days, days: l.days, issued_at: l.issued_at, expires_at: l.expires_at, days_left: l.expires_at ? Math.floor((new Date(l.expires_at) - now()) / DAY) : null,
    requested_by: l.requested_by, requested_at: l.requested_at, approved_by: l.approved_by, approved_at: l.approved_at, decision_note: l.decision_note, supersedes: l.supersedes, note: l.note, params: j(l.params), kid: l.kid });
  const LSEL = 'SELECT l.*, c.name AS client_name, i.installation_id, i.label AS installation_label FROM licenses l JOIN clients c ON c.id = l.client_id JOIN installations i ON i.id = l.installation_pk';

  app.get('/api/clients', need('read'), wrap(async (req, res) => {
    const q = String(req.query.q || '').trim(); const rows = db.prepare('SELECT * FROM clients WHERE archived = ? AND (name LIKE ? OR reference LIKE ?) ORDER BY name').all(req.query.archived === '1' ? 1 : 0, '%' + q.replace(/[%_]/g, '') + '%', '%' + q.replace(/[%_]/g, '') + '%');
    ok(res, { clients: rows.map((r) => ({ ...clientRow(r), installations: db.prepare('SELECT COUNT(*) AS n FROM installations WHERE client_id = ?').get(r.id).n })) });
  }));
  app.post('/api/clients', need('issue'), wrap(async (req, res) => {
    const f = clientFields(req.body || {}); if (db.prepare('SELECT 1 FROM clients WHERE name = ?').get(f.name)) throw bad('a client with this name already exists', 409);
    const r = db.prepare('INSERT INTO clients (name, reference, notes, contacts, created_at, created_by) VALUES (?,?,?,?,?,?)').run(f.name, f.reference, f.notes, f.contacts, now().toISOString(), req.user.username);
    A(req, 'client.create', f.name, { id: Number(r.lastInsertRowid) }); ok(res, { id: Number(r.lastInsertRowid) }, 201);
  }));
  app.get('/api/clients/:id', need('read'), wrap(async (req, res) => {
    const c = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.params.id)); if (!c) throw bad('no such client', 404);
    ok(res, { client: clientRow(c), installations: db.prepare('SELECT id, label, installation_id, notes, created_at FROM installations WHERE client_id = ? ORDER BY id').all(c.id),
      licenses: db.prepare(LSEL + ' WHERE l.client_id = ? ORDER BY l.requested_at DESC').all(c.id).map((l) => licenseView(l)), emails: db.prepare('SELECT e.id, e.license_id, e.kind, e.to_addrs, e.sent_at, e.status, e.error, e.sent_by FROM emails e JOIN licenses l ON l.id = e.license_id WHERE l.client_id = ? ORDER BY e.id DESC LIMIT 50').all(c.id).map((e) => ({ ...e, to_addrs: j(e.to_addrs) })) });
  }));
  app.put('/api/clients/:id', need('issue'), wrap(async (req, res) => {
    const c = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.params.id)); if (!c) throw bad('no such client', 404); const f = clientFields(req.body || {});
    if (db.prepare('SELECT 1 FROM clients WHERE name = ? AND id <> ?').get(f.name, c.id)) throw bad('a client with this name already exists', 409);
    db.prepare('UPDATE clients SET name = ?, reference = ?, notes = ?, contacts = ? WHERE id = ?').run(f.name, f.reference, f.notes, f.contacts, c.id); A(req, 'client.update', f.name, { id: c.id }); ok(res);
  }));
  app.post('/api/clients/:id/archive', need('issue'), wrap(async (req, res) => {
    const c = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.params.id)); if (!c) throw bad('no such client', 404); const arch = req.body && req.body.archived === false ? 0 : 1;
    db.prepare('UPDATE clients SET archived = ? WHERE id = ?').run(arch, c.id); A(req, arch ? 'client.archive' : 'client.unarchive', c.name); ok(res);
  }));
  app.post('/api/clients/:id/installations', need('issue'), wrap(async (req, res) => {
    const c = db.prepare('SELECT * FROM clients WHERE id = ?').get(Number(req.params.id)); if (!c) throw bad('no such client', 404); const b = req.body || {};
    const label = String(b.label || '').trim(); if (!label || label.length > 80) throw bad('the installation needs a label (for example "Head office", up to 80 characters)');
    const iid = String(b.installation_id || '').trim().toLowerCase(); if (!lic.validInstallationId(iid)) throw bad('the installation id must be the id shown on the client\'s License page (a UUID), or *');
    if (db.prepare('SELECT 1 FROM installations WHERE client_id = ? AND installation_id = ?').get(c.id, iid)) throw bad('this client already has that installation id', 409);
    const r = db.prepare('INSERT INTO installations (client_id, label, installation_id, notes, created_at) VALUES (?,?,?,?,?)').run(c.id, label, iid, b.notes ? String(b.notes).slice(0, 500) : null, now().toISOString());
    A(req, 'installation.create', c.name, { id: Number(r.lastInsertRowid), label, installation_id: iid }); ok(res, { id: Number(r.lastInsertRowid) }, 201);
  }));

  // ---- licenses ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  const getLicense = (id) => db.prepare(LSEL + ' WHERE l.id = ?').get(String(id));

  // Sign a pending request and keep the result. Called straight away when no approval is needed, or by the approver. A failure leaves the request as it was.
  async function issueNow(id, approvedBy, req) {
    if (inflight.has(id)) throw bad('this license is being issued already', 409); inflight.add(id);
    try {
      const l = getLicense(id); if (!l) throw bad('no such license', 404); if (l.status !== 'pending') throw bad('this request is not waiting any more', 409);
      const params = j(l.params); const norm = lic.normalize(params); let out;
      try { out = await lic.issue(signer, { customer: l.client_name, iid: l.installation_id, norm, now: now() }); } catch (e) { audit.log(db, actor(req), 'license.sign_failed', l.id, { error: String(e.message).slice(0, 200) }, now()); throw bad('the license could not be signed: ' + e.message, 502); }
      const done = tx(db, () => {
        const r = db.prepare("UPDATE licenses SET status='issued', approved_by=?, approved_at=?, kind=?, features=?, limits=?, grace_days=?, days=?, issued_at=?, expires_at=?, kid=?, token=?, token_sha256=?, note=? WHERE id=? AND status='pending'")
          .run(approvedBy, now().toISOString(), norm.kind, JSON.stringify(norm.features), JSON.stringify(norm.limits), norm.grace, norm.days, out.issued_at, out.expires_at, signer.kid, out.token, out.token_sha256, norm.note, l.id);
        if (r.changes !== 1) throw bad('this request is not waiting any more', 409);
        audit.log(db, actor(req), 'license.issue', l.id, { client: l.client_name, installation_id: l.installation_id, kind: norm.kind, days: norm.days, expires_at: out.expires_at, token_sha256: out.token_sha256, kid: signer.kid, approved_by: approvedBy, requested_by: l.requested_by }, now()); return true;
      });
      return done;
    } finally { inflight.delete(id); }
  }

  app.post('/api/licenses/request', need('issue'), wrap(async (req, res) => {
    const b = req.body || {}; const inst = db.prepare('SELECT i.*, c.archived, c.name AS client_name FROM installations i JOIN clients c ON c.id = i.client_id WHERE i.id = ?').get(Number(b.installation_pk));
    if (!inst) throw bad('choose one of the client\'s installations', 404); if (inst.archived) throw bad('this client is archived');
    const norm = lic.normalize({ template: b.template, features: b.features, days: b.days, tenants: b.tenants, retention: b.retention, grace: b.grace, note: b.note });
    let sup = null; if (b.supersedes) { sup = db.prepare("SELECT id, installation_pk FROM licenses WHERE id = ? AND status = 'issued'").get(String(b.supersedes)); if (!sup || sup.installation_pk !== inst.id) throw bad('the license to renew does not belong to this installation'); }
    const pending = db.prepare("SELECT COUNT(*) AS n FROM licenses WHERE installation_pk = ? AND status = 'pending'").get(inst.id).n; if (pending) throw bad('this installation already has a request waiting', 409);
    const id = lic.newLicenseId(now()); const params = { template: b.template || 'custom', features: norm.features, days: norm.days, tenants: norm.limits.tenants === undefined ? undefined : norm.limits.tenants === null ? 'unlimited' : norm.limits.tenants, retention: norm.limits.retention_days_max === undefined ? undefined : norm.limits.retention_days_max === null ? 'unlimited' : norm.limits.retention_days_max, grace: norm.grace, note: norm.note };
    db.prepare("INSERT INTO licenses (id, client_id, installation_pk, status, params, requested_by, requested_at, supersedes) VALUES (?,?,?,'pending',?,?,?,?)").run(id, inst.client_id, inst.id, JSON.stringify(params), req.user.username, now().toISOString(), sup ? sup.id : null);
    const approval = lic.needsApproval(cfg.approval, norm, inst.installation_id); A(req, 'license.request', id, { client: inst.client_name, kind: norm.kind, days: norm.days, needs_approval: approval, supersedes: sup ? sup.id : null });
    if (approval) return ok(res, { id, status: 'pending', needs_approval: true }, 202);
    try { await issueNow(id, req.user.username, req); } catch (e) { db.prepare("UPDATE licenses SET status='cancelled', decision_note=? WHERE id=? AND status='pending'").run('not issued: ' + String(e.message).slice(0, 200), id); throw e; }
    ok(res, { id, status: 'issued', needs_approval: false }, 201);
  }));
  app.get('/api/licenses', need('read'), wrap(async (req, res) => {
    const st = ['pending', 'issued', 'rejected', 'cancelled'].includes(req.query.status) ? req.query.status : null;
    ok(res, { licenses: db.prepare(LSEL + (st ? ' WHERE l.status = ?' : '') + ' ORDER BY l.requested_at DESC LIMIT 300').all(...(st ? [st] : [])).map((l) => licenseView(l, true)) });
  }));
  app.get('/api/licenses/:id', need('read'), wrap(async (req, res) => {
    const l = getLicense(req.params.id); if (!l) throw bad('no such license', 404);
    ok(res, { license: licenseView(l, true), emails: db.prepare('SELECT id, kind, to_addrs, subject, sent_at, status, error, sent_by FROM emails WHERE license_id = ? ORDER BY id DESC').all(l.id).map((e) => ({ ...e, to_addrs: j(e.to_addrs) })) });
  }));
  app.post('/api/licenses/:id/approve', need('approve'), wrap(async (req, res) => {
    const l = getLicense(req.params.id); if (!l) throw bad('no such license', 404); if (l.status !== 'pending') throw bad('this request is not waiting any more', 409);
    if (l.requested_by === req.user.username) throw bad('a second person must approve: you made this request', 403);
    await issueNow(l.id, req.user.username, req); ok(res, { id: l.id, status: 'issued' });
  }));
  app.post('/api/licenses/:id/reject', need('approve'), wrap(async (req, res) => {
    const l = getLicense(req.params.id); if (!l || l.status !== 'pending') throw bad('this request is not waiting any more', 409); const why = String((req.body || {}).reason || '').trim().slice(0, 300); if (!why) throw bad('say why it is rejected');
    db.prepare("UPDATE licenses SET status='rejected', approved_by=?, approved_at=?, decision_note=? WHERE id=? AND status='pending'").run(req.user.username, now().toISOString(), why, l.id); A(req, 'license.reject', l.id, { reason: why }); ok(res);
  }));
  app.post('/api/licenses/:id/cancel', need('issue'), wrap(async (req, res) => {
    const l = getLicense(req.params.id); if (!l || l.status !== 'pending') throw bad('this request is not waiting any more', 409); if (l.requested_by !== req.user.username && req.user.role !== 'admin') throw bad('only the person who asked, or an admin, can cancel it', 403);
    db.prepare("UPDATE licenses SET status='cancelled', decision_note=? WHERE id=? AND status='pending'").run('cancelled by ' + req.user.username, l.id); A(req, 'license.cancel', l.id); ok(res);
  }));
  app.get('/api/licenses/:id/file', need('issue'), wrap(async (req, res) => {
    const l = getLicense(req.params.id); if (!l || l.status !== 'issued') throw bad('no issued license with this id', 404); A(req, 'license.download', l.id);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="asix-license-' + slug(l.client_name) + '-' + l.id + '.jwt"'); res.send(l.token + '\n');
  }));
  const settingsEffective = () => { const rows = Object.fromEntries(db.prepare('SELECT key, value FROM settings').all().map((r) => [r.key, r.value])); return { ...mail.DEFAULT_TEMPLATES, ...Object.fromEntries(Object.entries(rows).filter(([k]) => k in mail.DEFAULT_TEMPLATES)), remindersEnabled: rows.remindersEnabled === undefined ? !!cfg.remindersEnabled : rows.remindersEnabled === 'true' }; };
  ctx.settings = settingsEffective;

  async function sendMail(req, l, kind, to, vars, subjectTpl, bodyTpl, attach) {
    const t = now().getTime(); const times = (sendTimes.get(req.user.username) || []).filter((x) => t - x < 3600000); if (times.length >= 30) throw bad('too many e-mails in the last hour: wait a little', 429);
    const recipients = mail.cleanRecipients(to); const subject = mail.render(subjectTpl, vars), text = mail.render(bodyTpl, vars);
    let status = 'sent', error = null, mid = null;
    try { mid = (await (ctx.send || mail.send)(cfg, { to: recipients, subject, text, attachments: attach ? [{ filename: 'asix-license-' + slug(l.client_name) + '.jwt', content: l.token + '\n', contentType: 'text/plain' }] : undefined })).message_id; }
    catch (e) { status = 'failed'; error = String(e.message).slice(0, 300); if (e.invalid) { audit.log(db, actor(req), 'email.refused', l.id, { error }, now()); throw e; } }
    times.push(t); sendTimes.set(req.user.username, times);
    db.prepare('INSERT INTO emails (license_id, kind, to_addrs, subject, sent_at, message_id, status, error, sent_by) VALUES (?,?,?,?,?,?,?,?,?)').run(l.id, kind, JSON.stringify(recipients), subject, now().toISOString(), mid, status, error, req.user.username);
    A(req, 'email.' + kind + '.' + status, l.id, { to: recipients, error }); if (status === 'failed') throw bad(error, 502); return { to: recipients, message_id: mid };
  }
  const mailVars = (l, extra = {}) => ({ customer: l.client_name, kind: l.kind, expires: String(l.expires_at).slice(0, 10), installation: l.installation_id, days: Math.max(0, Math.floor((new Date(l.expires_at) - now()) / DAY)), message: '', ...extra });
  app.post('/api/licenses/:id/send', need('issue'), wrap(async (req, res) => {
    const l = getLicense(req.params.id); if (!l || l.status !== 'issued') throw bad('only an issued license can be sent', 404); const s = settingsEffective(); const msg = String((req.body || {}).message || '').slice(0, 1000);
    const r = await sendMail(req, l, 'license', (req.body || {}).to, mailVars(l, { message: msg ? msg + '\n' : '' }), s.license_subject, s.license_body, true); ok(res, r);
  }));

  // ---- renewals, dashboard, exports -------------------------------------------------------------------------------------------------------------------------------------
  const currentLicenses = () => db.prepare(LSEL + " WHERE l.status = 'issued' AND l.issued_at = (SELECT MAX(l2.issued_at) FROM licenses l2 WHERE l2.installation_pk = l.installation_pk AND l2.status = 'issued')").all();
  ctx.currentLicenses = currentLicenses; ctx.getLicense = getLicense; ctx.mailVars = mailVars;
  app.get('/api/renewals', need('read'), wrap(async (req, res) => {
    const n = Number(req.query.days === undefined ? 60 : req.query.days); if (!Number.isInteger(n) || n < 0 || n > 3650) throw bad('days must be 0 to 3650');
    ok(res, { licenses: currentLicenses().map((l) => licenseView(l, true)).filter((l) => l.days_left <= n).sort((a, b) => a.days_left - b.days_left) });
  }));
  app.get('/api/dashboard', need('read'), wrap(async (req, res) => {
    const cur = currentLicenses().map((l) => licenseView(l, true));
    ok(res, { clients: db.prepare('SELECT COUNT(*) AS n FROM clients WHERE archived = 0').get().n, installations: db.prepare('SELECT COUNT(*) AS n FROM installations').get().n, active: cur.filter((l) => l.state === 'active').length, expiring: cur.filter((l) => l.state === 'expiring').length, expired: cur.filter((l) => l.state === 'expired').length,
      pending: db.prepare("SELECT COUNT(*) AS n FROM licenses WHERE status = 'pending'").get().n, signer: { type: signer.type, kid: signer.kid } });
  }));
  app.get('/api/export.csv', need('read'), wrap(async (req, res) => {
    const cell = (v) => { const s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join(' ') : typeof v === 'object' ? JSON.stringify(v) : String(v); return /^[=+\-@]/.test(s) ? "'" + s : s; };
    const q = (v) => { const s = cell(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    const cols = ['id', 'client', 'installation_id', 'status', 'kind', 'features', 'limits', 'grace_days', 'days', 'issued_at', 'expires_at', 'requested_by', 'approved_by', 'supersedes', 'note'];
    const rows = db.prepare(LSEL + ' ORDER BY l.requested_at').all().map((l) => licenseView(l, true)); A(req, 'export');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="asix-licenses.csv"');
    res.send([cols.join(','), ...rows.map((r) => cols.map((c) => q(c === 'client' ? r.client : r[c])).join(','))].join('\n') + '\n');
  }));

  // ---- audit, signer, settings, users ------------------------------------------------------------------------------------------------------------------------------------
  app.get('/api/audit', need('approve'), wrap(async (req, res) => ok(res, { entries: audit.list(db, Number(req.query.limit) || 100) })));
  app.get('/api/audit/verify', need('approve'), wrap(async (req, res) => ok(res, audit.verify(db))));
  app.get('/api/signer', need('read'), wrap(async (req, res) => {
    const h = await signer.health(); let pem = null, line = null, problem = null; try { pem = await signer.publicKeyPem(); line = lic.vendorKeysLine(signer.kid, pem); } catch (e) { problem = e.message; }
    ok(res, { type: signer.type, kid: signer.kid, health: h, public_key: pem, vendor_keys_line: line, problem, approval: cfg.approval });
  }));
  app.get('/api/settings', need('admin'), wrap(async (req, res) => ok(res, { settings: settingsEffective(), placeholders: PLACEHOLDERS, smtp_configured: !!(cfg.smtp.host && cfg.smtp.from), reminder_days: cfg.reminderDays })));
  app.put('/api/settings', need('admin'), wrap(async (req, res) => {
    const b = req.body || {}; const keys = Object.keys(mail.DEFAULT_TEMPLATES);
    for (const k of keys) if (b[k] !== undefined) {
      const v = String(b[k]); if (!v.trim() || v.length > 4000) throw bad(k + ' must be 1 to 4000 characters');
      for (const m of v.matchAll(/\{\{(\w+)\}\}/g)) if (!PLACEHOLDERS.includes(m[1])) throw bad('unknown placeholder {{' + m[1] + '}} (allowed: ' + PLACEHOLDERS.map((p) => '{{' + p + '}}').join(' ') + ')');
      db.prepare('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(k, v);
    }
    if (b.remindersEnabled !== undefined) db.prepare('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run('remindersEnabled', b.remindersEnabled ? 'true' : 'false');
    A(req, 'settings.update', null, { keys: Object.keys(b) }); ok(res, { settings: settingsEffective() });
  }));
  app.post('/api/settings/test-email', need('admin'), wrap(async (req, res) => {
    const to = mail.cleanRecipients([(req.body || {}).to]); const l = { id: null, client_name: 'test' };
    try { await (ctx.send || mail.send)(cfg, { to, subject: 'ASIX vendor server: test message', text: 'If you can read this, e-mail from the ASIX vendor server works.\n' }); } catch (e) { A(req, 'email.test.failed', null, { to, error: String(e.message).slice(0, 200) }); throw bad(e.message, e.invalid ? 400 : 502); }
    void l; A(req, 'email.test.sent', null, { to }); ok(res);
  }));
  const userView = (u) => ({ id: u.id, username: u.username, name: u.name, email: u.email, role: u.role, active: !!u.active, locked: !!(u.locked_until && new Date(u.locked_until) > now()), created_at: u.created_at });
  app.get('/api/users', need('admin'), wrap(async (req, res) => ok(res, { users: db.prepare('SELECT * FROM users ORDER BY username').all().map(userView) })));
  const lastAdmin = (id) => db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1 AND id <> ?").get(id).n === 0;
  const userFields = (b, creating) => {
    const username = String(b.username || '').trim(); if (creating && !/^[a-z0-9._-]{3,40}$/i.test(username)) throw bad('the username is 3 to 40 letters, digits, . _ -');
    const name = String(b.name || '').trim(); if (!name || name.length > 100) throw bad('the user needs a name'); const role = String(b.role || ''); if (!['admin', 'issuer', 'approver', 'viewer'].includes(role)) throw bad('role must be admin, issuer, approver or viewer');
    const email = b.email ? String(b.email).trim().toLowerCase() : null; if (email && !mail.EMAIL_RE.test(email)) throw bad('that is not an e-mail address'); return { username, name, role, email };
  };
  app.post('/api/users', need('admin'), wrap(async (req, res) => {
    const f = userFields(req.body || {}, true); const p = auth.passwordProblem((req.body || {}).password); if (p) throw bad(p); if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(f.username)) throw bad('that username is taken', 409);
    const secret = auth.newTotpSecret(); const r = db.prepare('INSERT INTO users (username, name, email, role, password_hash, totp_secret, created_at) VALUES (?,?,?,?,?,?,?)').run(f.username, f.name, f.email, f.role, auth.hashPassword(req.body.password), secret, now().toISOString());
    A(req, 'user.create', f.username, { role: f.role }); ok(res, { id: Number(r.lastInsertRowid), totp_secret: secret, otpauth: auth.otpauthUri(f.username, secret) }, 201);
  }));
  app.put('/api/users/:id', need('admin'), wrap(async (req, res) => {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id)); if (!u) throw bad('no such user', 404); const f = userFields({ ...(req.body || {}), username: u.username }, false); const active = (req.body || {}).active === false ? 0 : 1;
    if ((u.role === 'admin' && (f.role !== 'admin' || !active)) && lastAdmin(u.id)) throw bad('this is the last active admin: make another admin first', 409);
    db.prepare('UPDATE users SET name = ?, email = ?, role = ?, active = ? WHERE id = ?').run(f.name, f.email, f.role, active, u.id); if (!active || f.role !== u.role) auth.endAllSessions(db, u.id);
    A(req, 'user.update', u.username, { role: f.role, active: !!active }); ok(res);
  }));
  app.post('/api/users/:id/reset', need('admin'), wrap(async (req, res) => {
    const u = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(req.params.id)); if (!u) throw bad('no such user', 404); const p = auth.passwordProblem((req.body || {}).password); if (p) throw bad(p);
    const secret = auth.newTotpSecret(); db.prepare('UPDATE users SET password_hash = ?, totp_secret = ?, totp_last = 0, failed = 0, locked_until = NULL WHERE id = ?').run(auth.hashPassword(req.body.password), secret, u.id); auth.endAllSessions(db, u.id);
    A(req, 'user.reset', u.username); ok(res, { totp_secret: secret, otpauth: auth.otpauthUri(u.username, secret) });
  }));

  app.use('/api', (req, res) => res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'No such call' } }));
  app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: 0 }));
  return app;
}
module.exports = { createApp, PLACEHOLDERS };
