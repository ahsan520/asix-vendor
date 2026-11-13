// The ASIX vendor pages. Plain JavaScript, no build step, nothing is ever set as HTML: every value from the server is drawn as text.
const root = document.getElementById('app');
const S = { me: null, csrf: null, route: '', timer: null };
const FEATURES = { residential: ['search', 'detections', 'alerts', 'cases', 'actions', 'content-packs', 'dashboards', 'notifications', 'threat-intel'], enterprise: ['endpoints', 'xdr', 'soar', 'posture', 'compliance', 'ai', 'multi-tenant'] };

function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) { if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else if (k.startsWith('on')) n.addEventListener(k.slice(2), v); else if (v !== false && v !== null && v !== undefined) n[k] = v; }
  for (const c of kids.flat(Infinity)) if (c !== null && c !== undefined && c !== false && c !== '') n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
}
const T = (tag, cls, text) => el(tag, { class: cls, text });
const pill = (t, cls) => T('span', 'pill ' + (cls || ''), t);
const date = (v) => (v ? String(v).slice(0, 10) : '-');
const STATE = { active: ['Active', 'ok'], expiring: ['Expiring', 'warn'], expired: ['Expired', 'bad'], pending: ['Waiting for approval', 'warn'], issued: ['Issued', 'ok'], rejected: ['Rejected', 'bad'], cancelled: ['Cancelled', ''] };
const statePill = (s) => pill((STATE[s] || [s, ''])[0], (STATE[s] || [s, ''])[1]);

async function api(path, opts = {}) {
  const r = await fetch('/api' + path, { method: opts.method || 'GET', headers: { ...(opts.body ? { 'content-type': 'application/json' } : {}), ...(S.csrf ? { 'x-csrf-token': S.csrf } : {}) }, body: opts.body ? JSON.stringify(opts.body) : undefined, credentials: 'same-origin' });
  if (opts.raw) return r;
  let j = null; try { j = await r.json(); } catch { /* not JSON */ }
  if (r.status === 401 && path !== '/login') { S.me = null; S.csrf = null; render(); throw new Error('Sign in again'); }
  if (!r.ok || !j || j.success === false) throw new Error((j && j.error && j.error.message) || 'The request failed (' + r.status + ')');
  return j;
}
const can = (what) => !!S.me && { read: 1, issue: ['issuer', 'admin'].includes(S.me.role), approve: ['approver', 'admin'].includes(S.me.role), admin: S.me.role === 'admin' }[what];
const msg = (box, text, cls) => box.replaceChildren(text ? T('div', cls || 'err', text) : '');
// Run an action; show its error (or success text) in `box`.
async function act(box, fn, okText) { msg(box, ''); try { const r = await fn(); if (okText) msg(box, okText, 'okmsg'); return r; } catch (e) { msg(box, e.message); return undefined; } }
// Two-step confirmation drawn in the page (no browser dialogs).
function confirmBtn(label, what, go, cls) {
  const b = el('button', { class: cls || '', text: label }); const wrap = el('span', {}, b);
  b.addEventListener('click', () => { wrap.replaceChildren(T('span', 'mute', what + ' '), el('button', { class: 'pri', text: 'Confirm', onclick: go }), el('button', { text: 'Cancel', onclick: () => wrap.replaceChildren(b) })); });
  return wrap;
}
const table = (heads, rows, onRow) => el('table', {}, el('thead', {}, el('tr', {}, heads.map((h) => T('th', '', h)))), el('tbody', {}, rows.map((r) => el('tr', { class: onRow ? 'click' : '', onclick: onRow ? () => onRow(r) : null }, r.cells.map((c) => el('td', {}, c))))));

// ---- sign-in --------------------------------------------------------------------------------------------------------------------------------------------------------------------------
function loginPage() {
  const err = T('div', '', ''); const u = el('input', { autocomplete: 'username' }), p = el('input', { type: 'password', autocomplete: 'current-password' }), c = el('input', { inputMode: 'numeric', maxLength: 6, autocomplete: 'one-time-code' });
  const go = async () => { const r = await act(err, () => api('/login', { method: 'POST', body: { username: u.value, password: p.value, code: c.value } })); if (r) { S.me = r.user; S.csrf = r.csrf; location.hash = '#/dashboard'; render(); } };
  c.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  return el('div', { class: 'card login' }, T('h2', '', 'ASIX Vendor'), T('p', 'desc', 'Sign in with your password and the code from your authenticator app.'), T('label', '', 'Username'), u, T('label', '', 'Password'), p, T('label', '', 'Code (6 digits)'), c, el('div', { style: 'margin-top:12px' }, el('button', { class: 'pri', text: 'Sign in', onclick: go })), err);
}

// ---- pages ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
async function dashboard() {
  const d = await api('/dashboard'); const ren = await api('/renewals?days=60');
  return [T('h2', '', 'Dashboard'), T('p', 'desc', 'Where licensing stands today.'),
    el('div', { class: 'grid' }, ...[['Clients', d.clients], ['Active licenses', d.active], ['Expiring in 60 days', d.expiring], ['Expired', d.expired], ['Waiting for approval', d.pending]].map(([k, v]) => el('div', { class: 'card' }, T('h3', '', k), T('div', 'big', String(v))))),
    el('div', { class: 'card' }, T('h3', '', 'Needs a renewal (60 days)'), ren.licenses.length ? licenseTable(ren.licenses) : T('div', 'mute', 'Nothing expires in the next 60 days.')),
    el('div', { class: 'card' }, T('h3', '', 'Signing key'), T('div', '', d.signer.type + ' (key id ' + d.signer.kid + ')'))];
}
const licenseTable = (ls) => table(['Client', 'Installation', 'Kind', 'Expires', 'Left', 'State', 'Id'], ls.map((l) => ({ id: l.id, client_id: l.client_id, cells: [l.client || '', l.installation_label || '', l.kind || '-', date(l.expires_at), l.days_left === null ? '-' : l.days_left + ' d', statePill(l.state), l.id] })), (r) => { location.hash = '#/licenses/' + r.id; });

async function clientsPage() {
  const q = el('input', { placeholder: 'Search clients' }); const list = el('div', {}); const box = T('div', '', '');
  const load = async () => { const r = await api('/clients?q=' + encodeURIComponent(q.value)); list.replaceChildren(r.clients.length ? table(['Client', 'Reference', 'Contacts', 'Installations'], r.clients.map((c) => ({ id: c.id, cells: [c.name, c.reference || '', String(c.contacts.length), String(c.installations)] })), (r2) => { location.hash = '#/clients/' + r2.id; }) : T('div', 'mute', 'No clients yet.')); };
  q.addEventListener('input', load); await load();
  const nm = el('input', { placeholder: 'Client name' }), ref = el('input', { placeholder: 'Contract or invoice reference' });
  const add = can('issue') ? el('div', { class: 'card' }, T('h3', '', 'New client'), el('div', { class: 'row' }, nm, ref, el('button', { class: 'pri', text: 'Create client', onclick: async () => { const r = await act(box, () => api('/clients', { method: 'POST', body: { name: nm.value, reference: ref.value } })); if (r) location.hash = '#/clients/' + r.id; } })), box) : '';
  return [T('h2', '', 'Clients'), T('p', 'desc', 'Everyone you issue licenses to.'), add, el('div', { class: 'card' }, q, list)];
}

async function clientPage(id) {
  const d = await api('/clients/' + id); const c = d.client; const box = T('div', '', ''); const rerender = () => render();
  const contactRows = c.contacts.map((x) => ({ ...x }));
  const contactsBox = el('div', {});
  const drawContacts = () => contactsBox.replaceChildren(...contactRows.map((x, i) => el('div', { class: 'row', style: 'margin-bottom:6px' }, el('input', { value: x.name, placeholder: 'Name', oninput: (e) => { x.name = e.target.value; } }), el('input', { value: x.email, placeholder: 'E-mail', oninput: (e) => { x.email = e.target.value; } }),
    el('label', { style: 'margin:0' }, el('input', { type: 'checkbox', checked: x.license, onchange: (e) => { x.license = e.target.checked; } }), ' gets licenses'), el('label', { style: 'margin:0' }, el('input', { type: 'checkbox', checked: x.renewals, onchange: (e) => { x.renewals = e.target.checked; } }), ' renewal reminders'),
    el('button', { text: 'Remove', onclick: () => { contactRows.splice(i, 1); drawContacts(); } }))));
  drawContacts();
  const name = el('input', { value: c.name }), ref = el('input', { value: c.reference || '' }), notes = el('textarea', { rows: 2, value: c.notes || '' });
  const edit = el('div', { class: 'card' }, T('h3', '', 'Client'), T('label', '', 'Name'), name, T('label', '', 'Reference'), ref, T('label', '', 'Notes'), notes, T('label', '', 'Contacts'), contactsBox,
    can('issue') ? el('div', { style: 'margin-top:8px' }, el('button', { text: 'Add contact', onclick: () => { contactRows.push({ name: '', email: '', license: true, renewals: true }); drawContacts(); } }),
      el('button', { class: 'pri', text: 'Save', onclick: async () => { const r = await act(box, () => api('/clients/' + id, { method: 'PUT', body: { name: name.value, reference: ref.value, notes: notes.value, contacts: contactRows } }), 'Saved.'); if (r) rerender(); } }),
      confirmBtn(c.archived ? 'Unarchive' : 'Archive', c.archived ? 'Unarchive this client?' : 'Archive this client?', async () => { const r = await act(box, () => api('/clients/' + id + '/archive', { method: 'POST', body: { archived: !c.archived } })); if (r) rerender(); })) : '', box);
  const ibox = T('div', ''); const lab = el('input', { placeholder: 'Label, e.g. Head office' }), iid = el('input', { placeholder: 'Installation id from their License page', size: 42 });
  const insts = el('div', { class: 'card' }, T('h3', '', 'Installations'), d.installations.length ? table(['Label', 'Installation id', 'Added'], d.installations.map((i) => ({ cells: [i.label, el('code', { text: i.installation_id }), date(i.created_at)] }))) : T('div', 'mute', 'No installation yet. Ask the client for the id shown on Settings, License.'),
    can('issue') ? el('div', { class: 'row', style: 'margin-top:10px' }, lab, iid, el('button', { class: 'pri', text: 'Add installation', onclick: async () => { const r = await act(ibox, () => api('/clients/' + id + '/installations', { method: 'POST', body: { label: lab.value, installation_id: iid.value } })); if (r) rerender(); } })) : '', ibox);
  return [el('a', { href: '#/clients', text: '< Clients' }), T('h2', '', c.name), c.archived ? pill('Archived', 'warn') : '', edit, insts, can('issue') && d.installations.length && !c.archived ? requestForm(d) : '',
    el('div', { class: 'card' }, T('h3', '', 'Licenses'), d.licenses.length ? licenseTable(d.licenses.map((l) => ({ ...l, client: c.name }))) : T('div', 'mute', 'No license issued yet.')),
    el('div', { class: 'card' }, T('h3', '', 'E-mails sent'), d.emails.length ? table(['When', 'Kind', 'To', 'Status', 'By'], d.emails.map((e) => ({ cells: [date(e.sent_at), e.kind, e.to_addrs.join(', '), e.status === 'sent' ? pill('sent', 'ok') : pill('failed', 'bad'), e.sent_by || ''] }))) : T('div', 'mute', 'Nothing sent yet.'))];
}

function requestForm(d, renew) {
  const box = T('div', ''); const inst = el('select', {}, d.installations.map((i) => el('option', { value: i.id, text: i.label + ' (' + i.installation_id.slice(0, 8) + (i.installation_id === '*' ? '' : '...') + ')', selected: renew && renew.installation_pk === i.id })));
  const tpl = el('select', {}, [['residential', 'Residential (1 year)'], ['enterprise', 'Enterprise (1 year)'], ['trial', 'Trial (30 days, no grace)'], ['custom', 'Custom features']].map(([v, t]) => el('option', { value: v, text: t })));
  const days = el('input', { type: 'number', min: 1, max: 3650, placeholder: 'template default', value: renew ? renew.days : '' }), tenants = el('input', { placeholder: 'e.g. 5 or unlimited', size: 12, value: renew && renew.params && renew.params.tenants !== undefined ? renew.params.tenants : '' }), retention = el('input', { placeholder: 'days or unlimited', size: 12, value: renew && renew.params && renew.params.retention !== undefined ? renew.params.retention : '' });
  const grace = el('input', { type: 'number', min: 0, max: 90, placeholder: 'default 30', value: renew && renew.grace_days !== null && renew.grace_days !== undefined ? renew.grace_days : '' }), note = el('input', { placeholder: 'Invoice or contract number', size: 30 });
  const checks = {}; const chips = el('div', { class: 'chips' }, [...FEATURES.residential, ...FEATURES.enterprise].map((f) => { const cb = el('input', { type: 'checkbox', checked: !!(renew && renew.features && renew.features.includes(f)) }); checks[f] = cb; return el('label', {}, cb, f); }));
  if (renew) tpl.value = 'custom'; const chipWrap = el('div', { style: renew ? '' : 'display:none' }, T('label', '', 'Features'), chips);
  tpl.addEventListener('change', () => { chipWrap.style.display = tpl.value === 'custom' ? '' : 'none'; });
  const go = async () => {
    const body = { installation_pk: Number(inst.value), template: tpl.value, days: days.value, tenants: tenants.value, retention: retention.value, grace: grace.value, note: note.value, ...(renew ? { supersedes: renew.id } : {}) };
    if (tpl.value === 'custom') body.features = Object.keys(checks).filter((f) => checks[f].checked);
    const r = await act(box, () => api('/licenses/request', { method: 'POST', body })); if (r) location.hash = '#/licenses/' + r.id;
  };
  return el('div', { class: 'card' }, T('h3', '', renew ? 'Renew this license' : 'New license'), el('div', { class: 'row' }, el('div', {}, T('label', '', 'Installation'), inst), el('div', {}, T('label', '', 'Type'), tpl), el('div', {}, T('label', '', 'Days'), days), el('div', {}, T('label', '', 'Tenants'), tenants), el('div', {}, T('label', '', 'Retention days'), retention), el('div', {}, T('label', '', 'Grace days'), grace)),
    chipWrap, T('label', '', 'Note'), note, el('div', { style: 'margin-top:10px' }, el('button', { class: 'pri', text: 'Generate license', onclick: go })), T('div', 'mute', 'Enterprise licenses, terms over 400 days and any-installation licenses may need a second person to approve first.'), box);
}

async function licensePage(id) {
  const d = await api('/licenses/' + id); const l = d.license; const box = T('div', ''); const rerender = () => render();
  const feats = el('div', { class: 'chips' }, (l.features || []).map((f) => pill(f, 'ok')));
  const info = el('div', { class: 'card' }, T('h3', '', 'License ' + l.id), el('div', {}, statePill(l.state), ' ', l.kind ? pill(l.kind, '') : ''), T('p', '', 'Client: ' + l.client + ' - installation ' + (l.installation_label || '') + ' (' + l.installation_id + ')'),
    l.status === 'issued' ? T('p', '', 'Issued ' + date(l.issued_at) + ', expires ' + date(l.expires_at) + (l.days_left !== null ? ' (' + l.days_left + ' days left)' : '') + ', grace ' + (l.grace_days === null ? 'default 30' : l.grace_days) + ' days, signed by key ' + l.kid) : '',
    l.status === 'issued' ? T('p', 'mute', 'Limits: ' + JSON.stringify(l.limits)) : '', feats, T('p', 'mute', 'Requested by ' + l.requested_by + (l.approved_by ? ', approved by ' + l.approved_by : '') + (l.decision_note ? ' - ' + l.decision_note : '') + (l.note ? ' - note: ' + l.note : '')));
  const parts = [el('a', { href: '#/clients/' + l.client_id, text: '< ' + l.client }), info];
  if (l.status === 'pending') {
    parts.push(el('div', { class: 'card' }, T('h3', '', 'Waiting for a second person'), T('p', 'mute', 'This request needs approval by someone other than ' + l.requested_by + '.'), T('div', '', 'Asked for: ' + JSON.stringify(l.params)),
      el('div', { style: 'margin-top:8px' }, can('approve') && S.me.username !== l.requested_by ? el('span', {}, confirmBtn('Approve and issue', 'Sign this license now?', async () => { const r = await act(box, () => api('/licenses/' + id + '/approve', { method: 'POST', body: {} })); if (r) rerender(); }, 'pri'),
        (() => { const why = el('input', { placeholder: 'Reason', size: 30 }); return el('span', {}, why, el('button', { class: 'bad', text: 'Reject', onclick: async () => { const r = await act(box, () => api('/licenses/' + id + '/reject', { method: 'POST', body: { reason: why.value } })); if (r) rerender(); } })); })()) : '',
        can('issue') ? confirmBtn('Cancel request', 'Cancel this request?', async () => { const r = await act(box, () => api('/licenses/' + id + '/cancel', { method: 'POST', body: {} })); if (r) rerender(); }) : ''), box));
  }
  if (l.status === 'issued' && can('issue')) {
    const bx = T('div', ''); const to = el('input', { size: 44, placeholder: 'client@example.com, other@example.com' }); const m = el('textarea', { rows: 2, placeholder: 'Optional message to add to the e-mail' });
    const client = await api('/clients/' + l.client_id); to.value = client.client.contacts.filter((c) => c.license).map((c) => c.email).join(', ');
    parts.push(el('div', { class: 'card' }, T('h3', '', 'Send to the client'), T('label', '', 'To'), to, T('label', '', 'Message'), m,
      el('div', { style: 'margin-top:8px' }, confirmBtn(d.emails.some((e) => e.kind === 'license' && e.status === 'sent') ? 'Resend by e-mail' : 'Send by e-mail', 'Send the license to these addresses?', async () => { const r = await act(bx, () => api('/licenses/' + id + '/send', { method: 'POST', body: { to: to.value.split(',').map((x) => x.trim()).filter(Boolean), message: m.value } }), 'Sent.'); if (r) setTimeout(rerender, 800); }, 'pri'),
        el('button', { text: 'Download the file', onclick: async () => { const r = await api('/licenses/' + id + '/file', { raw: true }); if (!r.ok) { msg(bx, 'Could not download'); return; } const b = await r.blob(); const a = el('a', { href: URL.createObjectURL(b), download: 'asix-license-' + id + '.jwt' }); a.click(); } })), bx));
    parts.push(requestForm({ installations: client.installations }, { ...l, id: l.id }));
  }
  if (d.emails.length) parts.push(el('div', { class: 'card' }, T('h3', '', 'E-mails for this license'), table(['When', 'Kind', 'To', 'Status', 'By'], d.emails.map((e) => ({ cells: [date(e.sent_at), e.kind, e.to_addrs.join(', '), e.status === 'sent' ? pill('sent', 'ok') : pill('failed', 'bad'), e.sent_by || ''] })))));
  return parts;
}

async function licensesPage() { const r = await api('/licenses'); return [T('h2', '', 'Licenses'), T('p', 'desc', 'Everything issued and everything waiting.'), el('a', { href: '/api/export.csv', text: 'Export CSV (no license text)' }), el('div', { class: 'card' }, r.licenses.length ? licenseTable(r.licenses) : T('div', 'mute', 'Nothing yet.'))]; }
async function renewalsPage() {
  const sel = el('select', {}, [30, 60, 90, 180].map((n) => el('option', { value: n, text: n + ' days', selected: n === 60 }))); const list = el('div', {});
  const load = async () => { const r = await api('/renewals?days=' + sel.value); list.replaceChildren(r.licenses.length ? licenseTable(r.licenses) : T('div', 'mute', 'Nothing expires in that time.')); }; sel.addEventListener('change', load); await load();
  return [T('h2', '', 'Renewals'), T('p', 'desc', 'Licenses expiring soon or already expired. Open one to renew it.'), el('div', { class: 'card' }, T('label', '', 'Expiring within'), sel, list)];
}
async function approvalsPage() { const r = await api('/licenses?status=pending'); return [T('h2', '', 'Approvals'), T('p', 'desc', 'Requests waiting for a second person.'), el('div', { class: 'card' }, r.licenses.length ? licenseTable(r.licenses) : T('div', 'mute', 'Nothing is waiting.'))]; }
async function auditPage() {
  const r = await api('/audit?limit=200'); const v = await api('/audit/verify');
  return [T('h2', '', 'Audit log'), T('p', 'desc', 'Every sign-in, change, signing and e-mail. Each row is chained to the one before it.'), el('div', { class: 'card' }, v.ok ? pill('Chain intact: ' + v.count + ' rows', 'ok') : [pill('PROBLEMS', 'bad'), ...v.problems.map((p) => T('div', 'err', p))]),
    el('div', { class: 'card' }, table(['When', 'Who', 'What', 'Target', 'Detail'], r.entries.map((e) => ({ cells: [String(e.at).replace('T', ' ').slice(0, 19), e.actor, e.action, e.target || '', e.detail ? JSON.stringify(e.detail) : ''] }))))];
}
async function usersPage() {
  const r = await api('/users'); const box = T('div', ''); const out = T('div', '');
  const f = { username: el('input', { placeholder: 'username' }), name: el('input', { placeholder: 'Full name' }), email: el('input', { placeholder: 'E-mail' }), role: el('select', {}, ['issuer', 'approver', 'viewer', 'admin'].map((x) => el('option', { value: x, text: x }))), password: el('input', { type: 'password', placeholder: 'Password (12+ characters)', autocomplete: 'new-password' }) };
  const secret = (res) => { out.replaceChildren(el('div', { class: 'card' }, T('h3', '', 'Authenticator setup (shown once)'), el('pre', { text: 'secret: ' + res.totp_secret + '\nlink:   ' + res.otpauth }))); };
  return [T('h2', '', 'Users'), T('p', 'desc', 'Staff who can sign in. Everyone needs an authenticator app.'), out,
    el('div', { class: 'card' }, table(['User', 'Name', 'Role', 'State', ''], r.users.map((u) => ({ cells: [u.username, u.name, u.role, u.active ? (u.locked ? pill('locked', 'warn') : pill('active', 'ok')) : pill('disabled', 'bad'),
      el('span', {}, confirmBtn(u.active ? 'Disable' : 'Enable', (u.active ? 'Disable' : 'Enable') + ' ' + u.username + '?', async () => { const x = await act(box, () => api('/users/' + u.id, { method: 'PUT', body: { name: u.name, email: u.email, role: u.role, active: !u.active } })); if (x) render(); }),
        (() => { const pw = el('input', { type: 'password', placeholder: 'New password', size: 14, autocomplete: 'new-password' }); return el('span', {}, pw, el('button', { text: 'Reset password and code', onclick: async () => { const x = await act(box, () => api('/users/' + u.id + '/reset', { method: 'POST', body: { password: pw.value } })); if (x) secret(x); } })); })())] }))), box),
    el('div', { class: 'card' }, T('h3', '', 'New user'), el('div', { class: 'row' }, ...Object.values(f), el('button', { class: 'pri', text: 'Create', onclick: async () => { const x = await act(box, () => api('/users', { method: 'POST', body: Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.value])) })); if (x) { secret(x); } } })))];
}
async function settingsPage() {
  const [r, sg] = await Promise.all([api('/settings'), api('/signer')]); const s = r.settings; const box = T('div', ''); const tbox = T('div', '');
  const f = { license_subject: el('input', { value: s.license_subject, size: 70 }), license_body: el('textarea', { rows: 10, value: s.license_body }), reminder_subject: el('input', { value: s.reminder_subject, size: 70 }), reminder_body: el('textarea', { rows: 7, value: s.reminder_body }) };
  const rem = el('input', { type: 'checkbox', checked: s.remindersEnabled }); const to = el('input', { placeholder: 'your address', size: 30 });
  return [T('h2', '', 'Settings'), T('p', 'desc', 'The signing key, the e-mail templates and reminders.'),
    el('div', { class: 'card' }, T('h3', '', 'Signing key'), T('div', '', sg.type + ' - key id ' + sg.kid + ' - ' + (sg.health.ok ? 'working' : 'NOT working') + ': ' + sg.health.detail), sg.problem ? T('div', 'err', sg.problem) : '', sg.vendor_keys_line ? [T('p', 'mute', 'Paste this line into KEYS in src/licensing/vendor-keys.js of the ASIX product, then ship a build:'), el('pre', { text: sg.vendor_keys_line })] : '', T('p', 'mute', 'Approval policy: ' + sg.approval)),
    el('div', { class: 'card' }, T('h3', '', 'E-mail'), T('div', 'mute', r.smtp_configured ? 'SMTP is set up.' : 'SMTP is NOT set up: add the smtp host and from address to the server configuration.'), el('div', { class: 'row', style: 'margin-top:8px' }, to, el('button', { text: 'Send a test message', onclick: () => act(tbox, () => api('/settings/test-email', { method: 'POST', body: { to: to.value } }), 'Test message sent.') })), tbox),
    el('div', { class: 'card' }, T('h3', '', 'Templates'), T('p', 'mute', 'You can use ' + r.placeholders.map((p) => '{{' + p + '}}').join(' ') + '.'), T('label', '', 'License e-mail subject'), f.license_subject, T('label', '', 'License e-mail body'), f.license_body, T('label', '', 'Reminder subject'), f.reminder_subject, T('label', '', 'Reminder body'), f.reminder_body,
      el('label', { style: 'margin-top:10px' }, rem, ' Send renewal reminders to each client\'s renewal contacts (' + r.reminder_days.join(', ') + ' days before expiry)'), el('div', { style: 'margin-top:10px' }, el('button', { class: 'pri', text: 'Save', onclick: () => act(box, () => api('/settings', { method: 'PUT', body: { ...Object.fromEntries(Object.entries(f).map(([k, v]) => [k, v.value])), remindersEnabled: rem.checked } }), 'Saved.') })), box)];
}

// ---- the frame -----------------------------------------------------------------------------------------------------------------------------------------------------------------------
const NAV = [['dashboard', 'Dashboard'], ['clients', 'Clients'], ['licenses', 'Licenses'], ['renewals', 'Renewals'], ['approvals', 'Approvals', 'approve'], ['audit', 'Audit', 'approve'], ['users', 'Users', 'admin'], ['settings', 'Settings', 'admin']];
async function render() {
  clearTimeout(S.timer);
  if (!S.me) { try { const r = await api('/me'); S.me = r.user; S.csrf = r.csrf; } catch { root.replaceChildren(loginPage()); return; } }
  const [, page, id] = (location.hash || '#/dashboard').split('/'); const cur = page || 'dashboard';
  const main = el('main', {}, T('div', 'mute', 'Loading...'));
  root.replaceChildren(el('header', {}, T('b', '', 'ASIX Vendor'), el('nav', {}, NAV.filter((n) => !n[2] || can(n[2])).map(([k, t]) => el('a', { class: cur === k ? 'on' : '', href: '#/' + k, text: t }))), el('div', { class: 'who' }, T('span', 'mute', S.me.name + ' (' + S.me.role + ') '), el('a', { text: 'Sign out', onclick: async () => { try { await api('/logout', { method: 'POST', body: {} }); } catch { /* already out */ } S.me = null; S.csrf = null; render(); } }))), main);
  try {
    const pages = { dashboard, clients: clientsPage, licenses: licensesPage, renewals: renewalsPage, approvals: approvalsPage, audit: auditPage, users: usersPage, settings: settingsPage };
    const content = cur === 'clients' && id ? await clientPage(id) : cur === 'licenses' && id ? await licensePage(id) : await (pages[cur] || dashboard)();
    main.replaceChildren(...[content].flat(Infinity).filter(Boolean));
  } catch (e) { main.replaceChildren(T('div', 'err', e.message)); }
}
window.addEventListener('hashchange', render);
render();
