'use strict';
// E-mail: the license to the client, and renewal reminders. Plain text only, the license attached as a file. SMTP settings come from the configuration; the password from a file.
const fs = require('fs');
const nodemailer = require('nodemailer');

const EMAIL_RE = /^[^\s@<>(),;:"]+@[^\s@<>(),;:"]+\.[^\s@<>(),;:"]+$/;
const MAX_RECIPIENTS = 10;

const DEFAULT_TEMPLATES = {
  license_subject: 'Your ASIX license for {{customer}}',
  license_body: 'Hello,\n\nYour ASIX license for {{customer}} is attached ({{kind}}, valid until {{expires}}).\n\nTo install it:\n  1. Sign in to ASIX and open Settings, then License.\n  2. Under "Add a license", choose the attached file (or paste its text) and press "Store license".\n  3. Press "Activate" next to the stored license.\n\nThe license is made for installation {{installation}} and will not work on another one. If you need help, reply to this message.\n\n{{message}}\nASIX Licensing\n',
  reminder_subject: 'Your ASIX license for {{customer}} expires in {{days}} days',
  reminder_body: 'Hello,\n\nThe ASIX license for {{customer}} expires on {{expires}} ({{days}} days from now). After a grace period, search, reports and alerts stop; data collection continues and nothing is deleted.\n\nReply to this message and we will send a renewed license for installation {{installation}}.\n\nASIX Licensing\n',
};
// {{name}} is replaced by the value given; anything else stays as it is. No code is ever run from a template.
const render = (tpl, vars) => String(tpl).replace(/\{\{(\w+)\}\}/g, (m, k) => (Object.prototype.hasOwnProperty.call(vars, k) ? String(vars[k]) : m));
const cleanRecipients = (list) => {
  if (!Array.isArray(list) || !list.length) { const e = new Error('choose at least one recipient'); e.invalid = true; throw e; }
  const out = [...new Set(list.map((x) => String(x).trim().toLowerCase()))];
  if (out.length > MAX_RECIPIENTS) { const e = new Error('at most ' + MAX_RECIPIENTS + ' recipients'); e.invalid = true; throw e; }
  for (const a of out) if (!EMAIL_RE.test(a) || a.length > 200) { const e = new Error('"' + a.slice(0, 60) + '" is not an e-mail address'); e.invalid = true; throw e; }
  return out;
};

function transport(cfg) {
  const s = cfg.smtp; if (!s.host || !s.from) return null;
  const pass = s.passFile ? fs.readFileSync(s.passFile, 'utf8').trim() : undefined;
  return nodemailer.createTransport({ host: s.host, port: s.port, secure: !!s.secure, auth: s.user ? { user: s.user, pass } : undefined, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 20000 });
}
// send({ to, subject, text, attachments }) -> { message_id } or throws with a plain message.
async function send(cfg, msg) {
  const t = transport(cfg); if (!t) { const e = new Error('e-mail is not set up: add the smtp host and from address to the configuration'); e.invalid = true; throw e; }
  try { const r = await t.sendMail({ from: cfg.smtp.from, replyTo: cfg.smtp.replyTo || undefined, to: msg.to, subject: msg.subject, text: msg.text, attachments: msg.attachments }); return { message_id: r.messageId || null }; }
  catch (e) { throw new Error('the message could not be sent: ' + (e.response || e.message)); } finally { t.close(); }
}
module.exports = { DEFAULT_TEMPLATES, render, cleanRecipients, send, EMAIL_RE, MAX_RECIPIENTS };
