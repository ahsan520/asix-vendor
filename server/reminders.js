'use strict';
// Renewal reminders: when switched on (Settings), each client's renewal contacts get one e-mail at each reminder stage (default 60, 30 and 7 days before the license expires), once per license
// and stage. A failed send is tried again on the next hourly check; a client with no renewal contact is noted in the audit log, not retried every hour.
const audit = require('./audit');
const mail = require('./mail');
const DAY = 86400000;

async function runReminders(ctx, nowDate = new Date()) {
  const { cfg, db } = ctx; const s = ctx.settings(); const out = { sent: 0, failed: 0, skipped: 0 };
  if (!s.remindersEnabled) return out;
  const stages = [...cfg.reminderDays].sort((a, b) => a - b);
  for (const l of ctx.currentLicenses()) {
    const days = Math.floor((new Date(l.expires_at) - nowDate) / DAY); if (days < 0) continue;
    const stage = stages.find((x) => x >= days); if (stage === undefined) continue;
    if (db.prepare('SELECT 1 FROM reminders WHERE license_id = ? AND stage = ?').get(l.id, stage)) continue;
    const contacts = JSON.parse(db.prepare('SELECT contacts FROM clients WHERE id = ?').get(l.client_id).contacts || '[]').filter((c) => c.renewals);
    if (!contacts.length) { db.prepare('INSERT INTO reminders (license_id, stage, sent_at) VALUES (?,?,?)').run(l.id, stage, nowDate.toISOString()); audit.log(db, 'system', 'reminder.no_recipients', l.id, { stage, client: l.client_name }, nowDate); out.skipped += 1; continue; }
    const vars = ctx.mailVars(l, {}); const to = contacts.map((c) => c.email); const subject = mail.render(s.reminder_subject, vars), text = mail.render(s.reminder_body, vars);
    try {
      const r = await (ctx.send || mail.send)(cfg, { to, subject, text });
      db.prepare('INSERT INTO emails (license_id, kind, to_addrs, subject, sent_at, message_id, status, error, sent_by) VALUES (?,?,?,?,?,?,?,?,?)').run(l.id, 'reminder', JSON.stringify(to), subject, nowDate.toISOString(), r.message_id, 'sent', null, 'system');
      db.prepare('INSERT INTO reminders (license_id, stage, sent_at) VALUES (?,?,?)').run(l.id, stage, nowDate.toISOString()); audit.log(db, 'system', 'reminder.sent', l.id, { stage, to }, nowDate); out.sent += 1;
    } catch (e) {
      db.prepare('INSERT INTO emails (license_id, kind, to_addrs, subject, sent_at, message_id, status, error, sent_by) VALUES (?,?,?,?,?,?,?,?,?)').run(l.id, 'reminder', JSON.stringify(to), subject, nowDate.toISOString(), null, 'failed', String(e.message).slice(0, 300), 'system');
      audit.log(db, 'system', 'reminder.failed', l.id, { stage, error: String(e.message).slice(0, 200) }, nowDate); out.failed += 1;
    }
  }
  return out;
}
function start(ctx) { const t = setInterval(() => runReminders(ctx, ctx.now ? ctx.now() : new Date()).catch((e) => console.error('reminders failed:', e.message)), 3600000); t.unref(); return t; }
module.exports = { runReminders, start };
