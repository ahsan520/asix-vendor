'use strict';
// The database (SQLite through Node's built-in node:sqlite, no extra package). One file in the data directory. WAL mode, foreign keys on.
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL, email TEXT,
  role TEXT NOT NULL CHECK (role IN ('admin','issuer','approver','viewer')),
  password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, totp_last INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1, failed INTEGER NOT NULL DEFAULT 0, locked_until TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, reference TEXT, notes TEXT, contacts TEXT NOT NULL DEFAULT '[]',
  archived INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, created_by TEXT
);
CREATE TABLE IF NOT EXISTS installations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL REFERENCES clients(id), label TEXT NOT NULL, installation_id TEXT NOT NULL, notes TEXT, created_at TEXT NOT NULL,
  UNIQUE (client_id, installation_id)
);
CREATE TABLE IF NOT EXISTS licenses (
  id TEXT PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id), installation_pk INTEGER NOT NULL REFERENCES installations(id),
  status TEXT NOT NULL CHECK (status IN ('pending','issued','rejected','cancelled')),
  params TEXT NOT NULL, requested_by TEXT NOT NULL, requested_at TEXT NOT NULL, approved_by TEXT, approved_at TEXT, decision_note TEXT,
  kind TEXT, features TEXT, limits TEXT, grace_days INTEGER, days INTEGER, issued_at TEXT, expires_at TEXT, kid TEXT, token TEXT, token_sha256 TEXT, supersedes TEXT, note TEXT
);
CREATE INDEX IF NOT EXISTS licenses_client ON licenses (client_id, status);
CREATE TABLE IF NOT EXISTS emails (
  id INTEGER PRIMARY KEY AUTOINCREMENT, license_id TEXT, kind TEXT NOT NULL, to_addrs TEXT NOT NULL, subject TEXT NOT NULL, sent_at TEXT NOT NULL, message_id TEXT, status TEXT NOT NULL, error TEXT, sent_by TEXT
);
CREATE TABLE IF NOT EXISTS reminders (license_id TEXT NOT NULL, stage INTEGER NOT NULL, sent_at TEXT NOT NULL, PRIMARY KEY (license_id, stage));
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT, detail TEXT, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

function open(dataDir) {
  if (dataDir !== ':memory:') fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const file = dataDir === ':memory:' ? ':memory:' : path.join(dataDir, 'vendor.db');
  const db = new DatabaseSync(file);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
  db.exec(SCHEMA);
  if (file !== ':memory:') { try { fs.chmodSync(file, 0o600); } catch { /* best effort */ } }
  return db;
}
// Run fn inside one transaction; any throw rolls everything back.
function tx(db, fn) { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch { /* already rolled back */ } throw e; } }
module.exports = { open, tx };
