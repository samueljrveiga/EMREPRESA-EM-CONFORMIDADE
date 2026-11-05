'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const config = require('../config');

if (config.dbPath !== ':memory:') fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
const db = new DatabaseSync(config.dbPath);
db.exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;`);

db.exec(`
CREATE TABLE IF NOT EXISTS companies (
  id TEXT PRIMARY KEY,
  name_enc TEXT NOT NULL,
  link_token_enc TEXT NOT NULL,
  link_token_idx TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('admin','rh','gerente')),
  company_id TEXT REFERENCES companies(id),
  email_enc TEXT NOT NULL,
  email_idx TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 1,
  totp_secret_enc TEXT,
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  totp_last_step INTEGER NOT NULL DEFAULT 0,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  CHECK ((role = 'admin') = (company_id IS NULL))
);
CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_hash TEXT NOT NULL,
  prev_refresh_hash TEXT,
  prev_valid_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS courses (
  id TEXT PRIMARY KEY,
  data_enc TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS enrollments (
  id TEXT PRIMARY KEY,
  company_id TEXT NOT NULL REFERENCES companies(id),
  course_id TEXT NOT NULL REFERENCES courses(id),
  employee_name_enc TEXT NOT NULL,
  name_idx TEXT NOT NULL,
  completed_lessons TEXT NOT NULL DEFAULT '[]',
  lesson_starts TEXT NOT NULL DEFAULT '{}',
  quiz_passed INTEGER NOT NULL DEFAULT 0,
  quiz_score INTEGER,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  cert_code TEXT UNIQUE,
  UNIQUE (company_id, course_id, name_idx)
);
CREATE INDEX IF NOT EXISTS idx_enrollments_company ON enrollments(company_id);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value_enc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  at TEXT NOT NULL,
  type TEXT NOT NULL,
  company_id TEXT,
  detail_enc TEXT NOT NULL
);
`);

const prepared = new Map();
function stmt(sql) {
  if (!prepared.has(sql)) prepared.set(sql, db.prepare(sql));
  return prepared.get(sql);
}

function tx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try { const result = fn(); db.exec('COMMIT'); return result; }
  catch (err) { db.exec('ROLLBACK'); throw err; }
}

module.exports = {
  raw: db,
  tx,
  get: (sql, ...params) => stmt(sql).get(...params),
  all: (sql, ...params) => stmt(sql).all(...params),
  run: (sql, ...params) => stmt(sql).run(...params)
};
