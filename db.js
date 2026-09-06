// db.js — persistent storage using Node's built-in SQLite (node:sqlite).
// Requires Node 22.5+. No external dependency needed.
//
// Three tables:
//   users                - real, verified accounts only
//   pending_verifications - draft signups waiting on a 6-digit code
//   sessions             - bearer tokens issued after a successful login/verify

import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = path.join(__dirname, 'savesan.db');

export const db = new DatabaseSync(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    dob TEXT NOT NULL,
    phone TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS pending_verifications (
    email TEXT PRIMARY KEY,
    draft_json TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_sent_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS admin_sessions (
    token TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);

// Keep databases created before the admin area compatible.
const userColumns = db.prepare("PRAGMA table_info(users)").all();
if (!userColumns.some(column => column.name === 'is_disabled')) {
  db.exec('ALTER TABLE users ADD COLUMN is_disabled INTEGER NOT NULL DEFAULT 0');
}
