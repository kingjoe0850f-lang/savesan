// Persistent PostgreSQL storage for Render. DATABASE_URL is supplied by the
// Render Postgres service and never exposed to the browser.
import pg from 'pg';

const { Pool } = pg;
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required. Connect a Render Postgres database before starting SaveSan.');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function toPostgresPlaceholders(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

export const db = {
  prepare(sql) {
    const text = toPostgresPlaceholders(sql);
    return {
      async get(...params) {
        const result = await pool.query(text, params);
        return result.rows[0];
      },
      async all(...params) {
        const result = await pool.query(text, params);
        return result.rows;
      },
      async run(...params) {
        return pool.query(text, params);
      }
    };
  }
};

await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    dob TEXT NOT NULL,
    phone TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    is_disabled BOOLEAN NOT NULL DEFAULT FALSE
  );

  CREATE TABLE IF NOT EXISTS pending_verifications (
    email TEXT PRIMARY KEY,
    draft_json TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_sent_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS admin_sessions (
    token TEXT PRIMARY KEY,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS user_data (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data_json TEXT NOT NULL,
    updated_at BIGINT NOT NULL
  );
`);
