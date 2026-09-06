// lib/tokens.js — opaque bearer tokens. Simpler than JWTs for a small app:
// the token is just a random string looked up against the `sessions` table,
// so revoking a session is a single DELETE rather than needing a blocklist.

import { randomBytes } from 'node:crypto';

export function generateSessionToken(){
  return randomBytes(32).toString('hex');
}

export function generateVerificationCode(){
  // 6 digits, zero-padded, using crypto's RNG rather than Math.random().
  const n = randomBytes(4).readUInt32BE(0) % 1000000;
  return String(n).padStart(6, '0');
}
