// lib/password.js — salted scrypt hashing via Node's built-in crypto module.
// This is a real KDF (the same family bcrypt/argon2 belong to), not a toy —
// suitable to actually use, not just to demonstrate the idea.

import { scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';

const KEY_LEN = 64;

export function hashPassword(password){
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, KEY_LEN).toString('hex');
  return `${salt}:${hash}`;
}

export function verifyPassword(password, stored){
  const [salt, hashHex] = stored.split(':');
  const hash = scryptSync(password, salt, KEY_LEN);
  const storedBuf = Buffer.from(hashHex, 'hex');
  // timingSafeEqual requires equal-length buffers, and throws otherwise —
  // guard against that so a malformed stored value can't crash the request.
  if (hash.length !== storedBuf.length) return false;
  return timingSafeEqual(hash, storedBuf);
}
