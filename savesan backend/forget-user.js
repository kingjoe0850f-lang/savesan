// forget-user.js — deletes everything associated with one email address:
// their account (if verified), any in-progress verification, and any
// active sessions. Useful for re-testing sign-up with the same address.
//
// Usage:
//   node forget-user.js someone@example.com

import { db } from './db.js';

const email = process.argv[2];

if (!email){
  console.log('Usage: node forget-user.js someone@example.com');
  process.exit(1);
}

const normalizedEmail = email.toLowerCase();

const user = db.prepare('SELECT * FROM users WHERE email = ?').get(normalizedEmail);
const pending = db.prepare('SELECT * FROM pending_verifications WHERE email = ?').get(normalizedEmail);

let deletedSomething = false;

if (user){
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(user.id);
  console.log(`Deleted account for ${normalizedEmail} (and any active sessions).`);
  deletedSomething = true;
}

if (pending){
  db.prepare('DELETE FROM pending_verifications WHERE email = ?').run(normalizedEmail);
  console.log(`Deleted in-progress sign-up for ${normalizedEmail}.`);
  deletedSomething = true;
}

if (!deletedSomething){
  console.log(`No account or pending sign-up found for ${normalizedEmail} — nothing to do.`);
}
