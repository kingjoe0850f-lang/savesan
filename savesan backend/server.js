// server.js — the whole backend. Deliberately dependency-free (only
// Node built-ins) so it runs anywhere Node 22.5+ runs, no `npm install`
// required. For a larger app you'd likely reach for Express, but for
// five routes, plain node:http keeps this readable end to end in one file.

import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { db } from './db.js';
import { hashPassword, verifyPassword } from './lib/password.js';
import { generateSessionToken, generateVerificationCode } from './lib/tokens.js';
import { sendVerificationEmail } from './lib/email.js';
import { validateSignup, isValidEmail } from './lib/validate.js';

const PORT = process.env.PORT || 3001;
const CODE_TTL_MS = 10 * 60 * 1000;      // codes expire after 10 minutes
const RESEND_COOLDOWN_MS = 60 * 1000;     // one resend per 60 seconds
const MAX_ATTEMPTS = 5;                   // wrong-code guesses allowed per code
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// ---------------- Prepared statements ----------------
const findUserByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');
const insertUser = db.prepare(`
  INSERT INTO users (id, name, email, password_hash, dob, phone, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const findPending = db.prepare('SELECT * FROM pending_verifications WHERE email = ?');
const upsertPending = db.prepare(`
  INSERT INTO pending_verifications (email, draft_json, code, expires_at, attempts, last_sent_at)
  VALUES (?, ?, ?, ?, 0, ?)
  ON CONFLICT(email) DO UPDATE SET draft_json = excluded.draft_json, code = excluded.code,
    expires_at = excluded.expires_at, attempts = 0, last_sent_at = excluded.last_sent_at
`);
const bumpAttempts = db.prepare('UPDATE pending_verifications SET attempts = attempts + 1 WHERE email = ?');
const deletePending = db.prepare('DELETE FROM pending_verifications WHERE email = ?');
const insertSession = db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)');
const findSession = db.prepare('SELECT * FROM sessions WHERE token = ?');
const deleteSession = db.prepare('DELETE FROM sessions WHERE token = ?');

// ---------------- Helpers ----------------
function sendJSON(res, status, data){
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, ngrok-skip-browser-warning'
  });
  res.end(body);
}

function readBody(req){
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); }
      catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });
}

function publicUser(user){
  return { id: user.id, name: user.name, email: user.email };
}

function getBearerToken(req){
  const header = req.headers['authorization'] || '';
  const match = header.match(/^Bearer (.+)$/);
  return match ? match[1] : null;
}

// ---------------- Route handlers ----------------

async function handleSignup(req, res){
  const body = await readBody(req);
  const { name, email, password, dob, phone } = body;
  const errors = validateSignup({ name, email, password, dob, phone });

  if (findUserByEmail.get(String(email || '').toLowerCase())){
    errors.email = 'An account with this email already exists.';
  }
  if (Object.keys(errors).length){
    return sendJSON(res, 400, { ok: false, errors });
  }

  const normalizedEmail = email.toLowerCase();
  const code = generateVerificationCode();
  const draft = {
    id: randomUUID(),
    name: name.trim(),
    email: normalizedEmail,
    password_hash: hashPassword(password),
    dob,
    phone
  };

  upsertPending.run(normalizedEmail, JSON.stringify(draft), code, Date.now() + CODE_TTL_MS, Date.now());

  try {
    await sendVerificationEmail(normalizedEmail, code);
  } catch (err){
    return sendJSON(res, 502, { ok: false, error: 'Could not send verification email: ' + err.message });
  }

  sendJSON(res, 200, { ok: true, email: normalizedEmail });
}

async function handleVerify(req, res){
  const body = await readBody(req);
  const email = String(body.email || '').toLowerCase();
  const code = String(body.code || '');

  const pending = findPending.get(email);
  if (!pending) return sendJSON(res, 400, { ok: false, error: 'Nothing to verify — please sign up again.' });
  if (Date.now() > pending.expires_at){
    deletePending.run(email);
    return sendJSON(res, 400, { ok: false, error: 'That code has expired. Please request a new one.' });
  }
  if (pending.attempts >= MAX_ATTEMPTS){
    deletePending.run(email);
    return sendJSON(res, 429, { ok: false, error: 'Too many incorrect attempts. Please sign up again.' });
  }
  if (code !== pending.code){
    bumpAttempts.run(email);
    return sendJSON(res, 400, { ok: false, error: 'That code doesn\u2019t match. Check it and try again.' });
  }

  const draft = JSON.parse(pending.draft_json);
  insertUser.run(draft.id, draft.name, draft.email, draft.password_hash, draft.dob, draft.phone, Date.now());
  deletePending.run(email);

  const token = generateSessionToken();
  insertSession.run(token, draft.id, Date.now(), Date.now() + SESSION_TTL_MS);

  sendJSON(res, 200, { ok: true, token, user: publicUser({ id: draft.id, name: draft.name, email: draft.email }) });
}

async function handleResend(req, res){
  const body = await readBody(req);
  const email = String(body.email || '').toLowerCase();
  const pending = findPending.get(email);
  if (!pending) return sendJSON(res, 400, { ok: false, error: 'No signup in progress for that email.' });

  if (Date.now() - pending.last_sent_at < RESEND_COOLDOWN_MS){
    const waitSec = Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - pending.last_sent_at)) / 1000);
    return sendJSON(res, 429, { ok: false, error: `Please wait ${waitSec}s before requesting another code.` });
  }

  const code = generateVerificationCode();
  upsertPending.run(email, pending.draft_json, code, Date.now() + CODE_TTL_MS, Date.now());

  try {
    await sendVerificationEmail(email, code);
  } catch (err){
    return sendJSON(res, 502, { ok: false, error: 'Could not send verification email: ' + err.message });
  }
  sendJSON(res, 200, { ok: true });
}

async function handleLogin(req, res){
  const body = await readBody(req);
  const email = String(body.email || '').toLowerCase();
  const password = String(body.password || '');

  const pending = findPending.get(email);
  const user = findUserByEmail.get(email);

  if (!user && pending){
    return sendJSON(res, 403, { ok: false, needsVerification: true, email, error: 'Please verify your email to finish creating your account.' });
  }
  if (!user || !isValidEmail(email) || !verifyPassword(password, user.password_hash)){
    return sendJSON(res, 401, { ok: false, error: 'Incorrect email or password.' });
  }

  const token = generateSessionToken();
  insertSession.run(token, user.id, Date.now(), Date.now() + SESSION_TTL_MS);
  sendJSON(res, 200, { ok: true, token, user: publicUser(user) });
}

async function handleMe(req, res){
  const token = getBearerToken(req);
  const session = token && findSession.get(token);
  if (!session || Date.now() > session.expires_at){
    return sendJSON(res, 401, { ok: false, error: 'Not signed in.' });
  }
  const user = findUserById.get(session.user_id);
  if (!user) return sendJSON(res, 401, { ok: false, error: 'Not signed in.' });
  sendJSON(res, 200, { ok: true, user: publicUser(user) });
}

async function handleLogout(req, res){
  const token = getBearerToken(req);
  if (token) deleteSession.run(token);
  sendJSON(res, 200, { ok: true });
}

// ---------------- Router ----------------
const routes = {
  'POST /api/signup': handleSignup,
  'POST /api/verify': handleVerify,
  'POST /api/resend': handleResend,
  'POST /api/login': handleLogin,
  'GET /api/me': handleMe,
  'POST /api/logout': handleLogout
};

const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS'){
    return sendJSON(res, 204, {});
  }
  const url = new URL(req.url, `http://${req.headers.host}`);
  const key = `${req.method} ${url.pathname}`;
  const handler = routes[key];

  if (!handler){
    return sendJSON(res, 404, { ok: false, error: 'Not found.' });
  }

  try {
    await handler(req, res);
  } catch (err){
    console.error(err);
    sendJSON(res, 500, { ok: false, error: 'Server error.' });
  }
});

server.listen(PORT, () => {
  console.log(`SaveSan backend listening on http://localhost:${PORT}`);
  if (!process.env.RESEND_API_KEY){
    console.log('No RESEND_API_KEY set — verification codes will print to this console instead of being emailed.');
  }
});
