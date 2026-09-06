// server.js — the whole backend. Deliberately dependency-free (only
// Node built-ins) so it runs anywhere Node 22.5+ runs, no `npm install`
// required. For a larger app you'd likely reach for Express, but for
// five routes, plain node:http keeps this readable end to end in one file.

import { createServer } from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { db } from './db.js';
import { hashPassword, verifyPassword } from './password.js';
import { generateSessionToken, generateVerificationCode } from './tokens.js';
import { sendVerificationEmail } from './email.js';
import { validateSignup, isValidEmail } from './validate.js';

const PORT = process.env.PORT || 3001;
const CODE_TTL_MS = 10 * 60 * 1000;      // codes expire after 10 minutes
const RESEND_COOLDOWN_MS = 60 * 1000;     // one resend per 60 seconds
const MAX_ATTEMPTS = 5;                   // wrong-code guesses allowed per code
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const indexPath = path.join(__dirname, 'index.html');
const adminPath = path.join(__dirname, 'admin.html');

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
const findAdminSession = db.prepare('SELECT * FROM admin_sessions WHERE token = ?');
const insertAdminSession = db.prepare('INSERT INTO admin_sessions (token, created_at, expires_at) VALUES (?, ?, ?)');
const deleteAdminSession = db.prepare('DELETE FROM admin_sessions WHERE token = ?');
const listUsers = db.prepare('SELECT id, name, email, dob, phone, created_at, is_disabled FROM users ORDER BY created_at DESC');
const findManagedUser = db.prepare('SELECT id, name, email, is_disabled FROM users WHERE id = ?');
const setUserDisabled = db.prepare('UPDATE users SET is_disabled = ? WHERE id = ?');
const deleteManagedUser = db.prepare('DELETE FROM users WHERE id = ?');
const deleteUserSessions = db.prepare('DELETE FROM sessions WHERE user_id = ?');
const findUserData = db.prepare('SELECT data_json, updated_at FROM user_data WHERE user_id = ?');
const upsertUserData = db.prepare(`
  INSERT INTO user_data (user_id, data_json, updated_at) VALUES (?, ?, ?)
  ON CONFLICT (user_id) DO UPDATE SET data_json = EXCLUDED.data_json, updated_at = EXCLUDED.updated_at
`);

// ---------------- Helpers ----------------
// The integrated app uses same-origin requests, so CORS is disabled by
// default. Set ALLOWED_ORIGIN only if you later host the frontend elsewhere.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '';
const CORS_HEADERS = ALLOWED_ORIGIN ? {
  'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, ngrok-skip-browser-warning'
} : {};

function sendJSON(res, status, data){
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...CORS_HEADERS
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

function getAdminToken(req){
  const header = req.headers['x-admin-token'] || '';
  return typeof header === 'string' && header ? header : null;
}

function adminConfigured(){
  return Boolean(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD);
}

function secretsMatch(a, b){
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

async function requireAdmin(req, res){
  const token = getAdminToken(req);
  const session = token && await findAdminSession.get(token);
  if (!session || Date.now() > session.expires_at){
    if (token) await deleteAdminSession.run(token);
    sendJSON(res, 401, { ok: false, error: 'Admin sign-in required.' });
    return false;
  }
  return true;
}

// ---------------- Route handlers ----------------

async function handleSignup(req, res){
  const body = await readBody(req);
  const { name, email, password, dob, phone } = body;
  const errors = validateSignup({ name, email, password, dob, phone });

  if (await findUserByEmail.get(String(email || '').toLowerCase())){
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

  await upsertPending.run(normalizedEmail, JSON.stringify(draft), code, Date.now() + CODE_TTL_MS, Date.now());

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

  const pending = await findPending.get(email);
  if (!pending) return sendJSON(res, 400, { ok: false, error: 'Nothing to verify — please sign up again.' });
  if (Date.now() > pending.expires_at){
    await deletePending.run(email);
    return sendJSON(res, 400, { ok: false, error: 'That code has expired. Please request a new one.' });
  }
  if (pending.attempts >= MAX_ATTEMPTS){
    await deletePending.run(email);
    return sendJSON(res, 429, { ok: false, error: 'Too many incorrect attempts. Please sign up again.' });
  }
  if (code !== pending.code){
    await bumpAttempts.run(email);
    return sendJSON(res, 400, { ok: false, error: 'That code doesn\u2019t match. Check it and try again.' });
  }

  const draft = JSON.parse(pending.draft_json);
  await insertUser.run(draft.id, draft.name, draft.email, draft.password_hash, draft.dob, draft.phone, Date.now());
  await deletePending.run(email);

  const token = generateSessionToken();
  await insertSession.run(token, draft.id, Date.now(), Date.now() + SESSION_TTL_MS);

  sendJSON(res, 200, { ok: true, token, user: publicUser({ id: draft.id, name: draft.name, email: draft.email }) });
}

async function handleResend(req, res){
  const body = await readBody(req);
  const email = String(body.email || '').toLowerCase();
  const pending = await findPending.get(email);
  if (!pending) return sendJSON(res, 400, { ok: false, error: 'No signup in progress for that email.' });

  if (Date.now() - pending.last_sent_at < RESEND_COOLDOWN_MS){
    const waitSec = Math.ceil((RESEND_COOLDOWN_MS - (Date.now() - pending.last_sent_at)) / 1000);
    return sendJSON(res, 429, { ok: false, error: `Please wait ${waitSec}s before requesting another code.` });
  }

  const code = generateVerificationCode();
  await upsertPending.run(email, pending.draft_json, code, Date.now() + CODE_TTL_MS, Date.now());

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

  const pending = await findPending.get(email);
  const user = await findUserByEmail.get(email);

  if (!user && pending){
    return sendJSON(res, 403, { ok: false, needsVerification: true, email, error: 'Please verify your email to finish creating your account.' });
  }
  if (!user || !isValidEmail(email) || !verifyPassword(password, user.password_hash)){
    return sendJSON(res, 401, { ok: false, error: 'Incorrect email or password.' });
  }
  if (user.is_disabled){
    return sendJSON(res, 403, { ok: false, error: 'This account has been disabled. Please contact SaveSan support.' });
  }

  const token = generateSessionToken();
  await insertSession.run(token, user.id, Date.now(), Date.now() + SESSION_TTL_MS);
  sendJSON(res, 200, { ok: true, token, user: publicUser(user) });
}

async function handleMe(req, res){
  const token = getBearerToken(req);
  const session = token && await findSession.get(token);
  if (!session || Date.now() > session.expires_at){
    return sendJSON(res, 401, { ok: false, error: 'Not signed in.' });
  }
  const user = await findUserById.get(session.user_id);
  if (!user) return sendJSON(res, 401, { ok: false, error: 'Not signed in.' });
  sendJSON(res, 200, { ok: true, user: publicUser(user) });
}

async function handleLogout(req, res){
  const token = getBearerToken(req);
  if (token) await deleteSession.run(token);
  sendJSON(res, 200, { ok: true });
}

async function requireUser(req, res){
  const token = getBearerToken(req);
  const session = token && await findSession.get(token);
  if (!session || Date.now() > session.expires_at) {
    return null;
  }
  return session.user_id;
}

async function handleUserData(req, res){
  const userId = await requireUser(req, res);
  if (!userId) return sendJSON(res, 401, { ok: false, error: 'Not signed in.' });
  if (req.method === 'GET') {
    const saved = await findUserData.get(userId);
    return sendJSON(res, 200, { ok: true, data: saved ? JSON.parse(saved.data_json) : null, updatedAt: saved?.updated_at || null });
  }
  const body = await readBody(req);
  if (!body || typeof body.data !== 'object' || Array.isArray(body.data)) {
    return sendJSON(res, 400, { ok: false, error: 'Invalid data.' });
  }
  const serialized = JSON.stringify(body.data);
  if (serialized.length > 500000) return sendJSON(res, 413, { ok: false, error: 'Saved data is too large.' });
  await upsertUserData.run(userId, serialized, Date.now());
  sendJSON(res, 200, { ok: true });
}

async function handleAdminLogin(req, res){
  if (!adminConfigured()){
    return sendJSON(res, 503, { ok: false, error: 'Admin access has not been configured yet.' });
  }
  const body = await readBody(req);
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!secretsMatch(email, process.env.ADMIN_EMAIL.toLowerCase()) || !secretsMatch(password, process.env.ADMIN_PASSWORD)){
    return sendJSON(res, 401, { ok: false, error: 'Incorrect admin email or password.' });
  }
  const token = generateSessionToken();
  await insertAdminSession.run(token, Date.now(), Date.now() + ADMIN_SESSION_TTL_MS);
  sendJSON(res, 200, { ok: true, token, expiresAt: Date.now() + ADMIN_SESSION_TTL_MS });
}

async function handleAdminUsers(req, res){
  if (!await requireAdmin(req, res)) return;
  const url = new URL(req.url, `http://${req.headers.host}`);
  const query = String(url.searchParams.get('q') || '').trim().toLowerCase();
  const users = (await listUsers.all())
    .filter(user => !query || user.name.toLowerCase().includes(query) || user.email.toLowerCase().includes(query))
    .map(user => ({ ...user, is_disabled: Boolean(user.is_disabled) }));
  sendJSON(res, 200, { ok: true, users });
}

async function handleAdminUserAction(req, res){
  if (!await requireAdmin(req, res)) return;
  const userId = new URL(req.url, `http://${req.headers.host}`).pathname.split('/').at(-1);
  const user = await findManagedUser.get(userId);
  if (!user) return sendJSON(res, 404, { ok: false, error: 'User not found.' });
  const body = await readBody(req);
  if (body.action === 'disable' || body.action === 'enable'){
    const disabled = body.action === 'disable';
    await setUserDisabled.run(disabled, userId);
    if (disabled) await deleteUserSessions.run(userId);
    return sendJSON(res, 200, { ok: true, user: { ...user, is_disabled: disabled } });
  }
  if (body.action === 'delete'){
    await deleteUserSessions.run(userId);
    await deleteManagedUser.run(userId);
    return sendJSON(res, 200, { ok: true });
  }
  sendJSON(res, 400, { ok: false, error: 'Unsupported account action.' });
}

async function handleAdminLogout(req, res){
  const token = getAdminToken(req);
  if (token) await deleteAdminSession.run(token);
  sendJSON(res, 200, { ok: true });
}

// ---------------- Router ----------------
const routes = {
  'POST /api/signup': handleSignup,
  'POST /api/verify': handleVerify,
  'POST /api/resend': handleResend,
  'POST /api/login': handleLogin,
  'GET /api/me': handleMe,
  'POST /api/logout': handleLogout,
  'GET /api/data': handleUserData,
  'PUT /api/data': handleUserData,
  'POST /api/admin/login': handleAdminLogin,
  'GET /api/admin/users': handleAdminUsers,
  'POST /api/admin/logout': handleAdminLogout
};

const server = createServer(async (req, res) => {
  if (req.method === 'OPTIONS'){
    return sendJSON(res, 204, {});
  }
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/admin')){
    try {
      const html = await readFile(url.pathname === '/admin' ? adminPath : indexPath);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(html);
    } catch (err) {
      console.error(err);
      return sendJSON(res, 500, { ok: false, error: 'Could not load the web app.' });
    }
  }
  if (req.method === 'POST' && url.pathname.startsWith('/api/admin/users/')){
    return handleAdminUserAction(req, res);
  }
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
