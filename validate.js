// lib/validate.js — every rule the frontend already enforces gets checked
// again here. The frontend can be bypassed entirely (curl, a modified
// build, browser dev tools) so the server has to be the real gatekeeper.

export function isValidEmail(email){
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function calcAge(dobStr){
  const dob = new Date(dobStr);
  if (isNaN(dob.getTime())) return -1;
  const today = new Date();
  let age = today.getFullYear() - dob.getFullYear();
  const m = today.getMonth() - dob.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
  return age;
}

export function validateSignup({ name, email, password, dob, phone }){
  const errors = {};
  if (!name || !name.trim()) errors.name = 'Enter your name.';
  if (!isValidEmail(email)) errors.email = 'Enter a valid email.';
  if (!password || password.length < 8) errors.password = 'Use at least 8 characters.';
  if (!dob) errors.dob = 'Enter your date of birth.';
  else if (calcAge(dob) < 18) errors.dob = 'You must be at least 18 to use SaveSan.';
  if (!phone || String(phone).replace(/\D/g, '').length < 7) errors.phone = 'Enter a valid phone number.';
  return errors;
}
