// lib/email.js — sends the actual verification email via Resend's HTTP API.
//
// Uses native fetch (built into Node 18+), so no SDK/dependency is needed —
// this is a plain POST to https://api.resend.com/emails with a Bearer key.
//
// If RESEND_API_KEY isn't set, we don't fail the request — we log the code
// to the server console instead, so you can build/test the whole signup →
// verify → login flow locally before ever creating a Resend account.

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL || 'SaveSan <onboarding@resend.dev>';

export async function sendVerificationEmail(toEmail, code){
  if (!RESEND_API_KEY){
    console.log(`\n[DEV MODE — no RESEND_API_KEY set] Verification code for ${toEmail}: ${code}\n`);
    return { ok: true, dev: true };
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: FROM_EMAIL,
      to: toEmail,
      subject: 'Your SaveSan verification code',
      html: `
        <div style="font-family: sans-serif; max-width: 420px; margin: 0 auto;">
          <h2 style="color:#159173;">SaveSan</h2>
          <p>Your verification code is:</p>
          <p style="font-size: 32px; font-weight: 700; letter-spacing: 6px;">${code}</p>
          <p style="color:#647268; font-size: 13px;">This code expires in 10 minutes. If you didn't request this, you can ignore this email.</p>
        </div>
      `
    })
  });

  if (!res.ok){
    const body = await res.text().catch(() => '');
    throw new Error(`Resend API error (${res.status}): ${body}`);
  }

  return { ok: true, dev: false };
}
