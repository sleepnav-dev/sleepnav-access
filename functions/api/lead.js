// POST /api/lead — SleepNav "Request access" lead capture.
// Verifies Cloudflare Turnstile, validates the four fields, and emails the
// lead to LEAD_TO via Mailgun (EU region). Nothing is stored.
//
// Required secrets (Cloudflare Pages > Settings > Environment variables):
//   TURNSTILE_SECRET_KEY   Turnstile widget secret (encrypted)
//   MAILGUN_API_KEY        Mailgun private API key (encrypted)
// Optional plaintext overrides (sensible defaults below):
//   MAILGUN_DOMAIN  default mg.sleepnav.com
//   MAILGUN_BASE    default https://api.eu.mailgun.net   (EU region)
//   LEAD_TO         default az@snorer.com
//   LEAD_FROM       default SleepNav leads <leads@mg.sleepnav.com>

const MAX = { name: 100, pharmacy: 150, email: 200, phone: 40 };

function clean(v, max) {
  // trim, drop CR/LF (header-injection guard), cap length
  return String(v == null ? '' : v).replace(/[\r\n]+/g, ' ').trim().slice(0, max);
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ ok: false, error: 'bad_request' }, 400);
  }

  // Honeypot: real users never fill this. Silently accept and drop.
  if (clean(body.company, 200)) {
    return json({ ok: true });
  }

  const name = clean(body.name, MAX.name);
  const pharmacy = clean(body.pharmacy, MAX.pharmacy);
  const email = clean(body.email, MAX.email);
  const phone = clean(body.phone, MAX.phone);
  const token = String(body.token || '');

  if (!name || !pharmacy || !email) {
    return json({ ok: false, error: 'missing_fields' }, 422);
  }
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return json({ ok: false, error: 'bad_email' }, 422);
  }
  if (!token) {
    return json({ ok: false, error: 'no_token' }, 400);
  }

  // 1) Verify Turnstile
  try {
    const ip = request.headers.get('CF-Connecting-IP') || '';
    const form = new FormData();
    form.append('secret', env.TURNSTILE_SECRET_KEY || '');
    form.append('response', token);
    if (ip) form.append('remoteip', ip);
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
    });
    const verify = await verifyRes.json();
    if (!verify.success) {
      return json({ ok: false, error: 'verification_failed' }, 400);
    }
  } catch (e) {
    console.error('turnstile verify error', e);
    return json({ ok: false, error: 'verification_error' }, 502);
  }

  // 2) Send via Mailgun (EU)
  const domain = env.MAILGUN_DOMAIN || 'mg.sleepnav.com';
  const base = env.MAILGUN_BASE || 'https://api.eu.mailgun.net';
  const to = env.LEAD_TO || 'az@snorer.com';
  const from = env.LEAD_FROM || 'SleepNav leads <leads@mg.sleepnav.com>';

  const text =
    'New SleepNav access request\n' +
    '----------------------------\n' +
    'Name:     ' + name + '\n' +
    'Pharmacy: ' + pharmacy + '\n' +
    'Email:    ' + email + '\n' +
    'Phone:    ' + (phone || '(not given)') + '\n' +
    'Received: ' + new Date().toISOString() + '\n\n' +
    'Reply directly to this email to reach the sender.';

  try {
    const mg = new FormData();
    mg.append('from', from);
    mg.append('to', to);
    mg.append('h:Reply-To', email);
    mg.append('subject', 'New SleepNav access request: ' + pharmacy);
    mg.append('text', text);

    const auth = 'Basic ' + btoa('api:' + (env.MAILGUN_API_KEY || ''));
    const sendRes = await fetch(base + '/v3/' + domain + '/messages', {
      method: 'POST',
      headers: { Authorization: auth },
      body: mg,
    });

    if (!sendRes.ok) {
      const detail = await sendRes.text().catch(() => '');
      console.error('mailgun send failed', sendRes.status, detail);
      return json({ ok: false, error: 'send_failed' }, 502);
    }
  } catch (e) {
    console.error('mailgun send error', e);
    return json({ ok: false, error: 'send_error' }, 502);
  }

  return json({ ok: true });
}

// Any non-POST method
export async function onRequest(context) {
  if (context.request.method === 'POST') return onRequestPost(context);
  return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
}
