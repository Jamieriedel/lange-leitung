// Lange Leitung – Worker: iCal-Proxy + Gruppen-Speicher (Cloudflare KV)
//
// Zwei Aufgaben:
//  1) /proxy?url=…  holt eine .ics-Datei serverseitig (umgeht CORS). Nur echte Kalender-Hosts.
//  2) /group/<id>   liest/schreibt die gemeinsamen Daten einer Gruppe im KV-Speicher "DATA".
//
// KV-Binding muss im Worker "DATA" heißen (wird in Cloudflare einmal verknüpft).

const ALLOWED_HOSTS = [
  'calendar.google.com', 'www.google.com',
  'outlook.office365.com', 'outlook.live.com',
];
function hostAllowed(host) {
  host = host.toLowerCase();
  if (host.endsWith('.icloud.com')) return true;
  if (host.endsWith('.calendar.google.com')) return true;
  if (host.endsWith('.office365.com')) return true;
  return ALLOWED_HOSTS.includes(host);
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Group-Code, X-Member-Id, X-Member-Name, X-Silent',
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });


// ---------- Push (Web Push, VAPID + aes128gcm) ----------
// Die VAPID-Schlüssel erzeugt der Worker selbst beim ersten Bedarf und legt sie im KV ab –
// kein Geheimnis im Code, nichts manuell einzurichten.
const APP_URL = 'https://jamieriedel.github.io/lange-leitung/';
const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const ub64 = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

async function vapidKeys(env) {
  const raw = await env.DATA.get('vapid');
  if (raw) {
    const k = JSON.parse(raw);
    return { pub: k.pub, priv: await crypto.subtle.importKey('jwk', k.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']) };
  }
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const pub = b64u(await crypto.subtle.exportKey('raw', kp.publicKey));
  await env.DATA.put('vapid', JSON.stringify({ jwk, pub }));
  return { pub, priv: kp.privateKey };
}
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function encryptPayload(sub, text) {
  const uaPub = ub64(sub.keys.p256dh), auth = ub64(sub.keys.auth);
  const as = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const ikm = await hkdf(auth, secret, concat(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(enc.encode(text), new Uint8Array([2]))));
  return concat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([65]), asPub, ct);
}
async function vapidAuth(env, endpoint) {
  const { pub, priv } = await vapidKeys(env);
  const h = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const c = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: APP_URL })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, enc.encode(h + '.' + c));
  return `vapid t=${h}.${c}.${b64u(sig)}, k=${pub}`;
}
async function sendPush(env, sub, payload) {
  const body = await encryptPayload(sub, JSON.stringify(payload));
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: { Authorization: await vapidAuth(env, sub.endpoint), 'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'normal' },
    body,
  });
  return res.status;
}
async function notifyGroup(env, id, exceptMember, payload) {
  const raw = await env.DATA.get('p:' + id); if (!raw) return;
  const subs = JSON.parse(raw); let changed = false;
  await Promise.all(Object.entries(subs).map(async ([m, s]) => {
    if (m === exceptMember) return;
    try { const st = await sendPush(env, s, payload); if (st === 404 || st === 410) { delete subs[m]; changed = true; } } catch (e) {}
  }));
  if (changed) await env.DATA.put('p:' + id, JSON.stringify(subs));
}
const fmtWhen = ms => new Date(ms).toLocaleString('de-DE', { timeZone: 'Europe/Berlin', weekday: 'short', day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
function newsFor(key, prev, next, who) {
  if (!Array.isArray(next)) return null;
  const old = new Set((Array.isArray(prev) ? prev : []).map(x => x && x.id));
  const x = next.find(y => y && y.id && !old.has(y.id) && !y.demo);
  if (!x) return null;
  const by = who ? who + ': ' : '';
  if (key === 'events') return `${by}Neues Treffen – ${x.title} · ${fmtWhen(x.start)} Uhr`;
  if (key === 'polls') return `${by}Neue Umfrage – ${x.title}`;
  if (key === 'wannados') return `${by}Neues Wanna-do – ${x.text}`;
  if (key === 'expenses') return `${x.who} hat ${Number(x.amount).toFixed(2).replace('.', ',')} € eingetragen – ${x.what}`;
  return null;
}
async function groupData(env, id) { const raw = await env.DATA.get('g:' + id); return raw ? JSON.parse(raw) : {}; }
const codeOk = (data, request) => { const s = data.meta && data.meta.code; return !s || s === (request.headers.get('X-Group-Code') || ''); };

// ---------- .ics für „In meinen Kalender" ----------
function icsFile(u) {
  const t = (u.searchParams.get('t') || 'Treffen').slice(0, 140);
  const s = +u.searchParams.get('s'), e = +u.searchParams.get('e');
  if (!(s > 0 && e > s)) return null;
  const f = ms => new Date(ms).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const esc = x => x.replace(/[\;,]/g, m => '\\' + m).replace(/\r?\n/g, '\\n');
  const uid = (u.searchParams.get('id') || String(s)).replace(/[^A-Za-z0-9-]/g, '') + '@friends-app';
  return ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Friends-App//DE', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    'BEGIN:VEVENT', 'UID:' + uid, 'DTSTAMP:' + f(Date.now()), 'DTSTART:' + f(s), 'DTEND:' + f(e),
    'SUMMARY:' + esc(t), 'END:VEVENT', 'END:VCALENDAR', ''].join('\r\n');
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const u = new URL(request.url);
    const path = u.pathname.replace(/\/+$/, '');

    // ---- 1) iCal-Proxy ----
    if (path === '' || path === '/proxy') {
      let target = u.searchParams.get('url');
      if (!target) return new Response('Missing ?url=', { status: 400, headers: CORS });
      if (target.startsWith('webcal://')) target = 'https://' + target.slice(9);
      let t;
      try { t = new URL(target); } catch (e) { return new Response('Bad url', { status: 400, headers: CORS }); }
      // Jeder HTTPS-Kalender erlaubt (iCloud, Google, Dienstplan-Apps wie Swisio …),
      // aber durchgereicht wird NUR echter iCalendar-Inhalt – kein Allzweck-Proxy.
      if (t.protocol !== 'https:')
        return new Response('Only https', { status: 403, headers: CORS });
      try {
        const res = await fetch(t.toString(), {
          headers: {
            // Manche Dienstplan-Server (z.B. Swisio) liefern nur „echten" Clients aus
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Accept': 'text/calendar, text/plain, */*',
            'Accept-Language': 'de-DE,de;q=0.9',
          },
          redirect: 'follow',
        });
        const body = (await res.text()).replace(/^﻿/, '');
        if (u.searchParams.get('debug') === '1') {
          return new Response(JSON.stringify({
            status: res.status, contentType: res.headers.get('content-type'), length: body.length,
            isCalendar: /BEGIN:VCALENDAR/i.test(body.slice(0, 10000)),
            head: body.slice(0, 160).replace(/[^\x20-\x7E\n]/g, '?'),
          }, null, 2), { headers: { ...CORS, 'Content-Type': 'application/json' } });
        }
        if (body.length > 5_000_000) return new Response('Too large', { status: 413, headers: CORS });
        if (!/BEGIN:VCALENDAR/i.test(body.slice(0, 10000)))
          return new Response('Not a calendar', { status: 415, headers: CORS });
        return new Response(body, {
          status: res.status,
          headers: { ...CORS, 'Content-Type': 'text/calendar; charset=utf-8', 'Cache-Control': 'public, max-age=900' },
        });
      } catch (e) { return new Response('Fetch failed', { status: 502, headers: CORS }); }
    }

    // ---- Termin als .ics (öffnet „Zum Kalender hinzufügen") ----
    if (path === '/ics') {
      const ics = icsFile(u);
      if (!ics) return new Response('Bad times', { status: 400, headers: CORS });
      return new Response(ics, { headers: { ...CORS, 'Content-Type': 'text/calendar; charset=utf-8',
        'Content-Disposition': 'inline; filename="treffen.ics"' } });
    }

    // ---- Push: Schlüssel + Anmeldungen ----
    if (path === '/push/key') {
      if (!env.DATA) return json({ error: 'KV not configured' }, 500);
      return new Response((await vapidKeys(env)).pub, { headers: { ...CORS, 'Content-Type': 'text/plain' } });
    }
    const pm = path.match(/^\/push\/([A-Za-z0-9_-]{1,64})(?:\/([A-Za-z0-9_-]{1,64}))?$/);
    if (pm) {
      const id = pm[1];
      if (!codeOk(await groupData(env, id), request)) return json({ error: 'locked' }, 403);
      const raw = await env.DATA.get('p:' + id); const subs = raw ? JSON.parse(raw) : {};
      if (request.method === 'PUT') {
        let b; try { b = await request.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
        if (!b || !b.member || !b.sub || !/^https:\/\//.test(b.sub.endpoint || '') || !b.sub.keys) return json({ error: 'bad sub' }, 400);
        subs[String(b.member).slice(0, 64)] = { endpoint: b.sub.endpoint, keys: { p256dh: b.sub.keys.p256dh, auth: b.sub.keys.auth } };
        await env.DATA.put('p:' + id, JSON.stringify(subs));
        return json({ ok: true });
      }
      if (request.method === 'DELETE' && pm[2]) {
        delete subs[pm[2]]; await env.DATA.put('p:' + id, JSON.stringify(subs));
        return json({ ok: true });
      }
      return json({ error: 'method not allowed' }, 405);
    }

    // ---- 2) Gruppen-Speicher ----
    // GET  /group/<id>         -> gesamte Gruppendaten
    // PUT  /group/<id>/<key>   -> speichert Body (JSON) unter diesem Teil (z.B. cals, wannados, polls, expenses, meta)
    const gm = path.match(/^\/group\/([A-Za-z0-9_-]{1,64})(?:\/([a-z]{1,32}))?$/);
    if (gm) {
      if (!env.DATA) return json({ error: 'KV not configured' }, 500);
      const id = gm[1], key = gm[2];
      const storeKey = 'g:' + id;
      const raw = await env.DATA.get(storeKey);
      const data = raw ? JSON.parse(raw) : {};

      // Zugangscode serverseitig prüfen: hat die Gruppe einen Code, muss er passen.
      const savedCode = data.meta && data.meta.code;
      const givenCode = request.headers.get('X-Group-Code') || '';
      if (savedCode && savedCode !== givenCode) {
        return json({ error: 'locked' }, 403);
      }

      if (request.method === 'GET') {
        return json(data);
      }
      if (request.method === 'PUT' && key) {
        let value;
        try { value = await request.json(); } catch (e) { return json({ error: 'bad json' }, 400); }
        // meta.code darf nur gesetzt werden, solange die Gruppe noch keinen hat (erstes Anlegen)
        if (key === 'meta' && value && value.code && savedCode && savedCode !== value.code) {
          return json({ error: 'locked' }, 403);
        }
        const prev = data[key];
        data[key] = value;
        data._updated = Date.now();
        const out = JSON.stringify(data);
        if (out.length > 800000) return json({ error: 'group full' }, 413);
        await env.DATA.put(storeKey, out);
        // Push an die anderen: nur bei neuen Einträgen, nicht beim stillen Nachsynchronisieren
        if (!request.headers.get('X-Silent')) {
          let who = ''; try { who = decodeURIComponent(request.headers.get('X-Member-Name') || '').slice(0, 40); } catch (e) {}
          const msg = newsFor(key, prev, value, who);
          if (msg && ctx) ctx.waitUntil(notifyGroup(env, id, request.headers.get('X-Member-Id') || '', {
            title: (data.meta && data.meta.name) || 'Friends-App', body: msg, tag: id + '-' + key, url: APP_URL + '#g=' + id }));
        }
        return json({ ok: true, updated: data._updated });
      }
      return json({ error: 'method not allowed' }, 405);
    }

    return new Response('Not found', { status: 404, headers: CORS });
  },
};
