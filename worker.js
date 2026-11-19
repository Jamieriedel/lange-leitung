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
  'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });

export default {
  async fetch(request, env) {
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
        data[key] = value;
        data._updated = Date.now();
        const out = JSON.stringify(data);
        if (out.length > 800000) return json({ error: 'group full' }, 413);
        await env.DATA.put(storeKey, out);
        return json({ ok: true, updated: data._updated });
      }
      return json({ error: 'method not allowed' }, 405);
    }

    return new Response('Not found', { status: 404, headers: CORS });
  },
};
