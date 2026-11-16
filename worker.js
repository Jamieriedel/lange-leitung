// Lange Leitung – iCal-Proxy (Cloudflare Worker)
// Holt eine .ics-Datei serverseitig und gibt sie mit CORS-Header zurück,
// damit der Browser sie lesen darf. Nur echte Kalender-Hosts erlaubt.

const ALLOWED_HOSTS = [
  'p01-caldav.icloud.com', 'p02-caldav.icloud.com', 'p03-caldav.icloud.com',
  // iCloud nutzt viele nummerierte Hosts – wir erlauben das Muster unten generisch
  'calendar.google.com', 'www.google.com',
  'outlook.office365.com', 'outlook.live.com',
];

function hostAllowed(host) {
  host = host.toLowerCase();
  if (host.endsWith('.icloud.com')) return true;            // alle iCloud-CalDAV-Hosts
  if (host.endsWith('.calendar.google.com')) return true;
  if (ALLOWED_HOSTS.includes(host)) return true;
  if (host.endsWith('.office365.com')) return true;
  return false;
}

export default {
  async fetch(request) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': '*',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    const u = new URL(request.url);
    let target = u.searchParams.get('url');
    if (!target) return new Response('Missing ?url=', { status: 400, headers: cors });

    if (target.startsWith('webcal://')) target = 'https://' + target.slice(9);

    let targetUrl;
    try { targetUrl = new URL(target); } catch (e) {
      return new Response('Bad url', { status: 400, headers: cors });
    }
    if (targetUrl.protocol !== 'https:' || !hostAllowed(targetUrl.hostname)) {
      return new Response('Host not allowed', { status: 403, headers: cors });
    }

    try {
      const res = await fetch(targetUrl.toString(), {
        headers: { 'User-Agent': 'LangeLeitung/1.0', 'Accept': 'text/calendar, */*' },
        redirect: 'follow',
      });
      const body = await res.text();
      return new Response(body, {
        status: res.status,
        headers: { ...cors, 'Content-Type': 'text/calendar; charset=utf-8', 'Cache-Control': 'public, max-age=900' },
      });
    } catch (e) {
      return new Response('Fetch failed', { status: 502, headers: cors });
    }
  },
};
