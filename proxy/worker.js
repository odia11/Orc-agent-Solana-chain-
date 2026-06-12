/**
 * OrcAgent — Jupiter API proxy (Cloudflare Workers)
 *
 * Forwards /v6/quote and /v6/swap to quote-api.jup.ag with proper headers.
 * Use this when your hosting provider's IPs are rate-limited or blocked by Jupiter.
 *
 * Deploy:
 *   npm install -g wrangler
 *   wrangler login
 *   cd proxy && wrangler deploy
 *
 * Optional secret (prevents strangers from using your proxy):
 *   wrangler secret put PROXY_SECRET      # paste any random string
 *   Then set JUPITER_PROXY_SECRET=<same>  # in Railway Variables
 *
 * After deploy, set in Railway Variables:
 *   JUPITER_PROXY_URL=https://orcagent-jupiter-proxy.<subdomain>.workers.dev
 */

const JUPITER_BASE   = 'https://quote-api.jup.ag';
const ALLOWED_PATHS  = ['/v6/quote', '/v6/swap'];

export default {
  async fetch(request, env) {
    // ── Secret check (optional — only enforced when PROXY_SECRET is set) ──
    if (env.PROXY_SECRET) {
      const clientSecret = request.headers.get('X-Proxy-Secret') || '';
      if (clientSecret !== env.PROXY_SECRET) {
        return json({ error: 'Unauthorized' }, 403);
      }
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    // Health probe — Cloudflare ping / uptime checks
    if (path === '/' || path === '/health') {
      return json({ ok: true, proxy: 'orcagent-jupiter-proxy' }, 200);
    }

    // Only forward whitelisted Jupiter paths
    if (!ALLOWED_PATHS.some(p => path.startsWith(p))) {
      return json({ error: 'Path not allowed' }, 404);
    }

    const target = JUPITER_BASE + path + url.search;

    // Jupiter requires these headers — some endpoints reject requests without them
    const forwardHeaders = new Headers({
      'Accept':       'application/json',
      'Content-Type': 'application/json',
      'User-Agent':   'Mozilla/5.0 OrcAgent/1.0',
    });

    const upstream = new Request(target, {
      method:  request.method,
      headers: forwardHeaders,
      body:    request.method !== 'GET' ? request.body : undefined,
    });

    let resp;
    try {
      resp = await fetch(upstream);
    } catch (err) {
      return json({ error: 'Upstream unreachable', detail: String(err) }, 502);
    }

    // Stream Jupiter's response back unchanged
    return new Response(resp.body, {
      status:  resp.status,
      headers: { 'Content-Type': 'application/json' },
    });
  },
};

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
