// Cloudflare Worker: exchanges a GitHub OAuth "code" for an access token.
// The client secret lives only here (as a Worker secret), never in the web page.
export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const allowed = origin === env.ALLOWED_ORIGIN;
    const cors = {
      "Access-Control-Allow-Origin": allowed ? origin : "null",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    };
    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { ...cors, "Content-Type": "application/json" },
      });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST" || !allowed) return json({ error: "forbidden" }, 403);

    let code;
    try {
      ({ code } = await req.json());
    } catch (e) {
      return json({ error: "bad_request" }, 400);
    }
    if (typeof code !== "string" || !code) return json({ error: "bad_request" }, 400);

    const r = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        client_id: env.CLIENT_ID,
        client_secret: env.CLIENT_SECRET,
        code,
      }),
    });
    const d = await r.json();
    if (!d.access_token) return json({ error: d.error || "exchange_failed" }, 400);
    return json({ access_token: d.access_token });
  },
};
