export interface Env {
  FPC_PROXY_SECRET?: string;
  FPC_PATH?: string;
  FPC_API?: string;
  FPC_AGENT_URL?: string;
}

const DEFAULT_API = "https://api.fpchecker.com";
const DEFAULT_AGENT_URL = "https://fpchecker.com/static/fp-agent.min.js";
const AGENT_CACHE_SECONDS = 3600;
const API_ROUTE = /^v[12]\/(challenge|identify)$/;

interface CfProps {
  country?: string;
  timezone?: string;
  city?: string;
  asn?: number;
}

const text = (body: string, status: number): Response =>
  new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8" } });

function trimSlashes(s: string): string {
  return s.replace(/^\/+|\/+$/g, "");
}

/** Build the upstream request headers: client X-FPC-* and Cookie are dropped, trusted values added. */
function upstreamHeaders(request: Request, secret: string): Headers {
  const headers = new Headers();
  for (const [name, value] of request.headers) {
    const n = name.toLowerCase();
    if (n.startsWith("x-fpc-") || n === "cookie" || n === "host" || n === "cf-connecting-ip") continue;
    if (n.startsWith("cf-") || n === "x-forwarded-for" || n === "x-real-ip") continue;
    headers.set(name, value);
  }
  headers.set("x-fpc-proxy-secret", secret);
  const cf = ((request as unknown as { cf?: CfProps }).cf ?? {}) as CfProps;
  const ip = request.headers.get("cf-connecting-ip");
  if (ip) headers.set("x-fpc-client-ip", ip);
  if (cf.country) headers.set("x-fpc-client-country", cf.country);
  if (cf.timezone) headers.set("x-fpc-client-timezone", cf.timezone);
  if (cf.city) headers.set("x-fpc-client-city", encodeURIComponent(cf.city));
  if (cf.asn !== undefined && cf.asn !== null) headers.set("x-fpc-client-asn", String(cf.asn));
  headers.set("x-fpc-forwarded-host", new URL(request.url).host);
  return headers;
}

function downstream(res: Response): Response {
  const headers = new Headers(res.headers);
  headers.delete("set-cookie");
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function serveAgent(env: Env, ctx: ExecutionContext, request: Request): Promise<Response> {
  const cache = caches.default;
  const key = new Request(request.url, { method: "GET" });
  const hit = await cache.match(key);
  if (hit) return hit;
  let upstream: Response;
  try {
    upstream = await fetch(new Request(env.FPC_AGENT_URL || DEFAULT_AGENT_URL, { method: "GET" }));
  } catch {
    return text("fpchecker proxy: agent unavailable", 502);
  }
  const res = downstream(upstream);
  if (upstream.status !== 200) return res;
  res.headers.set("cache-control", `public, max-age=${AGENT_CACHE_SECONDS}`);
  ctx.waitUntil(cache.put(key, res.clone()));
  return res;
}

async function serveApi(env: Env, request: Request, route: string, secret: string): Promise<Response> {
  const base = (env.FPC_API || DEFAULT_API).replace(/\/+$/, "");
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const out = new Request(`${base}/${route}`, {
    method: request.method,
    headers: upstreamHeaders(request, secret),
    body: hasBody ? await request.arrayBuffer() : undefined,
    redirect: "manual",
  });
  try {
    return downstream(await fetch(out));
  } catch {
    return text("fpchecker proxy: upstream unreachable", 502);
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const prefix = trimSlashes(env.FPC_PATH || "fpc");
    const path = trimSlashes(new URL(request.url).pathname);
    if (!path.startsWith(`${prefix}/`)) return text("not found", 404);
    const route = path.slice(prefix.length + 1);
    const isAgent = route === "agent.js";
    if (!isAgent && !API_ROUTE.test(route)) return text("not found", 404);

    const secret = env.FPC_PROXY_SECRET;
    if (!secret) {
      return text("fpchecker proxy misconfigured: FPC_PROXY_SECRET is not set (wrangler secret put FPC_PROXY_SECRET)", 500);
    }
    return isAgent ? serveAgent(env, ctx, request) : serveApi(env, request, route, secret);
  },
};
