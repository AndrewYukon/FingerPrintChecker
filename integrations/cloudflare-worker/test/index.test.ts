import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";

const env: Env = { FPC_PROXY_SECRET: "s3cret" };

type Cf = Record<string, unknown>;
function req(path: string, init: RequestInit = {}, cf: Cf = {}): Request {
  const r = new Request(`https://shop.example.com${path}`, init);
  Object.defineProperty(r, "cf", { value: cf });
  return r;
}
const cf = { country: "DE", timezone: "Europe/Berlin", city: "Zürich", asn: 3320 };

let upstream: ReturnType<typeof vi.fn>;
let store: Map<string, Response>;

beforeEach(() => {
  store = new Map();
  upstream = vi.fn(async () => new Response('{"ok":true}', { status: 200 }));
  vi.stubGlobal("fetch", upstream);
  vi.stubGlobal("caches", {
    default: {
      match: async (r: Request) => store.get(r.url)?.clone(),
      put: async (r: Request, res: Response) => void store.set(r.url, res.clone()),
    },
  });
});
afterEach(() => vi.unstubAllGlobals());

const ctx = { waitUntil: (p: Promise<unknown>) => void p, passThroughOnException() {} } as unknown as ExecutionContext;
const call = (r: Request, e: Env = env) => worker.fetch(r, e, ctx);
const sent = () => upstream.mock.calls[0]![0] as Request;

describe("proxy", () => {
  it("forwards method, body, Origin, publishable key and adds trusted headers", async () => {
    const r = req(
      "/fpc/v2/identify",
      {
        method: "POST",
        body: '{"a":1}',
        headers: {
          origin: "https://shop.example.com",
          "x-publishable-key": "pk_1",
          "content-type": "application/json",
          "cf-connecting-ip": "203.0.113.9",
        },
      },
      cf,
    );
    const res = await call(r);
    expect(res.status).toBe(200);
    const s = sent();
    expect(s.url).toBe("https://api.fpchecker.com/v2/identify");
    expect(s.method).toBe("POST");
    expect(await s.text()).toBe('{"a":1}');
    expect(s.headers.get("origin")).toBe("https://shop.example.com");
    expect(s.headers.get("x-publishable-key")).toBe("pk_1");
    expect(s.headers.get("x-fpc-proxy-secret")).toBe("s3cret");
    expect(s.headers.get("x-fpc-client-ip")).toBe("203.0.113.9");
    expect(s.headers.get("x-fpc-client-country")).toBe("DE");
    expect(s.headers.get("x-fpc-client-timezone")).toBe("Europe/Berlin");
    expect(s.headers.get("x-fpc-client-city")).toBe(encodeURIComponent("Zürich"));
    expect(s.headers.get("x-fpc-client-asn")).toBe("3320");
    expect(s.headers.get("x-fpc-forwarded-host")).toBe("shop.example.com");
  });

  it("routes v1 and v2 challenge and identify", async () => {
    for (const p of ["v1/challenge", "v1/identify", "v2/challenge", "v2/identify"]) {
      upstream.mockClear();
      const res = await call(req(`/fpc/${p}`, { method: "POST", body: "{}" }, cf));
      expect(res.status).toBe(200);
      expect(sent().url).toBe(`https://api.fpchecker.com/${p}`);
    }
  });

  it("strips client-supplied X-FPC-* headers", async () => {
    await call(
      req("/fpc/v2/challenge", {
        method: "POST",
        body: "{}",
        headers: {
          "x-fpc-client-ip": "6.6.6.6",
          "x-fpc-proxy-secret": "guess",
          "x-fpc-client-country": "XX",
          "x-fpc-extra": "1",
          "cf-connecting-ip": "203.0.113.9",
        },
      }, cf),
    );
    const s = sent();
    expect(s.headers.get("x-fpc-client-ip")).toBe("203.0.113.9");
    expect(s.headers.get("x-fpc-proxy-secret")).toBe("s3cret");
    expect(s.headers.get("x-fpc-client-country")).toBe("DE");
    expect(s.headers.get("x-fpc-extra")).toBeNull();
  });

  it("omits geo headers that are unknown and never forwards a spoofed one", async () => {
    await call(req("/fpc/v2/challenge", { method: "POST", body: "{}", headers: { "x-fpc-client-city": "Evil" } }, {}));
    expect(sent().headers.get("x-fpc-client-city")).toBeNull();
    expect(sent().headers.get("x-fpc-client-ip")).toBeNull();
  });

  it("strips Cookie upstream and Set-Cookie downstream", async () => {
    upstream.mockImplementation(async () => {
      const h = new Headers({ "content-type": "application/json" });
      h.append("set-cookie", "a=1");
      return new Response("{}", { status: 200, headers: h });
    });
    const res = await call(req("/fpc/v2/identify", { method: "POST", body: "{}", headers: { cookie: "sid=1" } }, cf));
    expect(sent().headers.get("cookie")).toBeNull();
    expect(res.headers.get("set-cookie")).toBeNull();
    expect(res.headers.get("content-type")).toBe("application/json");
  });

  it("serves agent.js and caches it", async () => {
    upstream.mockImplementation(async () => new Response("/*agent*/", { status: 200, headers: { "content-type": "text/javascript" } }));
    const a = await call(req("/fpc/agent.js"));
    expect(a.status).toBe(200);
    expect(await a.text()).toBe("/*agent*/");
    expect(sent().url).toBe("https://fpchecker.com/static/fp-agent.min.js");
    expect(sent().headers.get("x-fpc-proxy-secret")).toBeNull();
    const b = await call(req("/fpc/agent.js"));
    expect(await b.text()).toBe("/*agent*/");
    expect(upstream).toHaveBeenCalledTimes(1);
  });

  it("does not cache a failed agent.js", async () => {
    upstream.mockImplementation(async () => new Response("no", { status: 502 }));
    const a = await call(req("/fpc/agent.js"));
    expect(a.status).toBe(502);
    await call(req("/fpc/agent.js"));
    expect(upstream).toHaveBeenCalledTimes(2);
  });

  it("404s unknown paths without calling upstream", async () => {
    for (const p of ["/", "/fpc", "/fpc/v3/identify", "/fpc/v2/other", "/other/v2/identify", "/fpc/v2/identify/x"]) {
      expect((await call(req(p, { method: "POST", body: "{}" }, cf))).status).toBe(404);
    }
    expect(upstream).not.toHaveBeenCalled();
  });

  it("passes upstream error status and body through", async () => {
    upstream.mockImplementation(async () => new Response('{"error":"rate"}', { status: 429 }));
    const res = await call(req("/fpc/v2/identify", { method: "POST", body: "{}" }, cf));
    expect(res.status).toBe(429);
    expect(await res.text()).toBe('{"error":"rate"}');
  });

  it("returns 502 when upstream is unreachable", async () => {
    upstream.mockImplementation(async () => { throw new Error("down"); });
    const res = await call(req("/fpc/v2/identify", { method: "POST", body: "{}" }, cf));
    expect(res.status).toBe(502);
  });

  it("500s with a clear message and never forwards when the secret is missing", async () => {
    for (const e of [{} as Env, { FPC_PROXY_SECRET: "" }]) {
      const res = await call(req("/fpc/v2/identify", { method: "POST", body: "{}" }, cf), e);
      expect(res.status).toBe(500);
      expect(await res.text()).toContain("FPC_PROXY_SECRET");
    }
    expect(upstream).not.toHaveBeenCalled();
  });

  it("honours FPC_PATH, FPC_API and FPC_AGENT_URL", async () => {
    const e: Env = { FPC_PROXY_SECRET: "x", FPC_PATH: "/_a/", FPC_API: "https://api.example.test/", FPC_AGENT_URL: "https://cdn.example.test/a.js" };
    await call(req("/_a/v1/identify", { method: "POST", body: "{}" }, cf), e);
    expect(sent().url).toBe("https://api.example.test/v1/identify");
    upstream.mockClear();
    await call(req("/_a/agent.js"), e);
    expect(sent().url).toBe("https://cdn.example.test/a.js");
  });
});
