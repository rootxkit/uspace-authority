// The BFF on the kit's handlers with a fake api: the two-step sign-in
// sets the contract's cookies and never answers the token; the proxy
// forwards its allow-list with the bearer and refuses everything else
// before api; logout tells api and clears both cookies whatever api
// answers, and only with the CSRF pair; a configuration that is missing
// a part answers 503 naming the variable. Each refusal beside the
// acceptance it differs from (E-01).
import { NextRequest } from "next/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { configFromEnv, createBff, PROXY_ALLOW_PATHS, type BffConfig } from "./handlers";

const ORIGIN = "https://console.test";
const SECRET = "unit-test-only-challenge-seal-key-0123456789";

interface Call {
  url: string;
  method: string;
  auth: string | null;
  xff: string | null;
  body: unknown;
}

function fakeApi(): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const f: typeof fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const headers = new Headers(init?.headers);
    const text = typeof init?.body === "string" ? init.body : null;
    calls.push({ url, method: init?.method ?? "GET", auth: headers.get("authorization"), xff: headers.get("x-forwarded-for"), body: text === null ? null : JSON.parse(text) });
    const path = new URL(url).pathname;
    const exp = new Date(Date.now() + 3600_000).toISOString();
    if (path === "/v1/auth/login") return Response.json({ mfa_token: "challenge-1", expires_at: new Date(Date.now() + 300_000).toISOString() });
    if (path === "/v1/auth/mfa") {
      const b = JSON.parse(text ?? "{}") as { code?: string };
      if (b.code !== "246810") return Response.json({ type: "https://schemas.uspace.ge/problems/mfa_refused", title: "x", status: 401 }, { status: 401 });
      return Response.json({ token: "header.payload.sig", token_type: "Bearer", expires_at: exp, idle_timeout_s: 1800, session: {} });
    }
    if (path === "/v1/auth/session") return Response.json({ sub: "u1" });
    return Response.json({ path }, { status: 200 });
  };
  return { fetch: f, calls };
}

function cfg(f: typeof fetch): BffConfig {
  return { apiBase: "http://api.internal:8080", sessionMaxAgeS: 43200, timeoutMs: 5000, mfaChallengeSecret: SECRET, fetch: f };
}

function post(path: string, body: unknown, cookie = ""): NextRequest {
  return new NextRequest(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, host: "console.test", ...(cookie === "" ? {} : { cookie }) },
    body: JSON.stringify(body),
  });
}

function cookiesOf(res: Response): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const [k, ...v] = (pair ?? "").split("=");
    out.set(k ?? "", line);
    void v;
  }
  return out;
}

describe("sign-in", () => {
  it("password then code: the session cookie is HttpOnly, Secure, SameSite=Strict, and the token is not in the answer", async () => {
    const api = fakeApi();
    const bff = createBff(cfg(api.fetch));
    const first = await bff.login(post("/_bff/login", { username: "inspector1", password: "pw" }));
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ status: "mfa_required" });
    const challenge = cookiesOf(first).get("uspace_mfa") ?? "";
    expect(challenge).toMatch(/HttpOnly/i);
    expect(challenge).toMatch(/Path=\/_bff/);
    const sealed = challenge.split(";")[0] ?? "";

    const second = await bff.login(post("/_bff/login", { username: "inspector1", otp: "246810" }, sealed));
    expect(second.status).toBe(200);
    const body = await second.text();
    expect(body).not.toContain("header.payload.sig");
    const c = cookiesOf(second);
    expect(c.get("uspace_session")).toMatch(/HttpOnly/i);
    expect(c.get("uspace_session")).toMatch(/Secure/i);
    expect(c.get("uspace_session")).toMatch(/SameSite=Strict/i);
    expect(c.get("uspace_csrf")).not.toMatch(/HttpOnly/i);
    // What reached api: the password once, then the challenge and the code.
    expect(api.calls.map((x) => [new URL(x.url).pathname, Object.keys(x.body as object).sort()])).toEqual([
      ["/v1/auth/login", ["password", "username"]],
      ["/v1/auth/mfa", ["code", "mfa_token"]],
    ]);
  });

  it("a code without the password step is refused before api", async () => {
    const api = fakeApi();
    const res = await createBff(cfg(api.fetch)).login(post("/_bff/login", { username: "inspector1", otp: "246810" }));
    expect(res.status).toBe(401);
    expect(api.calls).toEqual([]);
  });

  it("a cross-origin sign-in is refused before api", async () => {
    const api = fakeApi();
    const req = new NextRequest(`${ORIGIN}/_bff/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://elsewhere.test", host: "console.test" },
      body: JSON.stringify({ username: "a", password: "b" }),
    });
    expect((await createBff(cfg(api.fetch)).login(req)).status).toBe(403);
    expect(api.calls).toEqual([]);
  });
});

describe("proxy", () => {
  const get = (path: string, cookie = "uspace_session=header.payload.sig") =>
    new NextRequest(`${ORIGIN}/_bff/api${path}`, { method: "GET", headers: { cookie, host: "console.test" } });

  it("forwards an allowed path with the session as the bearer", async () => {
    const api = fakeApi();
    const res = await createBff(cfg(api.fetch)).proxy(get("/v1/auth/session"));
    expect(res.status).toBe(200);
    expect(api.calls).toHaveLength(1);
    expect(api.calls[0]?.url).toBe("http://api.internal:8080/v1/auth/session");
    expect(api.calls[0]?.auth).toBe("Bearer header.payload.sig");
  });

  it("refuses a path outside the allow-list before api (fail closed)", async () => {
    const api = fakeApi();
    for (const p of ["/v1/users", "/v1/zones/TSTP001", "/v1/auth/sessionx", "/v1/picture/ws"]) {
      expect((await createBff(cfg(api.fetch)).proxy(get(p))).status, p).toBe(404);
    }
    expect(api.calls).toEqual([]);
  });

  it("without WEB_TRUSTED_PROXY_HOPS api gets no client address, whatever the client wrote", async () => {
    const api = fakeApi();
    const req = new NextRequest(`${ORIGIN}/_bff/api/v1/auth/session`, {
      method: "GET",
      headers: { cookie: "uspace_session=header.payload.sig", host: "console.test", "x-forwarded-for": "198.51.100.7, 203.0.113.9" },
    });
    expect((await createBff(cfg(api.fetch)).proxy(req)).status).toBe(200);
    expect(api.calls[0]?.xff).toBeNull();
  });

  it("with one trusted hop api gets the address that hop recorded, not the client's own entry (the pair above)", async () => {
    const api = fakeApi();
    const req = new NextRequest(`${ORIGIN}/_bff/api/v1/auth/session`, {
      method: "GET",
      headers: { cookie: "uspace_session=header.payload.sig", host: "console.test", "x-forwarded-for": "198.51.100.7, 203.0.113.9" },
    });
    expect((await createBff({ ...cfg(api.fetch), trustedProxyHops: 1 }).proxy(req)).status).toBe(200);
    expect(api.calls[0]?.xff).toBe("203.0.113.9");
  });

  it("the allow-list is anchored", () => {
    expect(PROXY_ALLOW_PATHS.every((re) => re.source.startsWith("^") && re.source.endsWith("$"))).toBe(true);
  });
});

describe("configuration", () => {
  const good = { WEB_API_INTERNAL_URL: "http://api:8080", WEB_MFA_CHALLENGE_SECRET: SECRET };

  it("a complete environment is a configuration (the pair of the refusals below)", () => {
    expect(configFromEnv(good)).toMatchObject({ apiBase: "http://api:8080", sessionMaxAgeS: 43200, timeoutMs: 10000 });
  });

  it("names what is missing or wrong", () => {
    expect(configFromEnv({ ...good, WEB_API_INTERNAL_URL: "" })).toEqual({ problem: "WEB_API_INTERNAL_URL is not set" });
    expect(configFromEnv({ ...good, WEB_API_INTERNAL_URL: "ftp://x" })).toHaveProperty("problem");
    expect(configFromEnv({ ...good, WEB_MFA_CHALLENGE_SECRET: "short" })).toHaveProperty("problem");
    expect(configFromEnv({ ...good, WEB_TRUSTED_PROXY_HOPS: "0" })).toEqual({
      problem: 'WEB_TRUSTED_PROXY_HOPS: want a whole number of at least 1, got "0"',
    });
  });
});

describe("logout", () => {
  const CSRF = "csrf-value-1";
  const logoutReq = (headers: Record<string, string>) =>
    new NextRequest(`${ORIGIN}/_bff/logout`, { method: "POST", headers: { origin: ORIGIN, host: "console.test", ...headers } });
  const signedIn = { cookie: `uspace_session=header.payload.sig; uspace_csrf=${CSRF}` };

  /** Whether the answer clears a cookie: an empty value that expires at once. */
  function cleared(res: Response, name: string): boolean {
    const line = cookiesOf(res).get(name) ?? "";
    return line.startsWith(`${name}=;`) && /Max-Age=0/i.test(line);
  }

  it("with the CSRF pair: tells api with the bearer and clears both cookies", async () => {
    const api = fakeApi();
    const res = await createBff(cfg(api.fetch)).logout(logoutReq({ ...signedIn, "x-csrf-token": CSRF }));
    expect(res.status).toBe(204);
    expect(api.calls.map((c) => [new URL(c.url).pathname, c.method, c.auth])).toEqual([["/v1/auth/logout", "POST", "Bearer header.payload.sig"]]);
    expect(cleared(res, "uspace_session")).toBe(true);
    expect(cleared(res, "uspace_csrf")).toBe(true);
    expect(cookiesOf(res).get("uspace_session")).toMatch(/HttpOnly/i);
  });

  it("clears both cookies whatever api answers: an error, or api unreachable", async () => {
    const failing: typeof fetch = () => Promise.resolve(Response.json({ status: 500 }, { status: 500 }));
    const down: typeof fetch = () => Promise.reject(new TypeError("fetch failed"));
    for (const f of [failing, down]) {
      const res = await createBff(cfg(f)).logout(logoutReq({ ...signedIn, "x-csrf-token": CSRF }));
      expect(res.status).toBe(204);
      expect(cleared(res, "uspace_session")).toBe(true);
      expect(cleared(res, "uspace_csrf")).toBe(true);
    }
  });

  it("without the CSRF pair is refused before api and clears nothing (the pair of the first)", async () => {
    for (const headers of [signedIn, { ...signedIn, "x-csrf-token": "another-value" }, { "x-csrf-token": CSRF }]) {
      const api = fakeApi();
      const res = await createBff(cfg(api.fetch)).logout(logoutReq(headers));
      expect(res.status).toBe(403);
      expect(api.calls).toEqual([]);
      expect(res.headers.getSetCookie()).toEqual([]);
    }
  });
});

describe("bff(): fail closed", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  /** bff() of a fresh module (it caches a good configuration) under this environment. */
  async function bffUnder(env: Record<string, string>) {
    vi.resetModules();
    for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v);
    return (await import("./handlers")).bff();
  }

  const requests = () => ({
    login: post("/_bff/login", { username: "inspector1", password: "pw" }),
    logout: new NextRequest(`${ORIGIN}/_bff/logout`, { method: "POST", headers: { origin: ORIGIN, host: "console.test" } }),
    proxy: new NextRequest(`${ORIGIN}/_bff/api/v1/auth/session`, { method: "GET", headers: { cookie: "uspace_session=x", host: "console.test" } }),
  });

  for (const [missing, env] of [
    ["WEB_API_INTERNAL_URL", { WEB_API_INTERNAL_URL: "", WEB_MFA_CHALLENGE_SECRET: SECRET }],
    ["WEB_MFA_CHALLENGE_SECRET", { WEB_API_INTERNAL_URL: "http://api.internal:8080", WEB_MFA_CHALLENGE_SECRET: "short" }],
  ] as const) {
    it(`every route answers 503 naming ${missing}, and nothing reaches api`, async () => {
      const upstream = vi.spyOn(globalThis, "fetch");
      const handlers = await bffUnder(env);
      const r = requests();
      for (const [name, res] of [
        ["login", await handlers.login(r.login)],
        ["logout", await handlers.logout(r.logout)],
        ["proxy", await handlers.proxy(r.proxy)],
      ] as const) {
        expect(res.status, name).toBe(503);
        expect(res.headers.get("content-type"), name).toBe("application/problem+json");
        expect(res.headers.get("cache-control"), name).toBe("no-store");
        const body = (await res.json()) as { type: string; status: number; detail: string };
        expect(body.type, name).toBe("https://schemas.uspace.ge/problems/bff_unavailable");
        expect(body.status, name).toBe(503);
        expect(body.detail, name).toContain(missing);
        expect(res.headers.getSetCookie(), name).toEqual([]);
      }
      expect(upstream).not.toHaveBeenCalled();
    });
  }

  it("a complete environment is served by the kit's handlers, not the 503 (the pair above)", async () => {
    const upstream = vi.spyOn(globalThis, "fetch");
    const handlers = await bffUnder({ WEB_API_INTERNAL_URL: "http://api.internal:8080", WEB_MFA_CHALLENGE_SECRET: SECRET });
    const crossOrigin = new NextRequest(`${ORIGIN}/_bff/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://elsewhere.test", host: "console.test" },
      body: JSON.stringify({ username: "a", password: "b" }),
    });
    expect((await handlers.login(crossOrigin)).status).toBe(403);
    expect((await handlers.logout(requests().logout)).status).toBe(403);
    expect(upstream).not.toHaveBeenCalled();
  });
});
