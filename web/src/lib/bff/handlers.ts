// The three BFF routes (/_bff/login, /_bff/logout, /_bff/api/*) on the
// kit's helpers (docs/runbooks/session-contract.md; spec 00 §6.2, 06 §3).
// Nothing else runs on the server: no database, no bus, no key, no
// judgement. The BFF never verifies a token; api decides every request.
//
// - login: POST /v1/auth/login {username, password} answers the MFA
//   challenge, which the kit seals into the HttpOnly `uspace_mfa` cookie
//   (Path=/_bff) under WEB_MFA_CHALLENGE_SECRET; the browser's second
//   request {username, otp} becomes POST /v1/auth/mfa {mfa_token, code}.
//   The session JWT goes into `uspace_session` (HttpOnly, Secure,
//   SameSite=Strict) and a fresh double-submit value into `uspace_csrf`.
//   The page never sees the JWT.
// - proxy: /_bff/api/<path> is forwarded to api with the session cookie
//   as the bearer, for the paths in PROXY_ALLOW_PATHS only (fail closed:
//   anything else is a 404 of the BFF and never reaches api); an unsafe
//   method needs X-CSRF-Token equal to the CSRF cookie.
// - logout: the kit's CSRF check, POST /v1/auth/logout with the bearer,
//   and both cookies cleared whatever api answers.
//
// The picture WebSocket is not proxied: the browser upgrades
// /v1/picture/ws same-origin and the cookie rides the upgrade (M22).
// There is no ticket route.
import { bffHandlers, MIN_CHALLENGE_SECRET_BYTES, type BffHandlers } from "@rootxkit/uspace-ui/auth/server";
import { NextResponse } from "next/server";

/** api's sign-in steps and logout (api/openapi.yaml, WP-2). */
export const API_LOGIN_PATH = "/v1/auth/login";
export const API_MFA_PATH = "/v1/auth/mfa";
export const API_LOGOUT_PATH = "/v1/auth/logout";

/**
 * What the console may reach through the proxy, and nothing else: the
 * caller's session (who is signed in, for the shell) and the published
 * zones (the inspector map's zone layer). A later page adds its paths
 * here in its own work package.
 */
export const PROXY_ALLOW_PATHS: readonly RegExp[] = [/^\/v1\/auth\/session$/, /^\/v1\/zones$/];

export interface BffConfig {
  /** api as the web container reaches it (WEB_API_INTERNAL_URL). */
  apiBase: string;
  /** The ceiling of the session cookie's Max-Age, seconds (WEB_SESSION_MAX_AGE_S). */
  sessionMaxAgeS: number;
  /** The upstream timeout of every call, ms (WEB_UPSTREAM_TIMEOUT_MS). */
  timeoutMs: number;
  /** Reverse proxies in front of Next.js (WEB_TRUSTED_PROXY_HOPS). */
  trustedProxyHops?: number;
  /** Seals the MFA challenge cookie (WEB_MFA_CHALLENGE_SECRET, at least 32 bytes). */
  mfaChallengeSecret: string;
  fetch?: typeof fetch;
}

/** The three handlers for one configuration. */
export function createBff(cfg: BffConfig): BffHandlers {
  return bffHandlers({
    apiBase: cfg.apiBase,
    apiLoginPath: API_LOGIN_PATH,
    apiMfaPath: API_MFA_PATH,
    apiLogoutPath: API_LOGOUT_PATH,
    mfaChallengeSecret: cfg.mfaChallengeSecret,
    session: { secure: true, maxAgeS: cfg.sessionMaxAgeS },
    allowPaths: [...PROXY_ALLOW_PATHS],
    timeoutMs: cfg.timeoutMs,
    // Without WEB_TRUSTED_PROXY_HOPS no proxy in front of Next.js is
    // trusted to record the client: api is sent no client address (the
    // kit requires the choice to be said, retro-audit S6).
    ...(cfg.trustedProxyHops === undefined ? { noTrustedProxy: true as const } : { trustedProxyHops: cfg.trustedProxyHops }),
    ...(cfg.fetch === undefined ? {} : { fetch: cfg.fetch }),
  });
}

type Env = Record<string, string | undefined>;

function positiveInt(env: Env, name: string, fallback: number): number | string {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) return `${name}: want a whole number of at least 1, got ${JSON.stringify(raw)}`;
  return n;
}

/**
 * The BFF's configuration from the environment, or what is wrong with
 * it, naming the variable. Without a configuration every BFF route
 * answers 503 naming it (fail closed: there is no sign-in without the
 * MFA step and no proxy without its upstream).
 */
export function configFromEnv(env: Env): BffConfig | { problem: string } {
  const apiBase = env["WEB_API_INTERNAL_URL"] ?? "";
  if (apiBase === "") return { problem: "WEB_API_INTERNAL_URL is not set" };
  try {
    const u = new URL(apiBase);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("scheme");
  } catch {
    return { problem: `WEB_API_INTERNAL_URL: want an http or https URL, got ${JSON.stringify(apiBase)}` };
  }
  const secret = env["WEB_MFA_CHALLENGE_SECRET"] ?? "";
  if (new TextEncoder().encode(secret).length < MIN_CHALLENGE_SECRET_BYTES) {
    return { problem: `WEB_MFA_CHALLENGE_SECRET is not set or shorter than ${MIN_CHALLENGE_SECRET_BYTES} bytes` };
  }
  // A display-side ceiling only: api's session lifetime (<= 12 h) shortens it through expires_at.
  const maxAge = positiveInt(env, "WEB_SESSION_MAX_AGE_S", 12 * 3600);
  const timeout = positiveInt(env, "WEB_UPSTREAM_TIMEOUT_MS", 10_000);
  const hopsRaw = env["WEB_TRUSTED_PROXY_HOPS"];
  const hops = hopsRaw === undefined || hopsRaw === "" ? undefined : positiveInt(env, "WEB_TRUSTED_PROXY_HOPS", 1);
  for (const v of [maxAge, timeout, hops]) if (typeof v === "string") return { problem: v };
  return {
    apiBase,
    mfaChallengeSecret: secret,
    sessionMaxAgeS: maxAge as number,
    timeoutMs: timeout as number,
    ...(hops === undefined ? {} : { trustedProxyHops: hops as number }),
  };
}

/** A problem of the BFF itself, in the shape api uses (M28). */
function problem(status: number, slug: string, title: string, detail: string): NextResponse {
  return NextResponse.json(
    { type: `https://schemas.uspace.ge/problems/${slug}`, title, status, detail },
    { status, headers: { "Content-Type": "application/problem+json", "Cache-Control": "no-store" } },
  );
}

let cached: BffHandlers | null = null;

/** The handlers for this process, built at the first request (the build has no environment). */
export function bff(): BffHandlers {
  if (cached !== null) return cached;
  const cfg = configFromEnv(process.env);
  if ("problem" in cfg) {
    const off = () => Promise.resolve(problem(503, "bff_unavailable", "Console unavailable", cfg.problem));
    return { login: off, logout: off, proxy: off };
  }
  cached = createBff(cfg);
  return cached;
}
