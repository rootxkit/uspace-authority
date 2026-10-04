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
//   method needs X-CSRF-Token equal to the CSRF cookie and a body of at
//   most WEB_PROXY_MAX_BODY_BYTES that announces its length. A method a
//   WP-23 route does not take is a 405, but only to a signed-in caller
//   with the CSRF pair: anyone else is refused first (401, 403), so the
//   405 never tells an anonymous caller which methods a route takes.
// - logout: the kit's CSRF check, POST /v1/auth/logout with the bearer,
//   and both cookies cleared whatever api answers.
//
// The picture WebSocket is not proxied: the browser upgrades
// /v1/picture/ws same-origin and the cookie rides the upgrade (M22).
// There is no ticket route.
import { BFF_API_PREFIX, bffHandlers, checkCsrf, MIN_CHALLENGE_SECRET_BYTES, readSessionToken, type BffHandlers } from "@rootxkit/uspace-ui/auth/server";
import { NextResponse } from "next/server";

/** api's sign-in steps and logout (api/openapi.yaml, WP-2). */
export const API_LOGIN_PATH = "/v1/auth/login";
export const API_MFA_PATH = "/v1/auth/mfa";
export const API_LOGOUT_PATH = "/v1/auth/logout";

/** A path the proxy reaches and the methods it is reached with. */
export interface ProxyRoute {
  methods: readonly ("GET" | "POST" | "PUT" | "PATCH")[];
  path: RegExp;
}

const ULID = "[0-7][0-9A-HJKMNP-TV-Z]{25}";

/**
 * A geo-zone's or U-space airspace's identifier: the pattern
 * api/openapi.yaml pins on every /v1/zones/{identifier} and
 * /v1/uspace/{identifier} operation (ED-318's seven characters; the
 * characters this project's identifiers use). zone-identifier.test.ts
 * reads the spec and fails when the two differ.
 */
export const ZONE_IDENTIFIER = "[A-Za-z0-9_-]{1,7}";
const route = (methods: ProxyRoute["methods"], path: string): ProxyRoute => ({ methods, path: new RegExp(`^${path}$`) });

/**
 * WP-23's pages (api/openapi.yaml, each with its operation's method):
 * violations, incidents and evidence packs, occurrences, sources, the
 * audit log and the DPO report, the police realm, and the two public
 * reads. A path here is refused with any other method before api (405).
 */
export const OVERSIGHT_PROXY_ROUTES: readonly ProxyRoute[] = [
  route(["GET"], "/v1/violations"),
  route(["GET"], `/v1/violations/${ULID}`),
  route(["POST"], `/v1/violations/${ULID}/review`),
  route(["GET", "POST"], "/v1/incidents"),
  route(["GET", "PATCH"], `/v1/incidents/${ULID}`),
  route(["POST"], `/v1/incidents/${ULID}/evidence-packs`),
  route(["GET"], `/v1/incidents/${ULID}/evidence-packs/${ULID}`),
  route(["GET"], `/v1/incidents/${ULID}/evidence-packs/${ULID}/download`),
  route(["GET"], `/v1/incidents/${ULID}/evidence-packs/${ULID}/verify`),
  route(["GET"], "/v1/occurrences"),
  route(["POST"], "/v1/occurrences/export"),
  route(["GET"], `/v1/occurrences/${ULID}`),
  route(["GET"], `/v1/occurrences/${ULID}/reporter`),
  route(["POST"], `/v1/occurrences/${ULID}/classify`),
  route(["PATCH"], `/v1/occurrences/${ULID}/analysis`),
  route(["GET"], "/v1/sources"),
  route(["PUT"], "/v1/sources/(?:direct_rid|network_rid|ansp_feed)"),
  route(["PUT"], "/v1/sources/(?:direct_rid|network_rid|ansp_feed)/[A-Za-z0-9][A-Za-z0-9_-]{0,62}"),
  route(["GET"], "/v1/audit/events"),
  route(["GET"], "/v1/audit/verify"),
  route(["GET"], "/v1/audit/dpo-report"),
  route(["GET"], "/v1/police/aircraft"),
  route(["GET"], "/v1/police/operators/[^/]{1,64}"),
  route(["GET"], "/v1/police/serials/[^/]{1,64}"),
  route(["POST"], "/v1/police/exports"),
  route(["GET"], `/v1/police/exports/${ULID}/download`),
  route(["GET"], "/v1/registry/check"),
  route(["GET"], "/v1/certificates/register"),
];

/**
 * What the console may reach through the proxy, and nothing else: the
 * caller's session (who is signed in, for the shell), the zones (the
 * inspector map's zone layer), WP-22's authoring operations and WP-23's
 * routes. A later page adds its paths here in its own work package.
 * Every pattern is anchored; an identifier segment admits only the
 * characters api's identifiers use.
 */
export const PROXY_ALLOW_PATHS: readonly RegExp[] = [
  /^\/v1\/auth\/session$/,
  /^\/v1\/zones$/,
  // WP-22: the registry, zone and U-space authoring, publications and
  // certificates (api/openapi.yaml). The registry's machine and public
  // operations (validate, changes, check, the portal's submit and
  // verify, operator links) are not the console's and are not here.
  /^\/v1\/registry\/(operators|uas|pilots)$/,
  /^\/v1\/registry\/(operators|uas|pilots)\/[A-Za-z0-9_-]{1,64}(\/(status|personal-data|competencies))?$/,
  /^\/v1\/registry\/import$/,
  /^\/v1\/registry\/applications$/,
  /^\/v1\/registry\/applications\/[A-Za-z0-9_-]{1,64}\/(personal-data|review|approve|refuse)$/,
  /^\/v1\/zones\/(export|import|publish)$/,
  new RegExp(`^/v1/zones/${ZONE_IDENTIFIER}(/(approve|versions|applies))?$`),
  /^\/v1\/uspace(\/publish)?$/,
  new RegExp(`^/v1/uspace/${ZONE_IDENTIFIER}(/(designate|versions))?$`),
  /^\/v1\/publications$/,
  /^\/v1\/certificates(\/(register|publish-list))?$/,
  /^\/v1\/certificates\/[0-9a-f]{32}(\/(status-notices|suspend|limit|revoke|reinstate))?$/,
  ...OVERSIGHT_PROXY_ROUTES.map((r) => r.path),
];

/**
 * The largest request body the proxy forwards, bytes
 * (WEB_PROXY_MAX_BODY_BYTES): api's own largest, the registry import's
 * REGISTRY_IMPORT_MAX_BYTES default. A larger body is the BFF's 413 and
 * never reaches api; api still bounds each operation itself.
 */
export const DEFAULT_PROXY_MAX_BODY_BYTES = 8 * 1024 * 1024;

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * The proxy with its body bound: an unsafe method must announce its
 * length (411 otherwise) and stay within `maxBytes` (413 otherwise),
 * checked before api is called. The browser's fetch announces the length
 * of every body the console sends. It runs after the allow-list
 * (`createBff`): a path outside it is the 404, whatever its body.
 */
export function boundedProxy(proxy: BffHandlers["proxy"], maxBytes: number): BffHandlers["proxy"] {
  return (req) => {
    if (!UNSAFE.has(req.method)) return proxy(req);
    const declared = req.headers.get("content-length");
    if (declared === null) {
      return Promise.resolve(problem(411, "length_required", "Length required", "a request body must announce its Content-Length"));
    }
    if (!/^\d+$/.test(declared.trim()) || Number(declared) > maxBytes) {
      return Promise.resolve(problem(413, "body_too_large", "Request body too large", `at most ${maxBytes} bytes (WEB_PROXY_MAX_BODY_BYTES)`));
    }
    return proxy(req);
  };
}

/**
 * True when `pathname` is one of WP-23's routes and none of them admits
 * `method`: the proxy refuses it before api (fail closed). A path of
 * another work package is left to its own list.
 */
export function methodRefused(method: string, pathname: string): boolean {
  const routes = OVERSIGHT_PROXY_ROUTES.filter((r) => r.path.test(pathname));
  return routes.length > 0 && !routes.some((r) => (r.methods as readonly string[]).includes(method));
}

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
  /** The largest body the proxy forwards (WEB_PROXY_MAX_BODY_BYTES); DEFAULT_PROXY_MAX_BODY_BYTES when absent. */
  proxyMaxBodyBytes?: number;
  fetch?: typeof fetch;
}

/** The three handlers for one configuration. */
export function createBff(cfg: BffConfig): BffHandlers {
  const kit = kitHandlers(cfg);
  const bounded = boundedProxy(kit.proxy, cfg.proxyMaxBodyBytes ?? DEFAULT_PROXY_MAX_BODY_BYTES);
  return {
    ...kit,
    proxy: (req) => {
      const path = req.nextUrl.pathname.startsWith(BFF_API_PREFIX) ? req.nextUrl.pathname.slice(BFF_API_PREFIX.length) : "";
      // The allow-list first: the kit answers its 404 (and counts it)
      // without calling api, so an unknown path is never the bound's 411
      // or 413.
      if (!PROXY_ALLOW_PATHS.some((re) => re.test(path))) return kit.proxy(req);
      if (methodRefused(req.method, path)) {
        // Unauthenticated first: an anonymous caller is told only that,
        // whatever the method (api's own 401, with api's slug).
        if (readSessionToken(req, SESSION) === null) {
          return Promise.resolve(problem(401, "unauthenticated", "Unauthenticated", "no session"));
        }
        if (!checkCsrf(req, SESSION)) {
          return Promise.resolve(problem(403, "csrf_refused", "CSRF check failed", "send the uspace_csrf cookie's value as X-CSRF-Token"));
        }
        return Promise.resolve(problem(405, "method_not_allowed", "Method not allowed", `${req.method} is not served on this path`));
      }
      return bounded(req);
    },
  };
}

/** The session and CSRF cookies' names: the contract's defaults, which kitHandlers keeps (it names neither). */
const SESSION = {};

function kitHandlers(cfg: BffConfig): BffHandlers {
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
  const maxBody = positiveInt(env, "WEB_PROXY_MAX_BODY_BYTES", DEFAULT_PROXY_MAX_BODY_BYTES);
  for (const v of [maxAge, timeout, hops, maxBody]) if (typeof v === "string") return { problem: v };
  return {
    apiBase,
    mfaChallengeSecret: secret,
    sessionMaxAgeS: maxAge as number,
    timeoutMs: timeout as number,
    proxyMaxBodyBytes: maxBody as number,
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
