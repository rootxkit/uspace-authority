# WP-2: console authentication and the ecosystem token service

Branch `feat/WP-2-auth-tokens`. Milestone A-M1 (console auth), A-M4
(token service proven with the DP). Owns `internal/authz`,
`internal/tokens`, the migrations for `users`, `user_credentials`,
`user_mfa`, `sessions`, `oauth_clients`, `signing_keys`, and the routes
`/v1/auth/*`, `/v1/users*`, `/oauth/*`, `/.well-known/*`,
`/v1/oauth/*`. Depends on WP-1. Consumers: every API group (roles and
scopes), WP-6 (client credentials to the CISP), WP-14 (DSS tokens),
WP-16 (clients from certificates), WP-19 (police realm), WP-21 (BFF),
and every sibling system (the tables below are the ecosystem's).

This WP is safety-relevant for the ecosystem: a wrong issuer lets a
rogue host be a USSP. It is reviewed adversarially.

This WP gates nobody: every repo verifies against any allow-listed
issuer, and the lab issuer (`core/auth.Issuer` with client `lab-01`,
lab WP-L2) stands in for this service until A-M4.

## Read first

1. `docs/PLAN.md` §5 (auth rows), §7, §14 Q-A16.
2. Spec `00 §6.2` (JWT), `01 §1` users table, `06 §2` T3, T4, T5, T6,
   `06 §3`, `06 §4` (no key in the repo). The cross-plan reconciliation
   of 2026-10-02 (M18, M20, M21, M22, M23, M24) amends `06 §3` and
   `02 §1`; the lab's spec errata (WP-L4) carry it into the spec.
3. `uspace-core/auth`: `NewVerifier`, `Config`, `Claims`, `RequireScope`,
   `NewIssuer`, `Issuer.Issue`, `Issuer.JWKS`, and `auth/vectors_test.go`
   for `jwt_verify.json`. Core verifies and signs; this WP owns keys,
   clients, rotation, audiences and audit.
4. LESSONS E-14 (shared work on its own context), B-14, E-10, S-15
   (login limits, via utm `api/tests/test_login_rate_limit.py` as
   reference).
5. Reference only: utm `api/auth.py`, `api/auth_http.py`,
   `docs/runbooks/p6-08-operator-auth.md`.

## Normative tables

These two tables are the ecosystem's contract. Every sibling repo
verifies against them, and a sibling that needs a new scope, claim or
audience rule opens a pull request here first. `api/openapi.yaml` and
`docs/runbooks/token-service.md` restate them; a test in this WP loads
the scope catalogue from one place and refuses anything else.

### A. The JWT contract (every token in the ecosystem)

| Token | `iss` | `aud` | `sub` | `scope` | Other claims | TTL |
|---|---|---|---|---|---|---|
| Ecosystem machine token (this issuer) | this deployment's issuer URL | **host of the target's published base URL** (`uspace-cisp.chikox.net`, the DSS's host, a peer's `uss_base_url` host, the ANSP's host, this host) | client id `<system>-<code>-<nn>` | space-separated catalogue scopes (table B) | `exp`, `iat`, `jti`, `kid` | ≤ 1 h |
| Operator machine token (a USSP's issuer, not this one) | the USSP's issuer URL | the USSP's host | operator client id | `ussp.intents ussp.telemetry ussp.traffic ussp.geo` | `exp`, `iat`, `jti`, `kid` | ≤ 1 h |
| Console / portal session (every system) | the system's own issuer URL | the system's own host | account id | `session` | `roles: [..]`, `realm` (`console` / `police` here; `portal` at a USSP), `exp`, `iat`, `jti` = session id, `kid` | ≤ 12 h, idle 30 min |
| Webhook / direct-delivery JWS (`application/jose`) | the CISP's or the ANSP's issuer URL | host of the `callback_url` / target base URL | subscription id (CISP) or restriction id (ANSP) | — | payload = `cis/change/v1`, `iat`, `jti` = delivery id | single use |
| Detached publication JWS (`X-JWS-Signature`) | — (key by `kid` from the publisher's JWKS) | — | — | — | protected header `alg RS256`, `kid`, `iat` (≤ 5 min), `b64: false`, `crit: ["b64"]` | — |

Every verifier in every system: `core/auth.Verifier`, RS256 only,
allow-listed issuers with JWKS URLs, a configured `*_AUDIENCES` list
(the system's own public host plus a lab alias such as the compose
service name), 30 s skew, `jti` required, scope per endpoint. A
system id is never an audience: `USSP_SYSTEM_ID` is the certificate
code (M8), not an `aud` value.

Why hosts (M18): F3411 and F3548 discovery yield only a `uss_base_url`,
so a system-id audience cannot be derived for an ISA notification or a
peer call to a third-party USSP, and InterUSS tooling (the DSS's
`accepted_jwt_audiences`, `uss_qualifier`) uses hostnames.

### B. The scope catalogue

| Family | Scopes | Issued to |
|---|---|---|
| CIS (`06 §3`) | `cis.read`, `cis.publish:zones`, `cis.publish:uspace`, `cis.publish:ussp_list`, `cis.publish:restrictions`, `cis.publish:ats_data` (reserved until the Annex V SLA names the items; never issued) | subscribers; the authority (`zones`, `uspace`, `ussp_list`); the ANSP (`restrictions`) |
| Authority (`06 §3`) | `registry.validate`, `ussp.records`, `occurrences.write`, `certificates.status`, `police.query` | USSPs; the ANSP (`occurrences.write`); police accounts (`police.query`, inside a session) |
| ANSP | `ansp.traffic` (`06 §3`), `ansp.coordination`, `ansp.requests` (added, M23) | the authority and USSPs (`ansp.traffic`); USSPs (`ansp.coordination`); the authority (`ansp.requests`, F11) |
| Lab only | `dp.observe` (the conformance hook, Q-A7) | `lab-01` only; refused to every other client |
| F3548 (standard) | `utm.strategic_coordination`, `utm.constraint_processing`, `utm.constraint_management`, `utm.conformance_monitoring_sa`, `utm.availability_arbitration` | USSPs per their services; the ANSP (`constraint_management`); the authority (`availability_arbitration`, and `conformance_monitoring_sa` for its own DSS reads, Q-A5) |
| F3411 (standard) | `rid.service_provider`, `rid.display_provider` | USSPs (`service_provider`); the authority (`display_provider`) |
| At a USSP's issuer only, never here | `ussp.intents`, `ussp.telemetry`, `ussp.traffic`, `ussp.geo` | operator clients of that USSP |

Not JWT scopes: receiver authentication (`rid.observe` is retired; the
F9 receiver endpoint uses a bearer key plus body HMAC, WP-7) and console
roles (`roles[]` on a session token). A test refuses any scope outside
this table at client registration and at token request (E-01: beside
one that accepts every row).

For national scopes a client may request only the audiences on its
allowed list; for standard scopes (`utm.*`, `rid.*`) any audience may
be requested, because peers are discovered through the DSS and the CIS
USSP list, not configured (`00 §7`).

Client ids (M24), one per calling system: `authority-01`, `cisp-01`,
`ansp-01`, `ussp-<code>-01` (the code from `certificates.code`, WP-16),
`lab-01`. The CISP binds publishers by `sub` ∈ its configured client
ids; these are the values.

## What to build

### Console accounts (`internal/authz`)

- Users with argon2id credentials (parameters from config, defaults per
  the OWASP recommendation current at implementation time, written in
  the doc comment with the source), TOTP MFA (secret encrypted with the
  PII key; enrolment, verification, recovery codes hashed), roles
  `viewer`, `inspector`, `registrar`, `incident_officer`, `admin`,
  `auditor`, realm `console` or `police` (WP-19 adds agency and
  allow-list), status.
- Login: `POST /v1/auth/login` (username, password) → MFA challenge
  token (short, single-use) → `POST /v1/auth/mfa` → session. Per-user and
  per-IP rate limits (bounded, E-10), constant-time comparisons, no user
  enumeration (same response and timing for unknown user and wrong
  password; test it).
- Sessions: the session JWT of table A (RS256, this issuer, `aud` =
  this system's host, `sub` = account id, `scope = "session"`,
  `roles: [..]`, `realm`, `jti` = session id, TTL 12 h with idle expiry
  30 min), stored by `jti` in `sessions` so logout and admin revocation
  work; `GET /v1/auth/session`; `POST /v1/auth/logout`. The Next.js BFF
  (WP-21) holds the JWT in the `uspace_session` cookie (`HttpOnly;
  Secure; SameSite=Strict`) and forwards it as a bearer; CSRF is the
  `uspace_csrf` cookie echoed in `X-CSRF-Token` (M21). This WP serves
  the bearer side only and documents the cookie contract, the cookie
  names and the same-origin WebSocket rule (the picture upgrade carries
  the cookie and an `Origin` allow-list; no ticket, M22) in
  `docs/runbooks/session-contract.md`. The session is verified by the
  same `core/auth.Verifier` as machine tokens (one verifier, M20).
- Middleware: `RequireRole(roles...)`, `RequireRealm`, `RequireScope`
  (ecosystem tokens through `core/auth.Verifier`), `Purpose` extraction
  for PII reads. Every login, MFA failure, logout, role change and
  revocation is an `events` row.
- Admin routes `/v1/users*` (create, disable, reset MFA, set roles),
  bootstrap of the first admin from an environment variable on an empty
  table (one-shot, logged, refused when users exist).

### Ecosystem token service (`internal/tokens`)

- `signing_keys`: RSA-2048 (minimum) keys loaded from
  `SIGNING_KEY_FILES` (PEM paths) or a KMS reference; the active key
  signs, retiring keys stay in the JWKS until `retired_at + 24 h`
  (JWKS cache TTL). `POST /v1/oauth/keys/rotate` (admin, two-person rule
  by config: a second admin's confirmation within 10 min) activates the
  next key. The JWKS also lists this system's publication-signing key
  (WP-6's detached JWS, `use: sig`, its own `kid`) so the CISP verifies
  publications from the same document (M26). No private key is ever
  written to the database or the repo; tests generate keys at run time
  (`06 §4`).
- `oauth_clients` registry: `client_id` (table B's ids), `system`,
  scopes allow-list, `audiences[]` (hosts, consulted for national
  scopes), `client_secret_post` (argon2id hash, shown once) or
  `private_key_jwt` (client JWKS), `mtls_subject`, `certificate_id`,
  `status`. Scopes are least-privilege per client and limited to table
  B (a test refuses a scope outside it, beside one accepting each row).
- `POST /oauth/token`: client credentials grant; `aud` taken from the
  request's `audience` parameter (or RFC 8707 `resource`) as a host;
  for national scopes it must be on the client's `audiences[]`, for
  `utm.*` / `rid.*` any host is accepted; scopes requested ⊆ allowed;
  TTL ≤ 1 h; `jti` random; `iss` = `ISSUER_URL` from config. Every
  issuance and refusal is an `events` row (`06 §3`). Rate-limited per
  client.
- `GET /.well-known/jwks.json` (cacheable, `Cache-Control: max-age=300`)
  and `GET /.well-known/openid-configuration` with `issuer`,
  `jwks_uri`, `token_endpoint`, `grant_types_supported`.
- `internal/tokens.Client`: the outbound client-credentials helper every
  other WP uses to call the CISP, a USSP, the DSS or the ANSP: audience
  = the host of the target's base URL, pre-fetches at 50 % TTL on its
  own context (E-14, T5), one token per audience, bounded cache.
- Verification wiring: `authz.Verifier` builds `core/auth.Config` with
  `Audiences = AUTHORITY_AUDIENCES` (this host plus the lab alias),
  issuers = this issuer plus the configured CISP and ANSP issuers (for
  `/v1/cis/notifications`, WP-6) plus the lab issuer when configured,
  JWKS URLs from config; `Verifier.Counters` exported to metrics.

## Tests

- Vectors: `jwt_verify.json` through `RunOwned("authority")` against
  the `authz.Verifier` wiring (core already runs them against the
  package; here the test proves this repo's config plumbing reaches the
  same verdicts).
- E-01 pairs: every refusal beside its acceptance (wrong secret, revoked
  client, scope not in table B, scope not allowed for the client,
  national-scope audience not on the client's list, standard-scope
  audience of an unknown host accepted, expired, wrong issuer, HS256
  confusion, `aud` of another host refused by the verifier, missing
  MFA, idle session, revoked session, `scope` other than `session` on
  a cookie token).
- E-02: rotate a key and read the JWKS; a token signed by the retiring
  key still verifies for 24 h and not after; the issuer with no key
  configured refuses to start, naming the variable.
- E-10: session table growth bounded by expiry job; rate limiter maps
  evicted.
- Concurrency under `-race`: parallel logins and token requests.

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] A client created for the lab (`lab-01`), a token for audience
  `uspace-cisp.chikox.net`-shaped host obtained, verified by
  `core/auth` in a second process (integration test spawning the
  verifier side with its own `*_AUDIENCES`), refused after the client is
  suspended.
- [ ] Login → MFA → session → logout round trip; every step an `events`
  row with the right `event_type`; the session token has exactly table
  A's claims.
- [ ] `docs/runbooks/token-service.md`: key generation outside the repo,
  rotation, client onboarding, tables A and B restated, the host-as-
  audience rule with the lab alias.
- [ ] `docs/runbooks/session-contract.md`: cookie names, flags, CSRF
  header, the same-origin WebSocket rule.
- [ ] CHANGELOG line; `doc.go` files.

## Commits

`feat(authz): local console accounts with argon2id, TOTP and sessions [WP-2 A-M1]`,
`feat(tokens): ecosystem OAuth2 client-credentials issuer with JWKS and key rotation [WP-2 A-M4]`,
`feat(tokens): outbound client-credentials helper with early refresh [WP-2 A-M4]`,
`test(authz): run the jwt_verify vector through the authority's verifier wiring [WP-2 A-M4]`.
