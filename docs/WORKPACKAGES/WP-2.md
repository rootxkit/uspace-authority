# WP-2: console authentication and the ecosystem token service

Branch `feat/WP-2-auth-tokens`. Milestone A-M1 (console auth), A-M4
(token service proven with the DP). Owns `internal/authz`,
`internal/tokens`, the migrations for `users`, `user_credentials`,
`user_mfa`, `sessions`, `oauth_clients`, `signing_keys`, and the routes
`/v1/auth/*`, `/v1/users*`, `/oauth/*`, `/.well-known/*`,
`/v1/oauth/*`. Depends on WP-1. Consumers: every API group (roles and
scopes), WP-6 (client credentials to the CISP), WP-14 (DSS tokens),
WP-16 (clients from certificates), WP-19 (police realm), WP-21 (BFF).

This WP is safety-relevant for the ecosystem: a wrong issuer lets a
rogue host be a USSP. It is reviewed adversarially.

## Read first

1. `docs/PLAN.md` §5 (auth rows), §7.
2. Spec `00 §6.2` (JWT), `01 §1` users table, `06 §2` T3, T4, T5, T6,
   `06 §3`, `06 §4` (no key in the repo).
3. `uspace-core/auth`: `NewVerifier`, `Config`, `Claims`, `RequireScope`,
   `NewIssuer`, `Issuer.Issue`, `Issuer.JWKS`, and `auth/vectors_test.go`
   for `jwt_verify.json`. Core verifies and signs; this WP owns keys,
   clients, rotation, audiences and audit.
4. LESSONS E-14 (shared work on its own context), B-14, E-10, S-15
   (login limits, via utm `api/tests/test_login_rate_limit.py` as
   reference).
5. Reference only: utm `api/auth.py`, `api/auth_http.py`,
   `docs/runbooks/p6-08-operator-auth.md`.

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
- Sessions: a session JWT (RS256, this issuer, `aud` = `console`,
  `realm`, `roles`, `sid`, TTL 12 h with idle expiry 30 min) stored by
  `sid` in `sessions` so logout and admin revocation work; `GET
  /v1/auth/session`; `POST /v1/auth/logout`. The Next.js BFF (WP-21)
  holds the JWT in an `HttpOnly` cookie and forwards it as a bearer; this
  WP serves the bearer side only and documents the cookie contract
  (`docs/runbooks/session-contract.md`).
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
  next key. No private key is ever written to the database or the repo;
  tests generate keys at run time (`06 §4`).
- `oauth_clients` registry: `client_id` (`sys-name-nn`), `system`,
  scopes allow-list, `client_secret_post` (argon2id hash, shown once) or
  `private_key_jwt` (client JWKS), `mtls_subject`, `certificate_id`,
  `status`. Scopes are least-privilege per client and limited to the
  catalogue of `06 §3` (a test refuses an unknown scope).
- `POST /oauth/token`: client credentials grant; `aud` taken from the
  request's `audience` parameter (or `resource`) and checked against the
  client's allowed audiences (`cisp`, `ussp-<id>`, `dss`, `ansp`,
  `authority`); scopes requested ⊆ allowed; TTL ≤ 1 h; `jti` random;
  `iss` = `ISSUER_URL` from config. Every issuance and refusal is an
  `events` row (`06 §3`). Rate-limited per client.
- `GET /.well-known/jwks.json` (cacheable, `Cache-Control: max-age=300`)
  and `GET /.well-known/openid-configuration` with `issuer`,
  `jwks_uri`, `token_endpoint`, `grant_types_supported`.
- `internal/tokens.Client`: the outbound client-credentials helper every
  other WP uses to call the CISP, USSP, DSS or ANSP: pre-fetches at 50 %
  TTL on its own context (E-14, T5), one token per audience, bounded
  cache.
- Verification wiring: `authz.Verifier` builds `core/auth.Config` with
  `Audience = "authority"`, issuers = this issuer plus the configured
  CISP issuer (for webhooks; WP-6 adds the JWS path), JWKS URLs from
  config; `Verifier.Counters` exported to metrics.

## Tests

- Vectors: `jwt_verify.json` through `RunOwned("authority")` against
  the `authz.Verifier` wiring (core already runs them against the
  package; here the test proves this repo's config plumbing reaches the
  same verdicts).
- E-01 pairs: every refusal beside its acceptance (wrong secret, revoked
  client, scope not allowed, audience not allowed, expired, wrong
  issuer, HS256 confusion, missing MFA, idle session, revoked session).
- E-02: rotate a key and read the JWKS; a token signed by the retiring
  key still verifies for 24 h and not after; the issuer with no key
  configured refuses to start, naming the variable.
- E-10: session table growth bounded by expiry job; rate limiter maps
  evicted.
- Concurrency under `-race`: parallel logins and token requests.

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] A client created for the lab, a token obtained, verified by
  `core/auth` in a second process (integration test spawning the
  verifier side), refused after the client is suspended.
- [ ] Login → MFA → session → logout round trip; every step an `events`
  row with the right `event_type`.
- [ ] `docs/runbooks/token-service.md`: key generation outside the repo,
  rotation, client onboarding, the audiences table.
- [ ] CHANGELOG line; `doc.go` files.

## Commits

`feat(authz): local console accounts with argon2id, TOTP and sessions [WP-2 A-M1]`,
`feat(tokens): ecosystem OAuth2 client-credentials issuer with JWKS and key rotation [WP-2 A-M4]`,
`feat(tokens): outbound client-credentials helper with early refresh [WP-2 A-M4]`,
`test(authz): run the jwt_verify vector through the authority's verifier wiring [WP-2 A-M4]`.
