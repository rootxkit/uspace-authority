# Runbook: the console session contract

One session shape for every uspace system (cross-plan decisions M20,
M21, M22). `api` issues and checks it; the Next.js BFF of the console
(WP-21) carries it; `picture-ws` (WP-13) accepts it on the WebSocket
upgrade. This page is the contract the BFF and the WebSocket process
implement.

## The token

A session is table A's session JWT (`docs/WORKPACKAGES/WP-2.md`),
signed RS256 by this system's issuer:

| Claim | Value |
|---|---|
| `iss` | this system's issuer (`ISSUER_URL`) |
| `aud` | this system's own host (the host of `AUTHORITY_PUBLIC_URL`) |
| `sub` | the account id |
| `scope` | `session`, and nothing else |
| `roles` | the account's console roles, an array (possibly empty) |
| `realm` | `console`, or `police` (WP-19) |
| `iat`, `exp` | `exp` = `iat` + 12 h (`SESSION_TTL_S`) |
| `jti` | the session id (the `sessions` row) |
| header `kid` | the signing key |

Every verifier uses `uspace-core/auth.Verifier` with
`StrictSessionClaims` on. `api` also checks the `sessions` row on every
request: logout, admin revocation, a role change, a disable and an MFA
reset end it at once, and a session unused for 30 minutes
(`SESSION_IDLE_S`) ends for good. An account holds at most
`SESSION_MAX_PER_USER` live sessions; a new sign-in beyond that ends the
oldest.

## Sign-in

1. `POST /v1/auth/login` `{username, password}` → `{mfa_token,
   expires_at, enrolment?}`. `enrolment` (`secret`, `otpauth_uri`) is
   present until the account confirms TOTP.
2. `POST /v1/auth/mfa` `{mfa_token, code}` (or `recovery_code`) →
   `{token, token_type, expires_at, idle_timeout_s, session,
   recovery_codes?}`. `recovery_codes` appear once, at the sign-in that
   confirms enrolment.
3. `POST /v1/auth/logout` with the session as bearer ends it.
   `GET /v1/auth/session` reads it.

Wrong TOTP or recovery codes count against the account in the
database, across challenges, addresses and api replicas (NIST SP
800-63B 5.2.2): from `MFA_LOCKOUT_AFTER` (5) failures the account's MFA
is locked for `MFA_LOCKOUT_BASE_S` (60 s), doubling with each further
failure up to `MFA_LOCKOUT_MAX_S` (1 h); at `MFA_HARD_LOCK_AFTER` (100)
it stays locked until an admin calls `POST /v1/users/{id}/mfa/unlock`.
A success clears the count; each lock is an `mfa_locked` event. The
per-address and per-username sign-in limits are per process (each api
replica keeps its own buckets); the MFA budget is the bound that holds
across replicas.

Both sign-in answers carry `Cache-Control: no-store`. Refusals are
problems (`invalid_credentials`, `mfa_refused`, `rate_limited` with
`Retry-After`).

## Cookies (the BFF)

| Cookie | Holds | Flags |
|---|---|---|
| `uspace_session` | the session JWT, as returned by `/v1/auth/mfa` | `HttpOnly; Secure; SameSite=Strict; Path=/`; `Max-Age` = `exp` - now |
| `uspace_csrf` | a random value the BFF chooses at sign-in (at least 128 bits) | `Secure; SameSite=Strict; Path=/`; readable by the page (not `HttpOnly`) |

- The browser never sees the JWT in JavaScript: the BFF sets
  `uspace_session` and forwards it to `api` as
  `Authorization: Bearer <jwt>`.
- CSRF (double submit): every state-changing request from the page
  (anything but GET, HEAD, OPTIONS) carries the header `X-CSRF-Token`
  equal to the `uspace_csrf` cookie; the BFF compares them in constant
  time before it forwards anything (`authz.CheckCSRF` is the reference
  implementation).
- On logout, on a 401 from `api`, or at `exp`, the BFF clears both
  cookies.

## WebSockets (M22)

The console's WebSocket connects **same-origin** and the browser sends
the `uspace_session` cookie with the upgrade. The WebSocket process
(`picture-ws`) accepts the upgrade only when:

- the `Origin` header is exactly one of its configured allowed origins
  (scheme, host and port; no wildcard), and
- the cookie holds a valid session token of this issuer: `scope` is
  `session` (a machine token in the cookie is refused), the session row
  is live, and the roles allow the stream.

There is no ticket: a token in a query string would be written to
access logs. A close with code 4401 means "sign in again".
`authz.Authenticator.FromCookie` is the reference implementation.

## Machine tokens are not sessions

A token without `scope = "session"` is an ecosystem machine token (table
A, first row). It is refused on every console operation (403) and in the
session cookie; a session token is refused on machine operations.
