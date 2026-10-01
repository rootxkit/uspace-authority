// Package authz is console authentication and the verification wiring
// of WP-2: local accounts with argon2id passwords and TOTP MFA, sign-in
// in two steps, sessions, and the one verifier (core/auth) through which
// every bearer token this system accepts passes.
//
// Accounts (users.go): a lower-case username, the console roles
// (viewer, inspector, registrar, incident_officer, admin, auditor), the
// realm (console, or police for WP-19) and a status. Admins create,
// disable and enable accounts, set roles and reset MFA; each change ends
// the account's sessions and is an events row, and no change may leave
// the system without an active admin. The first admin comes from
// BOOTSTRAP_ADMIN_USERNAME on an empty users table, once.
//
// Sign-in (service.go): POST /v1/auth/login checks the password
// (argon2id, internal/passhash) and opens a short, single-use challenge
// (only its SHA-256 is stored); an unknown user, a disabled user and a
// wrong password get the same answer after the same work, so neither
// the answer nor its timing tells whether an account exists. Attempts
// are limited per address and per username (S-15; bounded maps, E-10).
// An account without confirmed TOTP receives its secret (pquerna/otp,
// RFC 6238) at this step; the secret is sealed with the PII key
// (internal/pii). POST /v1/auth/mfa takes the challenge and a TOTP code
// (each time step accepted once) or a recovery code (ten, hashed, each
// once); the first success confirms enrolment and shows the recovery
// codes once. The challenge allows MFA_MAX_ATTEMPTS codes, and every
// wrong code also counts against the account in the database (NIST SP
// 800-63B 5.2.2): MFA_LOCKOUT_AFTER failures lock it with a doubling
// backoff, MFA_HARD_LOCK_AFTER until an admin unlocks it.
//
// Sessions: table A's session JWT (M20) signed by internal/tokens, aud
// this system's own host, scope "session", roles, realm, jti = the
// session id, 12 h; the sessions row makes logout, revocation and the
// 30 min idle expiry work, and bounds an account's live sessions. The
// sweep deletes expired rows (E-10).
//
// Verification (verifier.go, identify.go): Verifier builds
// core/auth.Config with AUTHORITY_AUDIENCES, StrictSessionClaims, this
// issuer's token keys (rebuilt on every key refresh) and the configured
// peer issuers (CISP, ANSP, lab) by JWKS URL, a peer unreachable at
// start retried in the background. Authenticator.Identify turns a bearer
// token into the request's identity: a session of this issuer whose row
// is live, or an ecosystem machine token. apiserver.Authorize applies
// the operation's rule: role and realm for console operations
// (RequireRole, RequireRealm), any session, or a scope for machine
// operations (RequireScope). FromCookie is the WebSocket rule of M22
// (cookie on a same-origin upgrade, Origin allow-list), CheckCSRF the
// double-submit check of M21, RequirePurpose the purpose of a PII read.
// docs/runbooks/session-contract.md states the cookie contract.
package authz
