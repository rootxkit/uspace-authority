// Package tokens is the ecosystem token service of WP-2: the OAuth2
// client-credentials issuer every system of the U-space ecosystem calls,
// its client registry, its RS256 signing keys and its JWKS. The JWT
// contract (table A) and the scope catalogue (table B) are the normative
// tables of docs/WORKPACKAGES/WP-2.md; scopes.go holds table B, and a
// test reads the brief and fails on any difference.
//
// Signing and verification are uspace-core/auth's: machine tokens are
// signed by core's Issuer, client assertions (private_key_jwt) verified
// by core's Verifier, the publication key used through core's KeyRing
// (SignDetached). The only signing done here is the console session
// token (SignSession), whose roles and realm core's Issuer does not
// carry: its payload is table A's session row, marshalled here and
// signed by jwx with RS256 and the kid header, the same form core
// produces and core's Verifier (StrictSessionClaims) checks. Nothing in
// this package is a cryptographic primitive.
//
// Keys (keys.go, rotation.go): SIGNING_KEY_FILES are PEM files outside
// the repository; each key's kid is its RFC 7638 thumbprint; the private
// key never reaches the database (signing_keys holds the public JWK and
// the file path). The first configured key is activated on an empty
// table; later keys are rotation candidates, activated by
// POST /v1/oauth/keys/rotate under the two-person rule; a retired key
// stays in the JWKS for KEY_RETIRE_GRACE_S (24 h) and its tokens verify
// until then. Every replica re-reads signing_keys every KEY_REFRESH_S.
// The JWKS also lists the publication key of the detached
// X-JWS-Signature (M26) under its own kid; it never verifies a token
// here (TokenKeys leaves it out).
//
// Issuance (service.go): client_secret_post (argon2id, internal/passhash)
// or private_key_jwt (RFC 7523, assertion ids recorded in assertion_jtis
// until they expire, so each is used once across replicas); scopes in table B, grantable and on
// the client's list; aud the host of the requested audience or RFC 8707
// resource (M18), on the client's list for national scopes, any host for
// utm.* and rid.*; TTL at most 1 h; a per-client rate limit. Every
// issuance is a token_issued event in the transaction that releases the
// token (no row, no token) and every refusal a token_refused event.
//
// Client (client.go) is the outbound helper every other work package
// uses to call the CISP, a USSP, the DSS or the ANSP.
package tokens
