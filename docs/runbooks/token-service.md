# Runbook: the ecosystem token service

`api` is the ecosystem's OAuth2 issuer (WP-2, threat T4 of spec `06 §2`).
It signs RS256 machine tokens for every system that calls another
(client credentials), the console session tokens of this system, and
publishes the keys at `/.well-known/jwks.json`. This page is the
operator's view; the normative source of tables A and B is
`docs/WORKPACKAGES/WP-2.md`, and a test fails when the code, the
contract or this page drift from it.

## Endpoints

| Endpoint | Who | What |
|---|---|---|
| `POST /oauth/token` | machine clients | client credentials grant; form body only |
| `GET /.well-known/jwks.json` | every verifier | token keys and the publication key, `Cache-Control: public, max-age=300` |
| `GET /.well-known/openid-configuration` | every verifier | `issuer`, `jwks_uri`, `token_endpoint`, `grant_types_supported` |
| `GET/POST /v1/oauth/clients`, `GET/PATCH /v1/oauth/clients/{client_id}` | admin session | the client registry |
| `GET /v1/oauth/keys`, `POST /v1/oauth/keys/rotate` | admin session | signing keys and rotation |

## Table A: the JWT contract (restated)

| Token | `iss` | `aud` | `sub` | `scope` | Other claims | TTL |
|---|---|---|---|---|---|---|
| Ecosystem machine token (this issuer) | `ISSUER_URL` | host of the target's published base URL | client id | catalogue scopes, space-separated | `exp`, `iat`, `jti`, `kid` (header) | ≤ 1 h (`TOKEN_TTL_S`) |
| Operator machine token (a USSP's issuer) | the USSP's issuer | the USSP's host | operator client id | `ussp.intents ussp.telemetry ussp.traffic ussp.geo` | `exp`, `iat`, `jti`, `kid` | ≤ 1 h |
| Console session (every system) | the system's issuer | the system's own host | account id | `session` | `roles[]`, `realm`, `exp`, `iat`, `jti` = session id, `kid` | ≤ 12 h, idle 30 min |
| Webhook / direct-delivery JWS | the CISP's or the ANSP's issuer | host of the `callback_url` | subscription or restriction id | — | `cis/change/v1` body, `iat`, `jti` = delivery id | single use |
| Detached publication JWS (`X-JWS-Signature`) | — (key by `kid`) | — | — | — | `alg RS256`, `kid`, `iat` ≤ 5 min, `b64: false`, `crit: ["b64"]` | — |

Every verifier, in every system: `uspace-core/auth.Verifier`, RS256
only, allow-listed issuers with JWKS URLs, a configured `*_AUDIENCES`
list, 30 s skew, `jti` required, scope per endpoint, and
`StrictSessionClaims` on.

### The host-as-audience rule (M18)

`aud` is always the **host** of the target's published base URL, never
a system id: `uspace-cisp.example.test` for the CISP, the DSS's host,
a peer's `uss_base_url` host, the ANSP's host, this system's host. A
client asks for it with `audience=<host or base URL>` or one RFC 8707
`resource=<base URL>`; the issuer reduces a URL to its host name
(lower-case, no port, no path). One audience per token: a caller that
talks to three systems holds three tokens.

Each verifier accepts its own public host plus a **lab alias**, the
compose service name under which the lab reaches it. Here that list is
`AUTHORITY_AUDIENCES` (default: the host of `AUTHORITY_PUBLIC_URL`;
when set it must contain that host), for example
`AUTHORITY_AUDIENCES=uspace-authority.example.test,authority`.

For **national** scopes the requested host must be on the client's
`audiences[]`; for the standard `utm.*` and `rid.*` scopes any host is
accepted, because peers are discovered through the DSS and the CIS
USSP list, not configured (`00 §7`).

## Table B: the scope catalogue (restated)

| Family | Scopes | Issued to |
|---|---|---|
| CIS | `cis.read`, `cis.publish:zones`, `cis.publish:uspace`, `cis.publish:ussp_list`, `cis.publish:restrictions`, `cis.publish:ats_data` (reserved, never issued) | subscribers; the authority; the ANSP (`restrictions`) |
| Authority | `registry.validate`, `ussp.records`, `occurrences.write`, `certificates.status`, `police.query` | USSPs; the ANSP; police sessions |
| ANSP | `ansp.traffic`, `ansp.coordination`, `ansp.requests` | the authority and USSPs |
| Lab only | `dp.observe` | `lab-01` only; refused to every other client |
| F3548 | `utm.strategic_coordination`, `utm.constraint_processing`, `utm.constraint_management`, `utm.conformance_monitoring_sa`, `utm.availability_arbitration` | USSPs, the ANSP, the authority |
| F3411 | `rid.service_provider`, `rid.display_provider` | USSPs, the authority |
| A USSP's issuer only | `ussp.intents`, `ussp.telemetry`, `ussp.traffic`, `ussp.geo` | never issued here |

`rid.observe` is not a scope (receivers use a bearer key plus an HMAC,
WP-7), and console roles are `roles[]` on a session, not scopes. A
scope outside the table is refused at client registration and at the
token endpoint.

Client ids (M24), one per calling system: `authority-01`, `cisp-01`,
`ansp-01`, `ussp-<code>-01` (the certificate code), `lab-01`.

## Key generation (never in the repository)

Keys are generated on the host that runs `api`, outside any checkout,
readable by the `api` user only (spec `06 §4`; tests generate theirs at
run time):

```
umask 077
mkdir -p /srv/uspace-authority/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /srv/uspace-authority/keys/token-2026-10.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /srv/uspace-authority/keys/publication-2026-10.pem
```

PKCS #1 and PKCS #8 PEM are accepted, RSA of at least 2048 bits,
unencrypted (the file's permissions protect it). `kms:` references are
refused by this build. The kid is the RFC 7638 SHA-256 thumbprint of
the public key, so every replica derives the same kid from the same
file.

Configuration:

| Variable | Default | Meaning |
|---|---|---|
| `ISSUER_URL` | `AUTHORITY_PUBLIC_URL` | `iss`, and the base of `jwks_uri` and `token_endpoint` |
| `SIGNING_KEY_FILES` | required | token keys, comma-separated; the first is activated on an empty table, the others are rotation candidates |
| `PUBLICATION_KEY_FILE` | — | the detached-JWS key of WP-6, listed in the JWKS under its own kid |
| `TOKEN_TTL_S` | 3600 | machine token lifetime (at most 3600) |
| `TOKEN_RATE_LIMIT_PER_MIN`, `TOKEN_RATE_LIMIT_BURST`, `TOKEN_RATE_LIMIT_MAX_CLIENTS` | 60, 20, 1000 | per-client issuance limit |
| `ASSERTION_REPLAY_MAX` | 100000 | `private_key_jwt` assertion ids held until they expire |
| `KEY_RETIRE_GRACE_S` | 86400 | a retired key stays in the JWKS this long (the verifiers' JWKS cache TTL) |
| `KEY_ROTATION_TWO_PERSON`, `KEY_ROTATION_CONFIRM_S` | true, 600 | the two-person rule |
| `KEY_REFRESH_S` | 60 | how often every replica re-reads `signing_keys` |
| `ARGON2_MEMORY_KIB`, `ARGON2_TIME`, `ARGON2_THREADS` | 19456, 2, 1 | client secret and password hashing (OWASP minimum) |

Without `SIGNING_KEY_FILES` the process refuses to start and names the
variable; with a file that cannot be read or parsed, likewise. The
private key never reaches the database: `signing_keys` holds the kid,
the public JWK and the file path.

## Rotation (90 days, T4)

1. Generate the next key as above and add its path **after** the
   current ones in `SIGNING_KEY_FILES` on every replica; restart them
   one at a time. Each start registers the new kid as a candidate
   (`signing_key_registered`); the active key does not change.
2. An admin calls `POST /v1/oauth/keys/rotate`: 202, state `requested`
   (`key_rotation_requested`).
3. A **second** admin calls it within 10 minutes: 200, state
   `activated` (`signing_key_activated` with both names). The same
   admin twice is refused (409, `key_rotation_refused`).
4. Every replica picks the new key up within `KEY_REFRESH_S`. The old
   key is retired and stays in the JWKS for 24 h, so a verifier that
   cached the JWKS keeps verifying tokens signed before the rotation
   (they live at most 1 h, sessions at most 12 h).
5. After 24 h the old key leaves the JWKS (`GET /v1/oauth/keys` shows
   it `retired`); remove its file from `SIGNING_KEY_FILES` at the next
   deployment. Do not remove the file of the **active** key: a replica
   whose active kid has no file keeps signing with the key it had and
   counts `signing_key_file_missing` on every refresh.

## Client onboarding

1. Pick the client id (M24) and the scopes from table B (least
   privilege: a USSP's client for the authority holds
   `registry.validate` and `occurrences.write`), and the hosts it may
   name for national scopes.
2. An admin posts `POST /v1/oauth/clients`:
   - `client_secret_post`: the response carries `client_secret` once;
     hand it over out of band. Only its argon2id hash is kept.
   - `private_key_jwt`: post the client's public JWKS (RSA, at least
     2048 bits, `kid` on every key, no private members). The client
     signs an assertion with `iss` = `sub` = its client id, `aud` =
     `ISSUER_URL` or its `/oauth/token`, `exp` at most 5 minutes ahead,
     a fresh `jti` each time.
3. The client requests tokens:

   ```
   curl -s https://<authority host>/oauth/token \
     -d grant_type=client_credentials -d client_id=cisp-01 \
     -d client_secret=... -d scope=cis.read \
     -d audience=https://uspace-cisp.example.test
   ```

4. Suspend or revoke with `PATCH /v1/oauth/clients/{client_id}`
   (`{"status": "suspended"}`): no new token is issued from that
   moment (`invalid_client`); tokens already issued run to their `exp`,
   at most 1 h, because verifiers are stateless.

## Refusals and audit

Every issuance is a `token_issued` event (`jti`, `kid`, `aud`, scopes,
`exp`) written in the transaction that releases the token: if the
event cannot be written, the token is withheld. Every refusal is a
`token_refused` event with the RFC 6749 `error` and a `reason`
(`client_unknown`, `client_secret_wrong`, `client_suspended`,
`scope_not_in_catalogue`, `scope_reserved`, `scope_of_another_issuer`,
`scope_lab_only`, `scope_not_allowed_for_client`,
`audience_not_allowed_for_client`, `audience_multiple`,
`parameters_in_query`, `rate_limited`, ...). An unknown client and a
wrong secret get the same answer after the same argon2id work. The
status line and `/metrics` carry `tokens_issued`, `tokens_refused`,
`token_refusal_event_failed`, `http_rate_limited`,
`assertion_replayed`, `assertion_replay_memory_full`,
`signing_key_rotated`, `signing_key_rotation_refused`,
`signing_key_refresh_failed`, `signing_key_file_missing` and the
`signing_kid` in use.

Errors are `application/problem+json` (M28) with the RFC 6749 `error`
and `error_description` members beside the problem members, so an
OAuth2 client library and a uspace client both read them.

## Verifying this issuer's tokens elsewhere

A sibling system configures this issuer on its allow-list with
`https://<authority host>/.well-known/jwks.json` and verifies with
`uspace-core/auth.NewVerifier` (`Audiences` = its own host plus its lab
alias, `StrictSessionClaims: true`). The integration test
`TestIntegrationTokenVerifiedInASecondProcess` does exactly that in a
separate process.
