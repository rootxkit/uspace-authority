# Changelog

All notable changes to this repository. One line per work package under
Unreleased; the format follows Keep a Changelog.

## Unreleased

- WP-0: Go module on uspace-core v1.0.0; seven process stubs and the
  `uspace-authority` entrypoint with the `migrate` subcommand; config,
  logging, metrics, tracing and httpx baselines; OpenAPI skeleton with
  generated server, client and types; empty relational and timeseries
  migration trees; Makefile, CI, Dockerfile and the development compose
  stack.
- WP-1: `internal/store` (pgx pools with statement timeout,
  `application_name` and a per-process role; `sqlc` query sets for the
  relational database and the telemetry writer and reader; `WithTx`,
  session advisory locks for jobs, the schema-version check of D7;
  `migrate.Status` and `Latest`); the `events` audit log, partitioned by
  month, append-only by grant and trigger, with a monthly SHA-256 hash
  chain, `Verify` and `GET /v1/audit/events`; the versioned
  `authority_policy` with documented defaults, E-15 validation, audited
  create and activate, a `Follower` and `/v1/policy*`; the
  `authority_app`, `authority_ts_reader` and `authority_ts_writer` roles;
  the `requireRole` placeholder WP-2 replaces.
- WP-2: uspace-core v1.1.0; the ecosystem token service (`/oauth/token`
  client credentials with `client_secret_post` or `private_key_jwt`,
  `aud` = target host, scopes from table B, every issuance and refusal
  an event; `/.well-known/jwks.json` and issuer metadata; signing keys
  from PEM files with two-person rotation and a 24 h overlap; the
  publication key in the same JWKS; `/v1/oauth/clients*` and
  `/v1/oauth/keys*`); console accounts with argon2id, TOTP MFA sealed
  with the PII key, recovery codes, two-step sign-in without user
  enumeration, rate limits, sessions of table A with idle expiry and
  revocation, `/v1/auth/*` and `/v1/users*`, the first-admin bootstrap;
  the core/auth verifier wiring (own keys, CISP, ANSP and lab issuers);
  `tokens.Client` for outbound calls; the token-service and
  session-contract runbooks.
- WP-3: the registry (`internal/registry`, migrations
  `00009_registry` and `00003_registry_projection`): operators with the
  Art. 14(2) field set, UAS and remote pilots with competencies;
  registration numbers and serials through core `regnum` and `serial`
  only, the number's format from the new policy column
  `registration_number_pattern`; personal columns sealed with the PII
  key, the secret part and national id as keyed hashes
  (`REGISTRY_HASH_KEY_FILE`); one status graph with an expiry job;
  every change an event and an F8 change-feed entry; the projection
  `proj_registry_operators` / `proj_registry_uas` written as
  `authority_ts_projector` with the change (rolled back with it), and
  repaired at startup and every 300 s under an advisory lock;
  `ProjectionReader` for the resolvers; `/v1/registry/*` for registrars
  with purpose-logged personal-data reads; F8 `validate` (status only,
  batch of 100) and `changes` behind scope `registry.validate`.
