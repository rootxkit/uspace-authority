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
