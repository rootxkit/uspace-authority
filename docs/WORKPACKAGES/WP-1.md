# WP-1: store, audit and policy

Branch `feat/WP-1-store-audit-policy`. Milestone A-M1. Owns
`internal/store/pg`, `internal/store/ts`, `internal/store/migrate`
(beyond WP-0's runners), `internal/audit`, `internal/policy`, the
migrations for `events` and `authority_policy`, and the `sqlc` setup.
Depends on WP-0. Consumers: every later WP.

## Read first

1. `docs/PLAN.md` §1.2 D2, D7, §4, §6 (KV `policy`), §7 (records).
2. Spec `03` conventions and `03 §1` `events`; `05 §4` audit retention;
   `06 §2` T7, `06 §5` accountability.
3. LESSONS INV-03, G-08 (projection discipline, implemented by WP-3 and
   WP-5 on the primitives built here), B-06, B-09 (advisory locks), B-15,
   E-10, E-11.
4. Reference only: utm `infra/migrations/relational/versions/0002_airspace_policy.py`,
   `api/registry.py` (events writer).

## What to build

### Store

- `internal/store/pg`: `pgxpool` setup from config (max conns, statement
  timeout, `application_name` per process), `sqlc` configuration
  (`sqlc.yaml`, queries under `internal/store/pg/queries/*.sql`,
  generated into `internal/store/pg/gen`), a `Tx` helper with
  `WithTx(ctx, func(q *gen.Queries) error)`, and `AdvisoryLock(ctx, key)`
  used by every periodic job (one `api` replica runs a job at a time).
- `internal/store/ts`: the same for the telemetry database with two
  query sets: `writer` (used only by `tsdb-writer`) and `reader`
  (projection reads, record reads). The telemetry role used by hot-path
  processes has `SELECT` only; a test asserts an `INSERT` with that role
  fails.
- `internal/store/migrate`: embedded goose trees, `Up(ctx, db, tree)`
  under an advisory lock, `Status`, and the layout test (no table of one
  tree in the other).

### Audit (`events`)

- Migration: `events` partitioned by month (`ts`), `INSERT`-only grant
  for the application role, a trigger refusing `UPDATE` and `DELETE`,
  `prev_hash`/`hash` columns, index on `(entity_type, entity_id, ts)` and
  `(actor_id, ts)`.
- `audit.Writer.Record(ctx, tx, Event)` computes
  `hash = sha256(prev_hash ‖ canonical JSON of the row without hash)`
  inside the caller's transaction, serialised per month by an advisory
  lock so the chain is linear; the first row of a month links to the
  previous month's last hash. `Event` has `ActorType`, `ActorID`,
  `Realm`, `Purpose` (required for every PII read; a test refuses an
  empty purpose on event types tagged `pii_view`), `EntityType`,
  `EntityID`, `EventType`, `Payload`.
- `audit.Verify(ctx, month)` recomputes the chain and returns the first
  broken row or nil; exposed later by `/v1/audit/verify` (WP-27) and run
  in the integration test after tampering with one row as a superuser
  (E-01: prove the verifier can detect).
- `audit.Query` for `/v1/audit/events` with the filters the plan lists
  (handler wiring in this WP, read role `admin`/`auditor` stubbed until
  WP-2 lands: the route exists behind a `requireRole` placeholder that
  WP-2 replaces).

### Policy

- Migration `authority_policy` with the columns of plan §4.1 and
  documented defaults equal to the predecessor's (height limit 120 m
  AGL, pressure uncertainty 250 m, spoof distance 300 m, identity TTL
  15 s, max gap 3 s, identify within 4 s, broadcast tolerance 1 s, max
  latency 5 s, live max age 10 s, clear after 3 s, stale after 15 s, DP
  view diagonal 7 km, DP poll 1 Hz, CIS stale bound 300 s,
  `height_limit_in_uspace = evaluate`). Exactly one `active` row
  (partial unique index).
- `policy.Service`: `Active(ctx)`, `Create(ctx, p)` (new version,
  validated: every threshold finite and positive where E-15 applies;
  refusal names the field), `Activate(ctx, version, actor)` (audited,
  publishes to KV `policy` and `ctl.policy` — the bus client comes from
  WP-10; until it merges, publish through an interface with a no-op in
  tests), and `Follower` for hot-path processes: holds the last policy,
  applies only a higher `version`, exposes `policy_version` for every
  violation (`04 §3.3`).
- Routes `/v1/policy*` per plan §5.

## Tests

- Integration (service containers): migrations up and down twice; the
  `UPDATE`/`DELETE` refusal on `events` (E-01: the `INSERT` beside it);
  the hash chain across a month boundary; `Verify` detects a tampered
  row and passes an untouched month (E-02: read what the success says);
  advisory lock contention between two goroutines.
- Unit: policy validation refuses zero, negative, NaN and infinite
  thresholds and accepts the defaults (E-15); follower ignores an older
  version (E-01 pair).
- Race and shuffle clean.

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] `sqlc generate` output committed and `verify-generated` empty.
- [ ] `/v1/policy` round trip in the integration test; the active policy
  appears on the status line of a process that follows it.
- [ ] CHANGELOG line; `internal/store/doc.go`, `internal/audit/doc.go`,
  `internal/policy/doc.go` describe what was built.

## Commits

`feat(store): pgx pools, sqlc query sets and goose trees for both databases [WP-1 A-M1]`,
`feat(audit): append-only events with a monthly hash chain [WP-1 A-M1]`,
`feat(policy): versioned authority policy with an active row and a follower [WP-1 A-M1]`.
