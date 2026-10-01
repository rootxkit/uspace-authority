# uspace-authority: rules for every contributor and agent

`uspace-authority` is the competent authority's system of the Georgian
U-space rebuild (`github.com/rootxkit/uspace-authority`): the registry of
operators, UAS and remote pilots; geo-zones and U-space designations
(published through the CISP); USSP and CISP certificates and the public
register; the Remote ID receiver network and the authority's own
picture (direct Remote ID plus an ASTM F3411 Display Provider view of
every USSP); violations from the authority's own evidence; incidents and
evidence packs; occurrence reports under Reg. 376/2014; the audit log;
and the ecosystem OAuth2 token issuer. Read `docs/PLAN.md` before
changing anything; every work package has a brief in
`docs/WORKPACKAGES/`. The spec is `uspace-lab/docs/spec/`; the lessons
are `uspace-lab/knowledge/LESSONS.md`.

## Hard rules

1. **Nothing here commands an aircraft.** No process, type, dependency
   or configuration has a send path towards a vehicle; alerts and
   findings go to people and to records (spec `00 §1`, LESSONS INV-01).
   A task that seems to need a send path is out of scope: stop and ask.
2. **The authority does not alert pilots, separate traffic or authorise
   flights.** Those are the USSP's services (spec `01 §1` MUST NOT). A
   proximity (CPA) warning, a resolution advice or a real-time message
   to an operator does not belong in this repository. Conflict events
   from `uspace-core/alerting` are counted and dropped (plan D5).
3. **Judgement lives once, in `uspace-core`.** Identification, zone
   judging, the 120 m rule, time placement, pressure altitude, geodesy,
   ODID decoding, ED-318 and the JWT verifier are imported by tag and
   never re-implemented, forked or "simplified" here or in `web/`.
   `depguard` fails any other geometry, geodesy or JWT library. A
   behaviour the vectors do not foresee is a spec gap written in the PR,
   not a local rule.
4. **An alert path is not done until a scenario raises and clears it**
   (INV-02). A violation kind, a source-disabled clearing, a stale
   ageing or a degraded state counts as done when
   `uspace-lab/knowledge/scenarios.md`'s owned scenario passes through
   `internal/ltest` against real NATS, PostgreSQL and TimescaleDB, and
   the raise **and** the clear were observed. A unit test alone does
   not close it.
5. **Thresholds, periods and formats are data** (INV-03): the height
   limit, the pressure margin, TTLs, the registration-number pattern,
   retention periods and lapse periods are `authority_policy` columns or
   configuration with documented defaults, audited when changed, never
   literals, never relaxed to make a test pass.
6. **PII never reaches a public viewer, a USSP, the police without
   purpose, or an export by accident.** Registry validity answers are
   status-only; every PII read carries a `purpose` and writes an
   `events` row; PII columns are encrypted; the response schemas of
   public and machine endpoints are grepped for PII property names in
   tests. Occurrence reports live in their own schema and role and are
   **never** joined to violations or incidents (376 Art. 15–16); a test
   proves the absence of any path.
7. **Display Provider data is disposed of within 24 h** (F3411
   `NetDpMaxDataRetentionPeriodSeconds`); what a violation or an
   incident needs is copied into its own record at detection.
8. **Nothing hides an aircraft or a source silently.** A disabled source
   says who disabled it; a stale or unavailable input is shown with its
   age; every refusal, drop, fallback and degraded state is a named
   counter on the status line and `/metrics` (E-09); an empty console
   must never look like an empty sky (E-02, SC-22).
9. **Units and datums in every name** (E-13): `alt_amsl_m`, `alt_hae_m`,
   `height_agl_m`, `speed_ms`, `timeout_s`; in Go `AltAMSLM`, `SpeedMS`,
   `TimeoutS` or `time.Duration`. No stored AGL column, ever (D-02).
   Pressure altitude is never an AMSL value (R-08).
10. **Two migration trees, never merged** (`migrations/relational`,
    `migrations/timeseries`); only `api` writes the relational database;
    only `tsdb-writer` writes hypertables; hot-path processes never open
    the relational database (B-15). The web UI renders only: no
    database, NATS, geometry or JWT library in `web/`.
11. **No secret, key, certificate, token, real hostname or real
    registry data in git**, including test keys: keys are generated at
    test time; fixtures use `GEO-TEST-*` numbers and `TEST*` serials;
    the staging hostname appears only under `deploy/staging/`
    (spec `06 §4`).
12. **English only**, in code, comments, commits and docs; user-facing
    strings go through the `ka`/`en` catalogues from day one.

## Testing rules (LESSONS E-01 to E-04, E-10, E-11)

- **E-01 Test presence, not only absence.** Every test that asserts
  something does not happen (no violation, no refusal, no publish, no
  PII, nil) is paired with the test that makes it happen. Every
  `refuse-*` has its `accept-*` twin.
- **E-02 Run the branch that says nothing is wrong.** Start the process
  with the dependency absent (no NATS, no geoid, no terrain, no
  projection, no keys) and read what it says; make the thing succeed
  and read the success line; a cleanup or deploy that reports success
  while doing nothing is a bug.
- **E-03 Never write a wire-format offset or field name from memory.**
  ODID layouts come from `uspace-core/odid` and its reference frames;
  F3411, F3548 and ED-318 member names from `uspace-core/f3411`,
  `f3548`, `ed318` (generated from `uas_standards`); the sibling
  systems' national APIs from their `api/openapi.yaml` at a recorded
  commit; the InterUSS qualifier's shapes from its pinned commit.
- **E-04 Never report an inference as an observation.** "The scenarios
  pass" means you ran `make scenarios` and read the output. A skipped
  case is reported as skipped. A tool error is not evidence about the
  thing being checked. Read generated files back.
- **E-10** every bounded structure (queue, cache, nonce set, tracker,
  map keyed by an external id, rate limiter) has a test that exceeds
  its bound.
- **E-11** tests restore global state and pass under `-shuffle=on` and
  `-race`.
- Knowledge vectors are run through this repository's adapters with
  `vectors.File.RunOwned(t, "authority", ...)`; the test maps the wire
  shape onto core's input and compares the adapter's output. It never
  re-implements the judgement.
- Coverage: ≥ 85 % statement on the packages plan §9 names; every
  branch that produces a distinct counter or reason has a named test.

## Conventions

- Layout: `cmd/<process>/`, `internal/<package>/`, `api/openapi.yaml`
  (spec-first; the only source of handlers and types; an endpoint not
  in it does not exist), `api/gen/` (committed, verified offline),
  `schemas/` (JSON Schemas of produced messages), `migrations/`,
  `web/`, `deploy/`, `docs/`. Plan §3 has the import rules.
- Stack: Go 1.27, `CGO_ENABLED=0`; `net/http` routing; `oapi-codegen`
  v2; `pgx/v5` with `sqlc`; `goose` embedded; `nats.go` JetStream;
  `log/slog` JSON; Prometheus; OpenTelemetry; configuration from the
  environment through `internal/config` only. `web/`: Next.js App
  Router, TypeScript strict, Tailwind + shadcn/ui through `uspace-ui`,
  MapLibre GL, types from `openapi-typescript`, `pnpm` with a lockfile.
- Dependencies: standard library first; a new module needs a one-line
  reason in the commit body and a row in `docs/PLAN.md §13`.
- Errors: `*core.FieldError` or `problem+json` naming the field;
  lower-case, no trailing punctuation. No `panic`, `fmt.Print*`,
  `log.*` or `os.Exit` outside `cmd/*/main.go` and tests (`forbidigo`).
- Every PII read, every switch, every publication, every token
  issuance and refusal, every export and every review is an `events`
  row with the actor and, where it applies, the purpose.

## Cross-system contracts (reconciled 2026-10-02)

These are shared with the four sibling systems; change them by a pull
request against `docs/WORKPACKAGES/WP-2.md`'s normative tables first.

- JWT `aud` is always the **host** of the target's published base URL;
  each verifier accepts `AUTHORITY_AUDIENCES` (own host + lab alias).
  One client id per calling system (`authority-01`, `cisp-01`,
  `ansp-01`, `ussp-<code>-01`, `lab-01`). The scope catalogue is WP-2
  table B; `rid.observe` is not a scope.
- Sessions everywhere: `scope = "session"`, `roles[]`, `realm`, `jti`,
  `aud` = own host; cookies `uspace_session` / `uspace_csrf`, header
  `X-CSRF-Token`; WebSockets take the cookie on a same-origin upgrade
  with an `Origin` allow-list, never a ticket.
- Errors: `problem+json` with `errors: [{field, reason}]` and
  `truncated`, `type` = `https://schemas.uspace.ge/problems/<slug>`.
- Every WebSocket frame, served or consumed, is the `04 §2` envelope +
  `body` named by `schema`; `console/status/v1` is the status frame.
  Shared schemas come from `uspace-lab/schemas/common/`; this repo
  defines only `violation/v1`, `occurrence/v1`, `rid/observation/v1`
  and its status extras.
- CIS: receiver path `/v1/cis/notifications`, issuers CISP and ANSP;
  heartbeat `POST /v1/publishers/heartbeat` every 15 s; detached JWS in
  `X-JWS-Signature`; `cis/*` schemas are the CISP's.
- `AUTHORITY_MTLS_MODE = required | off`; migrations only by the
  `migrate` subcommand; `pnpm`; one `timescaledb-ha` container.

## Commands

```
make tools              # once per machine: the pinned linters
make lint               # gofmt, vet, staticcheck, golangci-lint (pinned versions; refuses others)
make race               # go test -race -shuffle=on ./...
make vectors            # uspace-core's vector tests from the module cache + this repo's RunOwned tests
make generate           # oapi-codegen, sqlc, openapi-typescript
make verify-generated   # regenerate offline and diff; must be empty
make up / make down     # the development stack (PostGIS, TimescaleDB, NATS)
make integration        # tests that need the stack (INTEGRATION=1)
make scenarios          # internal/ltest scenarios against the stack
make image              # the Go image; make web-image for the console
```

## Git conventions

- Branch per work package: `feat/WP-<k>-<slug>` (the slug is in the
  brief). Plan and docs branches: `plan/<slug>`, `docs/<slug>`.
- Conventional Commits, one logical change per commit, imperative
  subject under 72 characters, the work package and milestone in
  brackets at the end: `feat(registry): status-only validity lookups
  for USSPs [WP-3 A-M1]`, `fix(dp): mark a Service Provider slow after
  p99 3 s [WP-14 A-M4]`, `test(detect): zone incursion raised and cleared
  through a PROHIBITED zone (SC-07) [WP-12 A-M3]`. Types: `feat`, `fix`,
  `test`, `refactor`, `perf`, `docs`, `build`, `ci`, `chore`. Scope is
  the package or process.
- **No AI attribution of any kind**: no `Co-Authored-By`, no
  "generated by", no tool names in commits, PRs or code.
- Never force-push a shared branch; never commit to `main` directly.
- Do not push unless asked. The owner merges, after review.

## Before you say a work package is done

Run, in this order, and paste the last lines of each into the PR:

```
make tools
make lint
make race
make vectors
make verify-generated
make integration        # and make scenarios where the brief says so
```

Then check the brief's done-when list item by item. If a scenario or
vector cannot pass without a behaviour the plan did not foresee, stop
and write it down in the PR as a spec gap; do not change the vector or
relax the threshold.
