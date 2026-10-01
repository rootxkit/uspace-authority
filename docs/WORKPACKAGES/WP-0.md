# WP-0: scaffold

Branch `feat/WP-0-scaffold`. Milestone A-M1. Owns `go.mod`, `cmd/*`
stubs, `internal/config`, `internal/logging`, `internal/metrics`,
`internal/tracing`, `internal/httpx`, `Makefile`, `.golangci.yml`,
`.github/workflows/ci.yml`, `Dockerfile`, `deploy/compose.dev.yaml`,
`scripts/`, the two empty migration trees, the `api/openapi.yaml`
skeleton and `api/gen/`. Depends on nothing. Every other WP inherits it.

## Read first

1. `docs/PLAN.md` §2, §3, §9, §10, §13.
2. `uspace-core` PR #1 (`rootxkit/uspace-core`, "Plan, scaffolding, frozen
   base types and vector harness"): its `Makefile`, `.golangci.yml`,
   `.github/workflows/ci.yml`, `.gitleaks.toml`, `.gitattributes`,
   `SECURITY.md`. Copy the shape; pin the same linter versions.
3. Spec `00 §6`, `05 §6` (deployment), `06 §4` (public repo rules).
4. LESSONS E-02, E-09, E-12, B-08.

## What to build

- `go.mod`: `module github.com/rootxkit/uspace-authority`, `go 1.27`,
  `require github.com/rootxkit/uspace-core v0.2.0`. Add only the modules
  §13 of the plan lists, each with a reason in the commit body.
- `cmd/<process>/main.go` for the seven processes: parse config, set up
  slog JSON (`internal/logging`), Prometheus (`internal/metrics`) and
  OpenTelemetry (`internal/tracing`, OTLP exporter when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set, no-op otherwise), serve
  `/healthz`, `/readyz`, `/metrics` on the admin port, handle SIGTERM
  with a bounded drain, exit non-zero on a config error with the field
  named. Each `main` is the only place `os.Exit` is allowed.
- `internal/config`: one struct per process, loaded from the environment
  with `envconfig`-style tags written by hand (no library), validated
  (`FieldError` naming the variable), with `String()` that redacts
  secrets. Every URL, hostname, key path and threshold comes from here;
  `grep -r chikox.net` outside `deploy/staging/` is a CI failure.
- `internal/logging`: `slog` JSON handler; `Limited(key)` returning a
  logger that logs the first event, then at most one per interval per
  key with the suppressed count (E-09); `Status` helper that emits one
  status line per interval with every `core.Counters` snapshot.
- `internal/metrics`: registry, `CountersCollector` exposing a
  `core.Counters` as gauges with stable snake_case names, HTTP and NATS
  middleware histograms.
- `internal/httpx`: `net/http` server with `ReadHeaderTimeout`, body cap
  (1 MiB default, per-route override), request id, `problem+json`
  errors, structured access log, per-client token-bucket rate limiter
  (bounded map, eviction tested, E-10), `Shutdown` with deadline.
- `api/openapi.yaml`: OpenAPI 3.1 with `info`, `servers`, the `Problem`
  schema, the security schemes (`sessionCookie`, `ecosystemToken`,
  `receiverKey`), the health paths and the `x-audit` vendor extension
  documented. `oapi-codegen` config for `api/gen/` (server with strict
  handlers, client, types); `scripts/generate.sh` and
  `scripts/verify-generated.sh` (regenerate into a temp dir, diff).
- `migrations/relational/00001_init.sql` (`CREATE EXTENSION postgis`) and
  `migrations/timeseries/00001_init.sql` (`CREATE EXTENSION
  timescaledb`), goose runners in `internal/store/migrate` (WP-1 fills
  the rest), with a test that each tree applies and rolls back on a
  service container and that no file names a table of the other tree.
- `Dockerfile`: multi-stage, `CGO_ENABLED=0`, distroless static,
  `ENTRYPOINT ["/uspace-authority"]` with the process as the first
  argument (one binary that dispatches, or seven binaries copied in; one
  image either way). A build test that `internal/ltest` is not linked.
- `deploy/compose.dev.yaml`: PostGIS, TimescaleDB, NATS (JetStream, file
  store) with health checks; `make up` reaches healthy from cold.
- `Makefile` targets: `tools`, `lint`, `test`, `race`, `vectors`
  (`go test -run 'Vector|Manifest|Version' github.com/rootxkit/uspace-core/...`
  plus `./...`), `generate`, `verify-generated`, `integration`
  (`INTEGRATION=1`), `up`, `down`, `image`, `ci`.
- `.github/workflows/ci.yml`: the jobs of plan §13 with path filters,
  `concurrency` cancel-in-progress, `timeout-minutes`, caches, service
  containers for `integration`; `image` only on `main` and `v*` tags.
  `web` job is added by WP-21; `scenarios` by WP-25.
- `CLAUDE.md` is already written on `plan/initial`; `SECURITY.md`,
  `.gitleaks.toml`, `.gitattributes`, `.gitignore`, `CHANGELOG.md`.

## Done when

- [ ] `make tools lint race vectors verify-generated` clean locally;
  outputs pasted into the PR (E-04).
- [ ] CI green on the PR: every job listed in plan §13 except `web` and
  `scenarios`.
- [ ] `go run ./cmd/api` with `.env.example` starts, serves `/healthz`,
  logs one JSON status line, exits 0 on SIGTERM; with `PG_URL` unset
  exits non-zero naming `PG_URL` (E-02: run the failure and the success).
- [ ] The Docker image builds and `docker run <image> api --help` prints
  the config variables.
- [ ] `docs/runbooks/dev-setup.md` written and followed from a clean
  checkout.

## Commits

`build: initialise the module on uspace-core v0.2.0 [WP-0 A-M1]`,
`feat(config): load and validate per-process configuration from the environment [WP-0 A-M1]`,
`feat(httpx): server baseline with problem responses and rate limits [WP-0 A-M1]`,
`ci: lint, race, vectors, contract, integration and image jobs [WP-0 A-M1]`,
`build: Dockerfile and the development compose stack [WP-0 A-M1]`.
