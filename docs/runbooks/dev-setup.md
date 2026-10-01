# Development setup

From a clean checkout to a running `api` against the development stack.
Every `make` target is listed with the command it runs, for machines
without `make` (the Windows toolchain of this project has none).

## 1. Prerequisites

- Go 1.27 (`go version`), with `CGO_ENABLED=0` for builds. The race
  detector (`make race`) needs cgo and a C toolchain for the test binary
  only; where there is none, CI's `test-race` job is the check.
- Docker with Compose v2 (`docker compose version`).
- Git Bash or any POSIX shell for `scripts/*.sh`.
- Network access to the Go module proxy on first use (the module cache
  serves later runs).

On Windows with the Anaconda Go toolchain:

```
export GOROOT=C:/Users/<you>/AppData/Local/anaconda3/go
export PATH=/c/Users/<you>/AppData/Local/anaconda3/bin:$HOME/go/bin:$PATH
```

## 2. Clone and build

```
git clone https://github.com/rootxkit/uspace-authority.git
cd uspace-authority
go build ./...
```

## 3. Linters (once per machine)

`make tools` installs the pinned versions (the ones uspace-core pins):

```
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
go install honnef.co/go/tools/cmd/staticcheck@v0.8.1
go install github.com/zricethezav/gitleaks/v8@v8.24.3
```

`make lint` refuses any other golangci-lint version. Without `make`:

```
gofmt -l .                      # must print nothing
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
golangci-lint run ./...
```

## 4. Tests

| Target | Command |
|---|---|
| `make test` | `go test -count=1 -shuffle=on ./...` |
| `make race` | `CGO_ENABLED=1 go test -race -count=1 -shuffle=on ./...` |
| `make vectors` | `go test -count=1 -run 'Vector\|Manifest\|Version' github.com/rootxkit/uspace-core/...` then the same over `./...` |
| `make verify-generated` | `scripts/verify-generated.sh` (regenerates into a scratch directory and diffs) |
| `make generate` | `scripts/generate.sh` (after editing `api/openapi.yaml`, `sqlc.yaml`, a query under `internal/store/*/queries` or a migration) |

## 5. The development stack

`make up` (`docker compose -f deploy/compose.dev.yaml up -d --wait`)
starts PostGIS, TimescaleDB and NATS (JetStream, file store) and returns
once all three are healthy. Host ports are 56432 (PostGIS), 56433
(TimescaleDB), 56422 and 56822 (NATS client and monitoring), bound to
127.0.0.1; override them with `AUTHORITY_DEV_PG_PORT`,
`AUTHORITY_DEV_TS_PORT`, `AUTHORITY_DEV_NATS_PORT` and
`AUTHORITY_DEV_NATS_MON_PORT` if another stack holds them. `make down`
removes the containers and their volumes.

Apply both migration trees (`make migrate`), as the one-shot `migrate`
service does in a deployment; no long-running process migrates:

```
set -a; . deploy/.env.example; set +a
go run ./cmd/uspace-authority migrate
```

It logs one `tree at version` line per tree (`goose_db_version_relational`,
`goose_db_version_timeseries`) and exits 0. The migrations create the
NOLOGIN roles the processes work as when they do not exist yet
(`authority_app` in the relational database; `authority_ts_reader` and
`authority_ts_writer` in the telemetry one); each process `SET ROLE`s on
connect (`PG_ROLE` for `api`), so the login user must be a member. The
development stack logs in as the superuser, which is. Then the integration tests
(`make integration`):

```
INTEGRATION=1 go test -count=1 -run Integration -v ./...
```

Without `INTEGRATION=1` they skip and say why. Each integration test
works in a scratch database created from `template0` and migrated
(`internal/store/storetest`), dropped when it ends.

## 6. Run a process

```
set -a; . deploy/.env.example; set +a
go run ./cmd/api
```

The first line is `started` with the configuration (secrets redacted);
a `status` line follows at once and then every `STATUS_INTERVAL_S`.
`curl 127.0.0.1:9090/healthz` answers `{"status":"ok"}`; `/readyz` lists
the readiness checks (`relational`); `/metrics` is the Prometheus text.
The status line carries `policy_version` once api has read the active
policy. On `API_ADDR` (127.0.0.1:8080) `/v1/policy*` and
`/v1/audit/events` answer `401 unauthenticated` until WP-2 brings
console sessions; any other path answers a `not_found` problem. Started
without the relational database (or below the schema version it needs),
api logs `process failed` naming it and exits 1. SIGTERM (or Ctrl-C) drains within `SHUTDOWN_TIMEOUT_S` and exits
0 with a `stopped` line. With a required variable missing the process
writes one `configuration invalid` line naming it and exits 2.

`go run ./cmd/<process> --help` lists every variable a process reads.

## 7. The image

`make image` (`docker build -t ghcr.io/rootxkit/uspace-authority:dev .`)
builds one image holding the seven processes and the `migrate`
subcommand:

```
docker run --rm ghcr.io/rootxkit/uspace-authority:dev api --help
docker run --rm --env-file deploy/.env.example -e ADMIN_ADDR=:9090 -e API_ADDR=:8080 \
  -p 127.0.0.1:9090:9090 ghcr.io/rootxkit/uspace-authority:dev api
```

The build fails if any binary links `internal/ltest`. CI builds, signs
and pushes the image on `main` and `v*` tags only.
