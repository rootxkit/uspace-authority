# Staging: deploy, verify, back up, restore

WP-24. How uspace-authority runs on the staging droplet from the images
CI publishes, how a deploy is verified, and how the nightly backup and
its restore check work. The cutover from the predecessor is
`cutover.md`.

The droplet is shared by the five systems and composed by the private
deployment repository `uspace-deploy` (plan D1). This repository gives
it the shape and the tools; nothing here names the staging host except
`deploy/staging/hosts.env`.

| File | What it is |
|---|---|
| `deploy/compose.yaml` | the staging and production shape: seven processes, `migrate`, `web`, one timescaledb-ha container with both databases, NATS, named volumes, limits, networks |
| `deploy/compose.env.example` | the deployment's variables, placeholders only (`make check-deploy` renders with it) |
| `deploy/staging.env.example` | the operator's settings for staging (`AUTHORITY_ENV_FILE`), GCAA's open choices marked |
| `deploy/env/<process>.env.example` | every variable each process reads, generated from `--help` and checked in CI |
| `deploy/gen-secrets.sh` | the secrets directory, generated on the host, never replacing a file |
| `deploy/caddy/authority.snippet` | this system's Caddy site, proved by `deploy/caddy/proof.sh` |
| `deploy/verify-image.sh` | cosign signature and SBOM attestation of both images, by digest |
| `deploy/deploy.sh` | verify, pull, migrate, rolling restart, then verify every process |
| `deploy/backup.sh`, `deploy/restore-check.sh` | the nightly backup and its restore into scratch databases |
| `deploy/fixtures/operator.json` | the lab's registry fixture (REG-NOPII) |
| `deploy/smoke/` | the CI proof: all of the above against a stack brought up from scratch |

## Policy defaults pending GCAA

GCAA has not answered its policy questions. Every value it owns is the
spec's default, kept in configuration and marked **pending GCAA** where
it is set (`deploy/staging.env.example`, the processes' own help, the
status line's `retention_pending_gcaa`):

| Choice | Default | Where |
|---|---|---|
| Telemetry online, archive, violations, audit retention (Q8) | 90 days, 2 years, 5 years, 10 years; incidents indefinite | `RETENTION_*` |
| Registry of record, public portal (Q4, Q-A11) | portal and operator links off | `REGISTRY_APPLICATIONS`, `REGISTRY_OPERATOR_REPORTS` |
| Police purposes and their PII subset (Q8, Q-A14) | the spec's four, two with PII | `POLICE_PURPOSES`, `POLICE_PII_PURPOSES`, `WEB_POLICE_*` |
| Personal-data purposes in the console | the spec's three | `WEB_PII_PURPOSES` |
| How long backups are kept (spec 05 section 4) | 14 days | `AUTHORITY_BACKUP_KEEP_DAYS` |

## Images

On every push to `main` and every `v*` tag, after every gate including
the staging smoke, CI's `image` job builds both images, pushes them to
`ghcr.io/rootxkit/uspace-authority` and `ghcr.io/rootxkit/uspace-authority-web`
(tags `sha-<short>` and the `v*` tag), signs each digest with cosign
(keyless, GitHub's OIDC issuer) and verifies the signature; the `sbom`
job makes an SPDX SBOM of each with syft, and the `attest` job attaches
it as a signed attestation and verifies that. The web image is built
with `pnpm --frozen-lockfile` in CI, never on the server.

`deploy/verify-image.sh` checks both, by digest, against this
repository's `ci.yml` identity on `main` or a `v*` tag:

```
deploy/verify-image.sh ghcr.io/rootxkit/uspace-authority@sha256:<digest> \
                       ghcr.io/rootxkit/uspace-authority-web@sha256:<digest>
```

## First deploy, once

On the droplet, as the deploy user, with a checkout of this repository
at the commit of the images (uspace-deploy vendors the files instead):

1. Secrets, outside the checkout:
   `deploy/gen-secrets.sh /srv/uspace/secrets/authority`. It prints the
   files it wrote and kept, never a value. Run it again at any time: an
   existing file is kept.
2. Ground: `deploy/fetch-ground.sh --geoid-only /srv/uspace/data/ground`
   (the EGM2008 grid, SHA-256-pinned; terrain tiles when the lab
   publishes them, `docs/runbooks/ground.md`).
3. The deployment env file (uspace-deploy holds it): the variables of
   `deploy/compose.env.example` with the real digests, paths, edge
   network and the edge Caddy's fixed address, plus
   `deploy/staging/hosts.env`.
4. The settings: a copy of `deploy/staging.env.example` as
   `AUTHORITY_ENV_FILE`.
5. `deploy/deploy.sh --env-file <deployment env> --env-file deploy/staging/hosts.env --accept-not-ready rid-ingest:receiver_keys`
   (no receiver is registered yet; the acceptance is printed).
6. Sign in as `admin` (password in `keys/admin.pw`), enrol TOTP, then
   remove `BOOTSTRAP_ADMIN_USERNAME` from the settings and delete
   `keys/admin.pw`. While the variable stays, api logs `bootstrap
   refused` at error level on every start.
7. Create `authority-01` at this issuer (`POST /v1/oauth/clients`),
   write its secret to `keys/authority-01.secret`, uncomment the
   `*_CLIENT_SECRET_FILE` lines of the settings, and deploy again.

## Deploying

```
deploy/deploy.sh --env-file <deployment env> --env-file deploy/staging/hosts.env
```

It renders the compose file, refuses an image that is not by digest,
verifies both signatures and SBOM attestations, pulls by digest, starts
postgres and NATS, runs `migrate` and reads its exit status and the
version it reports for each tree, restarts the processes one at a time
(tsdb-writer, rid-ingest, detect, dp-poller, manned-ingest, api,
picture-ws, web), each answering `/healthz` before the next, and then
verifies every process: `/healthz`, every `/readyz` check, the version
its `started` line names and its last status line. It ends with the list
of what it verified, or exits non-zero naming the check that failed. A
failing readiness check fails the deploy unless it is named with
`--accept-not-ready <service>:<check>`, and an accepted one is printed
as such. `--verify-only` checks a running stack and changes nothing.

Rollback is a deploy of the previous digests: the migrations are
forward-only and every process refuses a schema older than it needs, so
a rollback across a migration needs the backup of the night before it.

## Backups

Nightly, by the host's cron, as the deploy user (one line; cron has no
continuation lines):

```
20 2 * * *  cd /srv/uspace-authority && AUTHORITY_SECRETS_DIR=/srv/uspace/secrets/authority deploy/backup.sh /var/backups/uspace-authority >> /var/log/uspace-authority-backup.log 2>&1 && deploy/restore-check.sh /var/backups/uspace-authority >> /var/log/uspace-authority-backup.log 2>&1
```

`backup.sh` writes `authority-<stamp>.dump` and `authority_ts-<stamp>.dump`
(`pg_dump -Fc` inside the postgres container, read back with
`pg_restore --list` before they are moved into place) and
`nats-kv-<stamp>.jsonl` (every JetStream KV bucket, one line per key,
from the pinned nats-box as the `backup` NATS user). With
`AUTHORITY_BACKUP_REMOTE` (an rclone remote) each file is copied off the
droplet and the copy's size compared; which account holds it is the
owner's open question, and until it is set the run says the files stayed
on the host. Files older than `AUTHORITY_BACKUP_KEEP_DAYS` are removed.

`restore-check.sh` restores the newest complete backup into
`authority_restore_check` and `authority_ts_restore_check` in the same
container (TimescaleDB through `timescaledb_pre_restore()` and
`timescaledb_post_restore()`), counts `events`, `uas_operators` and
`rid_observations`, decodes every KV value, prints the counts, and drops
the scratch databases, also on failure. It fails on an empty audit log.
The log line to look for each morning:

```
restore-check: restored <stamp>: events=<n> uas_operators=<n> rid_observations=<n> hypertables=4 nats_kv_keys=<n> nats_kv_buckets=<n>
```

The scratch databases take about the databases' size again on the same
disk for the length of the check.

To restore for real: stop the processes, create the two databases from
the dumps the same way (`restore-check.sh` shows the commands), run
`deploy.sh`.

## The registry fixture (uspace-lab REG-NOPII)

`deploy/fixtures/operator.json` is the lab's operator: registration
number `GEOTESTLAB0001` with every Art. 14(2) field of a legal person,
its UAS `TESTA00000LAB01`, a receiver and an aircraft, all test data.
The staging smoke registers it through the API (as a registrar it
creates), proves the personal data is held, and that
`GET /v1/registry/validate` answers it `valid` with none of it. Against
a running lab or staging stack:

```
STAGING_SMOKE=1 STAGING_SMOKE_URL=https://<authority host> \
STAGING_SMOKE_ADMIN_PASSWORD_FILE=<keys/admin.pw> STAGING_SMOKE_STATE_DIR=<state dir> \
STAGING_SMOKE_GEOID_FILE=<egm2008-2_5.pgm> [STAGING_SMOKE_CA_FILE=<lab CA>] \
  go test -count=1 -run TestStagingSmoke -v ./deploy/smoke
```

It is idempotent: a second run finds what the first registered. The
state directory keeps what it created (the TOTP secrets of `admin` and
`smoke-registrar`, the `lab-01` client secret, the receiver keys, mode
0600) and `fixture.json`; the lab's conformance target then sets
`AUTHORITY_CONFORMANCE_OPERATOR=GEOTESTLAB0001`.

## The CI proof: `staging-smoke`

`deploy/smoke/run.sh` (CI job `staging-smoke`, `make staging-smoke`)
does all of the above against a stack brought up from scratch: secrets,
the edge Caddy with the snippet at the address the compose trusts,
`deploy.sh` with the two local images (the only run that skips the
signature check, said at every step), the verification refused without
the rid-ingest acceptance, the Go driver through the public host
(sign-in, fixture, validate, one receiver batch accepted, the picture's
status and snapshot frames carrying the aircraft's track), the
verification passing with nothing accepted, backup with the writers
paused and restore-check with the counts read beside it (and refused
with one count changed), api and tsdb-writer refusing an older schema
and naming the version, `docker stats`, and the teardown with its
absence checked.

## Resources

Measured by `deploy/smoke/run.sh` on Docker Desktop (16 CPU, 7.7 GiB VM),
2026-10-05, after the smoke (one receiver, one aircraft), `docker stats`:

| Container | Memory | Limit |
|---|---:|---:|
| postgres (both databases) | 141 MiB | 512 MiB |
| web | 81 MiB | 224 MiB |
| api | 61 MiB | 256 MiB |
| rid-ingest | 42 MiB | 224 MiB |
| tsdb-writer | 24 MiB | 128 MiB |
| manned-ingest | 22 MiB | 64 MiB |
| detect | 20 MiB | 192 MiB |
| dp-poller | 16 MiB | 224 MiB |
| picture-ws | 16 MiB | 128 MiB |
| nats | 14 MiB | 192 MiB |
| **total** | **448 MiB** (Caddy's 13 not counted) | 2144 MiB (+128 migrate, one-shot) |

The limits are uspace-deploy's demo budget (`docs/BUDGET.md`: the
authority's 1920 MiB plus web's 224), within the droplet's 7.6 GB with
the other systems. RSS and CPU at the lab's 100-drone profile are not
measured yet: that is the lab's load run against these images (plan
section 10, budget 1.2 GB RSS), and this table is the idle baseline it
is compared with.

Disk on the droplet (about 18 GB free): the two images about 0.6 GB
(timescaledb-ha 4.4 GB is already there for the other systems), the
tools (nats-box, cosign) 0.3 GB, NATS at most 1 GiB (the demo profile's
`AUTHORITY_NATS_MAX_FILE_STORE`), PostgreSQL WAL 256 MB, container logs
at most 11 x 30 MB, the dumps of 14 nights (a few MB each at demo
traffic) and the restore check's transient copy. The demo fits. Under
sustained load it does not: plan section 8 puts telemetry at up to
5 GB/day uncompressed at 100 drones, kept online 90 days (pending GCAA)
and then archived to `ARCHIVE_URL`, a volume on the same disk. **Before
any sustained load run the droplet needs the 100 GB volume** (uspace-deploy
profile `volume`) or an object store for the archive.
