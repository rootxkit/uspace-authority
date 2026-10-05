#!/usr/bin/env bash
# The deploy/ checks (`make check-deploy`, CI job `deploy`), none of which
# starts the stack (deploy/smoke/run.sh does, in its own job):
#
#   1. shellcheck of every deploy script;
#   2. deploy/env/*.env.example regenerated and compared (the catalogue
#      cannot drift from the processes' --help);
#   3. deploy/compose.yaml rendered by `docker compose config` with
#      deploy/compose.env.example and placeholder secrets, and read back
#      per service (jq): no published port; a memory limit, read-only
#      root and no capabilities everywhere it applies; one image for
#      every Go process; each process given only the DSN of the database
#      it opens (CLAUDE.md rule 10) and its own NATS user; only api,
#      rid-ingest, dp-poller, picture-ws and web on Caddy's edge network,
#      the project network internal; AUTHORITY_TRUSTED_PROXIES single
#      hosts (the edge Caddy, and web for api), never a range; refused
#      without an image or a host (fail closed);
#   4. deploy/staging.env.example holds no DSN and no secret;
#   5. deploy/caddy/proof.sh against the pinned Caddy.
#
# Needs docker, jq, go and, for step 1, shellcheck: without shellcheck
# step 1 says SKIPPED, and CI (where it is installed) never skips.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "check-deploy: FAIL $*" >&2; exit 1; }

scripts=(deploy/gen-secrets.sh deploy/deploy.sh deploy/verify-image.sh deploy/backup.sh deploy/restore-check.sh
  deploy/caddy/proof.sh deploy/smoke/run.sh deploy/fetch-ground.sh scripts/check-deploy.sh scripts/gen-env-catalog.sh)
if type -P shellcheck >/dev/null 2>&1; then
  shellcheck "${scripts[@]}"
  echo "check-deploy: shellcheck ok (${#scripts[@]} scripts)"
elif [ -n "${CI:-}" ]; then
  fail "shellcheck is not installed in CI"
else
  echo "check-deploy: shellcheck SKIPPED, not installed"
fi
type -P jq >/dev/null 2>&1 || fail "jq is not installed"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
if type -P cygpath >/dev/null 2>&1; then tmp="$(cygpath -m "$tmp")"; fi

# 2. The catalogue.
scripts/gen-env-catalog.sh "$tmp/env" >/dev/null
if ! diff -ru deploy/env "$tmp/env"; then
  fail "deploy/env is out of date: run scripts/gen-env-catalog.sh and commit the result"
fi
echo "check-deploy: deploy/env matches every process's --help ($(find deploy/env -name '*.env.example' | wc -l | tr -d ' ') catalogues)"

# 3. The secrets directory in the shape gen-secrets.sh writes it, with
# placeholder values (no real secret): compose reads the env files when
# it renders.
s="$tmp/secrets"
mkdir -p "$s/keys" "$s/nats"
printf 'POSTGRES_PASSWORD=placeholder\n' > "$s/db.env"
printf 'PG_URL=postgres://postgres:placeholder@postgres:5432/authority?sslmode=disable\n' > "$s/relational.env"
printf 'TS_URL=postgres://postgres:placeholder@postgres:5432/authority_ts?sslmode=disable\n' > "$s/timeseries.env"
printf 'WEB_MFA_CHALLENGE_SECRET=placeholder\n' > "$s/web.env"
go=(api rid-ingest dp-poller manned-ingest detect tsdb-writer picture-ws)
for p in "${go[@]}" backup; do printf 'NATS_URL=nats://%s:placeholder@nats:4222\n' "$p" > "$s/nats/$p.env"; done
: > "$s/nats/users.conf"

render() { # the rendered compose as JSON
  AUTHORITY_SECRETS_DIR="$s" docker compose --env-file deploy/compose.env.example -f deploy/compose.yaml config --format json
}
render > "$tmp/r.json"
j() { jq -j "$@" "$tmp/r.json" | tr -d '\r'; }

services="$(j '[.services | keys[]] | join(" ")')"
want_services="api detect dp-poller manned-ingest migrate nats picture-ws postgres rid-ingest tsdb-writer web"
[ "$services" = "$want_services" ] || fail "services are '$services', want '$want_services'"

[ "$(j '[.services[] | select(.ports != null and (.ports | length) > 0)] | length')" = 0 ] || fail "a service publishes a port"
[ "$(j '[.services[] | select(.deploy.resources.limits.memory == null)] | length')" = 0 ] || fail "a service has no memory limit"
[ "$(j '[.services[] | select(.deploy.resources.limits.cpus == null)] | length')" = 0 ] || fail "a service has no CPU limit"
no_ro="$(j '[.services | to_entries[] | select(.key != "postgres" and .value.read_only != true) | .key] | join(" ")')"
[ -z "$no_ro" ] || fail "no read-only root filesystem: $no_ro"
caps="$(j '[.services | to_entries[] | select(.key != "postgres" and .key != "nats" and ((.value.cap_drop // []) | index("ALL")) == null) | .key] | join(" ")')"
[ -z "$caps" ] || fail "capabilities not dropped: $caps"
limits="$(j '[.services[] | .deploy.resources.limits.memory | tonumber] | add')"
echo "check-deploy: compose renders: $services; no published port; memory and CPU limits on all ($((limits / 1048576)) MiB in all), read-only roots"

# shellcheck disable=SC2016 # $k is jq's
images="$(j '[.services | to_entries[] | select(.key as $k | ["migrate","api","rid-ingest","dp-poller","manned-ingest","detect","tsdb-writer","picture-ws"] | index($k)) | .value.image] | unique | length')"
[ "$images" = 1 ] || fail "the Go processes run $images different images"

# DSNs: migrate and api both, the telemetry processes TS_URL only,
# manned-ingest and the rest none.
got="$(j '.services | to_entries[] | "\(.key) \((.value.environment.PG_URL // "") != "") \((.value.environment.TS_URL // "") != "")\n"' | sort)"
want="api true true
detect false true
dp-poller false true
manned-ingest false false
migrate true true
nats false false
picture-ws false true
postgres false false
rid-ingest false true
tsdb-writer false true
web false false"
[ "$got" = "$want" ] || fail "the DSNs per service (service PG_URL TS_URL) are
$got
want
$want"
echo "check-deploy: DSNs per process: migrate and api both, the five telemetry processes TS_URL only, manned-ingest and web none"

# One NATS user per process, named after it; none for migrate and web.
got="$(j '.services | to_entries[] | select(.value.environment.NATS_URL != null) | "\(.key) \(.value.environment.NATS_URL | capture("^nats://(?<u>[^:]+):").u)\n"' | sort)"
want="$(for p in "${go[@]}"; do echo "$p $p"; done | sort)"
[ "$got" = "$want" ] || fail "the NATS users per service are
$got
want
$want"
echo "check-deploy: every Go process has its own NATS user; migrate and web have none"

# Networks.
edge="$(j '[.services | to_entries[] | select((.value.networks // {}) | has("edge")) | .key] | sort | join(" ")')"
[ "$edge" = "api dp-poller picture-ws rid-ingest web" ] || fail "on the edge network: '$edge'"
[ "$(j '.networks.authority.internal')" = true ] || fail "the project network is not internal"
[ "$(j '.networks.edge.external')" = true ] || fail "the edge network is not the deployment's (external)"
egress="$(j '[.services | to_entries[] | select((.value.networks // {}) | has("egress")) | .key] | sort | join(" ")')"
[ "$egress" = "detect manned-ingest" ] || fail "on the egress network: '$egress'"
echo "check-deploy: edge network: $edge; egress: $egress; the project network is internal"

# AUTHORITY_TRUSTED_PROXIES: single hosts only.
host_only() { # <comma-separated entries>
  local e entries
  IFS=, read -ra entries <<<"$1"
  [ "${#entries[@]}" -gt 0 ] || return 1
  for e in "${entries[@]}"; do
    e="${e// /}"
    case "$e" in
      "") return 1 ;;
      */32 | */128) ;;
      */*) return 1 ;;
    esac
  done
}
# The guard itself (E-01): a range is refused, a host is accepted.
if host_only 172.18.0.0/16 || host_only "192.0.2.2/32,10.0.0.0/8" || ! host_only "192.0.2.2/32,2001:db8::2"; then
  fail "host_only does not tell a host from a range"
fi
while IFS= read -r line; do
  svc="${line%% *}"; p="${line#* }"
  host_only "$p" || fail "$svc: AUTHORITY_TRUSTED_PROXIES is '$p': list the edge Caddy's own address, not a range"
done < <(j '.services | to_entries[] | select(.value.environment.AUTHORITY_TRUSTED_PROXIES != null) | "\(.key) \(.value.environment.AUTHORITY_TRUSTED_PROXIES)\n"')
[ "$(j '.services.api.environment.AUTHORITY_TRUSTED_PROXIES')" = "192.0.2.2/32,192.0.2.3/32" ] || fail "api does not trust exactly the edge Caddy and web"
[ "$(j '.services["rid-ingest"].environment.AUTHORITY_TRUSTED_PROXIES')" = "192.0.2.2/32" ] || fail "rid-ingest does not trust exactly the edge Caddy"
echo "check-deploy: AUTHORITY_TRUSTED_PROXIES: single hosts only (the edge Caddy; api also web)"
[ "$(j '.services.api.environment.AUTHORITY_PUBLIC_URL')" = "https://authority.example.test" ] || fail "AUTHORITY_PUBLIC_URL is not https://AUTHORITY_HOST"
[ "$(j '.services.api.environment.AUTHORITY_MTLS_MODE')" = "off" ] || fail "staging.env.example does not say AUTHORITY_MTLS_MODE=off"

# Fail closed: no image, no host, no secrets directory.
for v in AUTHORITY_IMAGE AUTHORITY_WEB_IMAGE AUTHORITY_HOST AUTHORITY_CADDY_IP; do
  if env "$v=" AUTHORITY_SECRETS_DIR="$s" docker compose --env-file deploy/compose.env.example -f deploy/compose.yaml config >/dev/null 2>"$tmp/err"; then
    fail "compose rendered with $v empty"
  fi
done
if docker compose --env-file deploy/compose.env.example -f deploy/compose.yaml config >/dev/null 2>"$tmp/err"; then
  fail "compose rendered without AUTHORITY_SECRETS_DIR"
fi
echo "check-deploy: compose refuses to render without an image, the host, the Caddy address or the secrets directory"

# The smoke override renders on top (the CI smoke's shape).
AUTHORITY_SECRETS_DIR="$s" SMOKE_DIR="$tmp" docker compose --env-file deploy/compose.env.example \
  -f deploy/compose.yaml -f deploy/smoke/compose.smoke.yaml config --quiet || fail "the smoke override does not render"
echo "check-deploy: deploy/smoke/compose.smoke.yaml renders over compose.yaml"

# The development stack holds both databases in one container, as staging
# does (M37): one database service, the same image.
docker compose -f deploy/compose.dev.yaml config --format json > "$tmp/dev.json"
dev_db="$(jq -j '[.services | to_entries[] | select(.value.image | startswith("timescale/timescaledb-ha")) | .key] | join(" ")' "$tmp/dev.json" | tr -d '\r')"
[ "$dev_db" = postgres ] || fail "deploy/compose.dev.yaml's database services are '$dev_db', want the one postgres"
[ "$(jq -j '.services.postgres.image' "$tmp/dev.json" | tr -d '\r')" = "$(j '.services.postgres.image')" ] ||
  fail "the development stack's database image differs from staging's"
echo "check-deploy: the development stack holds both databases in one container of staging's image"

# 4. No DSN or secret in the settings template.
if grep -nE '^(PG_URL|TS_URL|NATS_URL|POSTGRES_PASSWORD|WEB_MFA_CHALLENGE_SECRET)=|(PASSWORD|SECRET|TOKEN)=[^ ]' deploy/staging.env.example; then
  fail "deploy/staging.env.example holds a DSN or a secret"
fi
echo "check-deploy: deploy/staging.env.example holds no DSN and no secret"

# 5. The Caddy snippet, against the running Caddy.
deploy/caddy/proof.sh
