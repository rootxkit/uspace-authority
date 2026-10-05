#!/usr/bin/env bash
# The staging smoke (WP-24; `make staging-smoke`, CI job `staging-smoke`):
# deploy/compose.yaml brought up from scratch the way deploy/deploy.sh
# deploys it, behind the edge Caddy with deploy/caddy/authority.snippet,
# then exercised through the public host, backed up, restored, and torn
# down. Every step says what it saw; any step that fails stops the run.
#
#   SMOKE_GO_IMAGE=uspace-authority:smoke SMOKE_WEB_IMAGE=uspace-authority-web:smoke \
#   SMOKE_GROUND_DIR=<dir with egm2008-2_5.pgm> deploy/smoke/run.sh
#
# Steps:
#    1. secrets (deploy/gen-secrets.sh), a throwaway root CA, the edge
#       network with the addresses compose.yaml trusts, the edge Caddy;
#    2. deploy/deploy.sh --unsigned-local-images: migrate (both trees and
#       their versions), the rolling start, the verification; rid-ingest
#       has no receiver yet, so its receiver_keys check is accepted by
#       name and printed;
#    3. the same verification without that acceptance must fail and name
#       rid-ingest's receiver_keys (E-01: the deploy's failure path);
#    4. the Go driver (deploy/smoke): sign-in, the registry fixture,
#       validate status only, one receiver batch accepted, the picture's
#       frames and the aircraft's track; it must pass and not skip;
#    5. the verification again, with nothing accepted: now every process
#       is ready;
#    6. backup (deploy/backup.sh) with the writers paused, so the live
#       counts read beside it are the dump's; restore-check with those
#       counts must pass, and with one count changed must fail;
#    7. a process started against an older schema refuses and names the
#       version (api on the relational tree, tsdb-writer on the
#       timeseries one); the version row is put back after each;
#    8. memory and CPU of every container (docker stats);
#    9. teardown (also on failure): the project's containers, volumes and
#       networks removed, and their absence checked.
#
# SMOKE_VERSION, when set, is the VERSION the images were built with;
# every process must report it. SMOKE_LOG_DIR, when set, receives every
# container's log on failure (the CI artifact).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
deploy="$(cd "$here/.." && pwd)"
repo="$(cd "$deploy/.." && pwd)"
project="${SMOKE_PROJECT:-uspace-authority-smoke}"
edge="${project}-edge"
subnet="${SMOKE_EDGE_SUBNET:-172.31.250.0/24}"
prefix="${subnet%.*}"
port="${SMOKE_HTTPS_PORT:-58443}"
host=authority.smoke.test
go_image="${SMOKE_GO_IMAGE:?the Go image to deploy (a local tag)}"
web_image="${SMOKE_WEB_IMAGE:?the web image to deploy (a local tag)}"
ground="${SMOKE_GROUND_DIR:?a directory holding egm2008-2_5.pgm (deploy/fetch-ground.sh --geoid-only)}"
[ -s "$ground/egm2008-2_5.pgm" ] || { echo "smoke: $ground/egm2008-2_5.pgm is missing" >&2; exit 2; }

work="$(mktemp -d)"
if type -P cygpath >/dev/null 2>&1; then
  work="$(cygpath -m "$work")"
  ground="$(cygpath -m "$ground")"
  repo="$(cygpath -m "$repo")"
fi
step() { echo; echo "smoke: ---- $*"; }
fail() { echo "smoke: FAIL $*" >&2; exit 1; }

dc() {
  docker compose -p "$project" --env-file "$work/deploy.env" \
    -f "$deploy/compose.yaml" -f "$here/compose.smoke.yaml" "$@"
}

# shellcheck disable=SC2317 # run by the EXIT trap
teardown() {
  local rc=$? left
  echo
  echo "smoke: ---- teardown"
  if [ "$rc" -ne 0 ] && [ -n "${SMOKE_LOG_DIR:-}" ] && [ -f "$work/deploy.env" ]; then
    mkdir -p "$SMOKE_LOG_DIR"
    for s in $(dc config --services 2>/dev/null); do
      dc logs --no-log-prefix "$s" > "$SMOKE_LOG_DIR/$s.log" 2>&1 || true
    done
    echo "smoke: container logs written to $SMOKE_LOG_DIR"
  fi
  if [ -f "$work/deploy.env" ]; then
    dc down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  docker network rm "$edge" >/dev/null 2>&1 || true
  left="$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
  left+="$(docker volume ls -q --filter "label=com.docker.compose.project=$project")"
  left+="$(docker network ls -q --filter "name=^${edge}\$")"
  rm -rf "$work"
  if [ -n "$left" ]; then
    echo "smoke: FAIL containers, volumes or networks of $project are still present after teardown" >&2
    rc=1
  else
    echo "smoke: teardown verified: no container, volume or network of $project is left"
  fi
  exit "$rc"
}
trap teardown EXIT

# ---- 1 -----------------------------------------------------------------------
step "1. secrets, CA, edge network, Caddy"
"$deploy/gen-secrets.sh" "$work/secrets"
mkdir -p "$work/ca" "$work/basemap" "$work/state" "$work/backups"
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/O=uspace-authority smoke/CN=smoke root" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$work/ca/ca.key" -out "$work/ca/ca.pem" >/dev/null 2>&1
chmod 0644 "$work/ca/ca.key" "$work/ca/ca.pem"
printf '{"release":"smoke"}\n' > "$work/basemap/SOURCE.json"
cat > "$work/deploy.env" <<EOF
AUTHORITY_IMAGE=$go_image
AUTHORITY_WEB_IMAGE=$web_image
AUTHORITY_HOST=$host
CISP_HOST=cisp.smoke.invalid
ANSP_HOST=ansp.smoke.invalid
LAB_HOST=lab.smoke.invalid
AUTHORITY_ENV_FILE=$repo/deploy/staging.env.example
AUTHORITY_SECRETS_DIR=$work/secrets
AUTHORITY_GROUND_DIR=$ground
AUTHORITY_EDGE_NETWORK=$edge
AUTHORITY_CADDY_IP=$prefix.2
AUTHORITY_WEB_IP=$prefix.3
AUTHORITY_CA_BUNDLE=/etc/smoke/ca.pem
SMOKE_DIR=$work
SMOKE_HTTPS_PORT=$port
EOF
docker network create --subnet "$subnet" --ip-range "$prefix.128/25" "$edge" >/dev/null
echo "smoke: edge network $edge ($subnet; Caddy $prefix.2, web $prefix.3)"
dc up -d --no-deps --wait caddy >/dev/null 2>&1 || fail "the edge Caddy did not become healthy: $(dc logs --no-log-prefix --tail 5 caddy 2>&1 | tr '\n' ' ')"
echo "smoke: edge Caddy healthy on 127.0.0.1:$port"

deploy_args=(--env-file "$work/deploy.env" --project "$project" -f "$here/compose.smoke.yaml")
export AUTHORITY_EXPECT_VERSION="${SMOKE_VERSION:-}"

# ---- 2 -----------------------------------------------------------------------
step "2. deploy.sh (local images)"
"$deploy/deploy.sh" "${deploy_args[@]}" --unsigned-local-images --accept-not-ready rid-ingest:receiver_keys

# ---- 3 -----------------------------------------------------------------------
step "3. the verification without the acceptance fails and names the check"
rc=0
out="$("$deploy/deploy.sh" "${deploy_args[@]}" --verify-only 2>&1)" || rc=$?
printf '%s\n' "$out" | grep -E 'FAIL|ok, every' || true
if [ "$rc" -eq 0 ] || ! grep -q 'FAIL rid-ingest: /readyz receiver_keys not ready' <<<"$out"; then
  fail "deploy.sh --verify-only exited $rc without naming rid-ingest's receiver_keys"
fi
echo "smoke: refused as it should be (exit $rc, rid-ingest receiver_keys named)"

# ---- 4 -----------------------------------------------------------------------
step "4. the Go driver through the public host"
rc=0
(cd "$repo" && STAGING_SMOKE=1 STAGING_SMOKE_URL="https://$host" STAGING_SMOKE_CONNECT="127.0.0.1:$port" \
  STAGING_SMOKE_CA_FILE="$work/ca/ca.pem" STAGING_SMOKE_ADMIN_PASSWORD_FILE="$work/secrets/keys/admin.pw" \
  STAGING_SMOKE_STATE_DIR="$work/state" STAGING_SMOKE_GEOID_FILE="$ground/egm2008-2_5.pgm" \
  go test -count=1 -run '^TestStagingSmoke$' -v ./deploy/smoke) > "$work/driver.log" 2>&1 || rc=$?
cat "$work/driver.log"
[ "$rc" -eq 0 ] || fail "the driver exited $rc"
if grep -q -- '--- SKIP' "$work/driver.log"; then fail "the driver skipped with STAGING_SMOKE=1"; fi
grep -q -- '--- PASS: TestStagingSmoke' "$work/driver.log" || fail "the driver did not report PASS"

# ---- 5 -----------------------------------------------------------------------
step "5. the verification with nothing accepted"
"$deploy/deploy.sh" "${deploy_args[@]}" --verify-only

# ---- 6 -----------------------------------------------------------------------
step "6. backup and restore check"
# The writers paused, so nothing changes between the counts and the dump.
writers=(api tsdb-writer rid-ingest detect dp-poller manned-ingest picture-ws)
dc pause "${writers[@]}" >/dev/null
count() { dc exec -T postgres psql -X -U postgres -d "$1" -tAc "SELECT count(*) FROM $2" | tr -d '\r'; }
expect="events=$(count authority events),uas_operators=$(count authority uas_operators),rid_observations=$(count authority_ts rid_observations)"
echo "smoke: live counts with the writers paused: $expect"
rc=0
AUTHORITY_COMPOSE_PROJECT="$project" AUTHORITY_SECRETS_DIR="$work/secrets" "$deploy/backup.sh" "$work/backups" || rc=$?
dc unpause "${writers[@]}" >/dev/null
[ "$rc" -eq 0 ] || fail "backup.sh exited $rc"
AUTHORITY_COMPOSE_PROJECT="$project" RESTORE_CHECK_EXPECT="$expect" "$deploy/restore-check.sh" "$work/backups"
events="${expect#events=}"
events="${events%%,*}"
wrong="events=$((events + 1)),${expect#*,}"
rc=0
out="$(AUTHORITY_COMPOSE_PROJECT="$project" RESTORE_CHECK_EXPECT="$wrong" "$deploy/restore-check.sh" "$work/backups" 2>&1)" || rc=$?
printf '%s\n' "$out" | tail -n 2
if [ "$rc" -eq 0 ] || ! grep -q "expected $wrong" <<<"$out"; then
  fail "restore-check accepted counts that differ ($wrong)"
fi
echo "smoke: restore-check refuses counts that differ (exit $rc)"

# ---- 7 -----------------------------------------------------------------------
step "7. a process against an older schema refuses and names the version"
refuses() { # <database> <version table> <service> <tree>
  local db="$1" table="$2" svc="$3" tree="$4" v older id out rc=0
  v="$(dc exec -T postgres psql -X -U postgres -d "$db" -tAc "SELECT version_id FROM $table ORDER BY id DESC LIMIT 1" | tr -d '\r')"
  older=$((v - 1))
  id="$(dc exec -T postgres psql -X -q -U postgres -d "$db" -tAc "INSERT INTO $table (version_id, is_applied) VALUES ($older, true) RETURNING id" | head -n 1 | tr -d '\r')"
  out="$(timeout 120 docker compose -p "$project" --env-file "$work/deploy.env" -f "$deploy/compose.yaml" -f "$here/compose.smoke.yaml" \
    run --rm --no-deps -T "$svc" 2>&1)" || rc=$?
  dc exec -T postgres psql -X -q -U postgres -d "$db" -tAc "DELETE FROM $table WHERE id = $id" >/dev/null
  [ "$(dc exec -T postgres psql -X -U postgres -d "$db" -tAc "SELECT version_id FROM $table ORDER BY id DESC LIMIT 1" | tr -d '\r')" = "$v" ] ||
    fail "the $tree version row was not put back"
  local want="$tree schema is at version $older, this build needs $v"
  if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ] || ! grep -q "$want" <<<"$out"; then
    printf '%s\n' "$out" | tail -n 5
    fail "$svc against $tree version $older exited $rc without saying '$want'"
  fi
  echo "smoke: $svc refused (exit $rc): $want"
}
refuses authority goose_db_version_relational api relational
refuses authority_ts goose_db_version_timeseries tsdb-writer timeseries

# ---- 8 -----------------------------------------------------------------------
step "8. memory and CPU (docker stats, after the smoke)"
mapfile -t ids < <(docker ps -q --filter "label=com.docker.compose.project=$project")
docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' "${ids[@]}" |
  sed "s/^$project-//" | sort | tee "$work/stats.txt"
total="$(awk -F'\t' '{print $2}' "$work/stats.txt" |
  awk '{v=$1; u=v; gsub(/[0-9.]/,"",u); gsub(/[A-Za-z]/,"",v); m=(u=="GiB")?v*1024:(u=="KiB")?v/1024:v; s+=m} END {printf "%.0f", s}')"
echo "smoke: $total MiB in containers"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### staging smoke"
    echo
    echo "Every step passed; restore-check counts: \`$expect\`; $total MiB in containers after the smoke."
    echo
    echo '| container | memory | CPU |'
    echo '|---|---|---|'
    awk -F'\t' '{print "| " $1 " | " $2 " | " $3 " |"}' "$work/stats.txt"
  } >> "$GITHUB_STEP_SUMMARY"
fi

echo
echo "smoke: ok, every step passed"
