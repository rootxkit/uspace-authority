#!/usr/bin/env bash
# Restores the newest complete backup of deploy/backup.sh into scratch
# databases and says what came back (docs/PLAN.md section 10, WP-24; the
# predecessor's P0-09 restore rehearsal):
#
#   deploy/restore-check.sh <backup directory>
#
# The newest stamp with all three files (authority-<stamp>.dump,
# authority_ts-<stamp>.dump, nats-kv-<stamp>.jsonl) is restored inside
# the compose project's postgres container (the server's own pg_restore)
# into authority_restore_check and authority_ts_restore_check, created
# for the check and dropped after it, also on failure; the TimescaleDB
# dump through timescaledb_pre_restore() and timescaledb_post_restore().
# Then it counts the rows of events, uas_operators and rid_observations
# in the restored copies, decodes every KV value of the export, and
# prints the counts. It never says "ok" without the numbers (E-02).
#
# It fails when a restore fails, when the restored audit log is empty (a
# deployed authority always has events: the bootstrap and every
# sign-in), when a KV value does not decode, or, with
# RESTORE_CHECK_EXPECT set (CI: "events=N,uas_operators=M,rid_observations=K",
# the counts read from the live databases when the dump was taken), when a
# count differs.
#
# The scratch databases live in the production container for the length
# of the check: about the size of the databases again, on the same disk
# (docs/runbooks/staging.md, "Backups").
#
# Environment: AUTHORITY_COMPOSE_PROJECT (uspace-authority),
# RESTORE_CHECK_EXPECT.
set -euo pipefail

dir="${1:?usage: deploy/restore-check.sh <backup directory>}"
project="${AUTHORITY_COMPOSE_PROJECT:-uspace-authority}"
expect="${RESTORE_CHECK_EXPECT:-}"
rel=authority_restore_check
ts=authority_ts_restore_check

die() { echo "restore-check: FAIL $*" >&2; exit 1; }

pg="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter label=com.docker.compose.service=postgres)"
[ -n "$pg" ] || die "no running postgres container in compose project $project"
[ "$(printf '%s\n' "$pg" | wc -l)" -eq 1 ] || die "more than one postgres container in compose project $project"

# The newest stamp with all three files.
stamp=""
for f in $(find "$dir" -maxdepth 1 -type f -name 'authority-*.dump' | sort -r); do
  s="$(basename "$f" .dump)"
  s="${s#authority-}"
  if [ -s "$dir/authority_ts-$s.dump" ] && [ -s "$dir/nats-kv-$s.jsonl" ]; then stamp="$s"; break; fi
done
[ -n "$stamp" ] || die "no complete backup (authority, authority_ts and nats-kv of one stamp) in $dir"
echo "restore-check: backup $stamp from $dir"

psql_q() { # <database> <sql>: one value
  docker exec -e PGOPTIONS='-c client_min_messages=warning' "$pg" psql -v ON_ERROR_STOP=1 -X -q -U postgres -d "$1" -tAc "$2"
}
drop_scratch() {
  psql_q postgres "DROP DATABASE IF EXISTS $rel WITH (FORCE)" >/dev/null
  psql_q postgres "DROP DATABASE IF EXISTS $ts WITH (FORCE)" >/dev/null
}
# shellcheck disable=SC2317 # run by the EXIT trap
cleanup() {
  local rc=$?
  if ! drop_scratch; then
    echo "restore-check: FAIL the scratch databases could not be dropped" >&2
    rc=1
  elif [ -n "$(psql_q postgres "SELECT datname FROM pg_database WHERE datname IN ('$rel', '$ts')")" ]; then
    echo "restore-check: FAIL a scratch database is still present after the drop" >&2
    rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT

drop_scratch
psql_q postgres "CREATE DATABASE $rel" >/dev/null
psql_q postgres "CREATE DATABASE $ts" >/dev/null

# --exit-on-error: a restore that half-worked is a failure, not a count.
if ! out="$(docker exec -i "$pg" pg_restore --exit-on-error -U postgres -d "$rel" < "$dir/authority-$stamp.dump" 2>&1)"; then
  die "pg_restore of authority-$stamp.dump: $(printf '%s' "$out" | tail -n 3 | tr '\n' ' ')"
fi
psql_q "$ts" "CREATE EXTENSION IF NOT EXISTS timescaledb" >/dev/null
psql_q "$ts" "SELECT timescaledb_pre_restore()" >/dev/null
# The dump re-creates the extension it was taken with; the one created
# above is that extension, so its CREATE EXTENSION is the one error the
# TimescaleDB restore procedure expects. Every other error fails.
rc=0
out="$(docker exec -i "$pg" pg_restore -U postgres -d "$ts" < "$dir/authority_ts-$stamp.dump" 2>&1)" || rc=$?
psql_q "$ts" "SELECT timescaledb_post_restore()" >/dev/null
if [ "$rc" -ne 0 ]; then
  others="$(printf '%s\n' "$out" | grep -E '^pg_restore: error:' | grep -v 'extension "timescaledb" already exists' || true)"
  if [ -n "$others" ]; then
    die "pg_restore of authority_ts-$stamp.dump: $(printf '%s' "$others" | head -n 3 | tr '\n' ' ')"
  fi
fi

events="$(psql_q "$rel" "SELECT count(*) FROM events")"
operators="$(psql_q "$rel" "SELECT count(*) FROM uas_operators")"
observations="$(psql_q "$ts" "SELECT count(*) FROM rid_observations")"
hypertables="$(psql_q "$ts" "SELECT count(*) FROM timescaledb_information.hypertables")"

# The KV export: every line parses and every value decodes.
kv_lines="$(wc -l < "$dir/nats-kv-$stamp.jsonl" | tr -d ' ')"
# tr -d '\r': a Windows jq ends its lines with CRLF.
kv_buckets="$(jq -r .bucket "$dir/nats-kv-$stamp.jsonl" | tr -d '\r' | sort -u | wc -l | tr -d ' ')"
if ! jq -r .value_b64 "$dir/nats-kv-$stamp.jsonl" | tr -d '\r' | while IFS= read -r v; do printf '%s' "$v" | base64 -d >/dev/null || exit 1; done; then
  die "a value of nats-kv-$stamp.jsonl does not decode"
fi

echo "restore-check: restored $stamp: events=$events uas_operators=$operators rid_observations=$observations hypertables=$hypertables nats_kv_keys=$kv_lines nats_kv_buckets=$kv_buckets"

[ "$events" -gt 0 ] || die "the restored audit log is empty (events=0)"
if [ -n "$expect" ]; then
  got="events=$events,uas_operators=$operators,rid_observations=$observations"
  [ "$got" = "$expect" ] || die "counts $got, expected $expect"
  echo "restore-check: the counts equal the live databases' at the dump ($expect)"
fi
