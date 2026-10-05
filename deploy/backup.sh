#!/usr/bin/env bash
# Nightly backup of uspace-authority (docs/PLAN.md section 10, WP-24),
# run by the host's cron as the deploy user, followed by the restore
# check (docs/runbooks/staging.md, "Backups"):
#
#   20 2 * * *  cd /srv/uspace-authority && deploy/backup.sh /var/backups/uspace-authority \
#                 && deploy/restore-check.sh /var/backups/uspace-authority
#
# Writes, under one UTC stamp:
#
#   authority-<stamp>.dump     relational database (registry, zones, the
#                              hash-chained events, users, clients), pg_dump -Fc
#   authority_ts-<stamp>.dump  TimescaleDB (rid_observations, tracks, the
#                              registry projection), pg_dump -Fc
#   nats-kv-<stamp>.jsonl      every JetStream KV bucket, one line per key
#                              ({"bucket","key","value_b64"}): the receiver
#                              key set, the source-control state, the policy
#                              and the certificate sets the processes follow
#
# The dumps are taken inside the compose project's postgres container, so
# the dump tool is the server's own version. Each file is written under
# a .partial name and checked before it is moved into place (a dump must
# list with pg_restore --list; the KV export must hold one valid JSON line
# per key it listed), so a failed run never leaves a file that looks like
# a backup. The JetStream streams themselves are not backed up: every one
# is bounded by age (the longest is the 1 h track mirror) and what they
# carry is already in the databases.
#
# Off the host: with AUTHORITY_BACKUP_REMOTE set (an rclone remote and
# path), each file is copied there and the copy's size compared. Which
# account holds it is the owner's open question (uspace-deploy D-Q3);
# without it the run says the files stayed on this host.
#
# Then removes this job's complete files older than
# AUTHORITY_BACKUP_KEEP_DAYS (14 by default: how long backups are kept
# is a national choice of spec 05 section 4, pending GCAA, so it is
# configuration). A failed step exits non-zero and leaves older files
# alone. Nothing secret is printed.
#
# Environment: AUTHORITY_COMPOSE_PROJECT (uspace-authority),
# AUTHORITY_SECRETS_DIR (for nats/backup.env, the backup's NATS user),
# AUTHORITY_BACKUP_KEEP_DAYS, AUTHORITY_BACKUP_REMOTE, NATS_BOX_IMAGE.
set -euo pipefail

NATS_BOX_IMAGE="${NATS_BOX_IMAGE:-natsio/nats-box:0.18.0@sha256:abdc9f9f0120bb8adfbf674eb037d1551db55356eb198b7bd4ffed377f6950a6}"
dir="${1:?usage: deploy/backup.sh <backup directory>}"
keep_days="${AUTHORITY_BACKUP_KEEP_DAYS:-14}"
project="${AUTHORITY_COMPOSE_PROJECT:-uspace-authority}"
remote="${AUTHORITY_BACKUP_REMOTE:-}"
secrets="${AUTHORITY_SECRETS_DIR:?the secrets directory (nats/backup.env)}"

die() { echo "backup: $*" >&2; exit 1; }
case "$keep_days" in ''|*[!0-9]*) echo "backup: AUTHORITY_BACKUP_KEEP_DAYS must be a whole number of days" >&2; exit 2 ;; esac
[ -r "$secrets/nats/backup.env" ] || die "$secrets/nats/backup.env is missing (deploy/gen-secrets.sh)"
if [ -n "$remote" ] && ! type -P rclone >/dev/null 2>&1; then
  die "AUTHORITY_BACKUP_REMOTE is set but rclone is not installed"
fi
mkdir -p "$dir"

# container <service>: the one running container of that service.
container() {
  local ids
  ids="$(docker ps -q --filter "label=com.docker.compose.project=$project" --filter "label=com.docker.compose.service=$1")"
  [ -n "$ids" ] || die "no running $1 container in compose project $project"
  [ "$(printf '%s\n' "$ids" | wc -l)" -eq 1 ] || die "more than one $1 container in compose project $project"
  printf '%s' "$ids"
}
pg="$(container postgres)"
nats="$(container nats)"
# The network NATS listens on (the project's internal one).
net="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$nats" | head -n 1)"
[ -n "$net" ] || die "the nats container is on no network"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
files=()

for db in authority authority_ts; do
  partial="$dir/.$db-$stamp.dump.partial"
  final="$dir/$db-$stamp.dump"
  if ! docker exec "$pg" pg_dump -Fc -U postgres "$db" > "$partial"; then
    rm -f "$partial"
    die "pg_dump $db failed; older dumps kept"
  fi
  # Read it back with the server's own pg_restore.
  if ! entries="$(docker exec -i "$pg" pg_restore --list < "$partial" | grep -cv '^;')"; then
    rm -f "$partial"
    die "the dump of $db does not list; older dumps kept"
  fi
  mv "$partial" "$final"
  echo "backup: $final ($(wc -c < "$final" | tr -d ' ') bytes, $entries entries)"
  files+=("$final")
done

# The KV export, from the pinned nats-box on the project's network, as
# the backup's own NATS user. A key name never holds a space, so a line
# that is not a key name (the CLI's "No keys found in bucket") is skipped.
partial="$dir/.nats-kv-$stamp.jsonl.partial"
final="$dir/nats-kv-$stamp.jsonl"
# shellcheck disable=SC2016 # expanded by the container's shell
export_kv='set -eu
s="--server=$NATS_URL"
n=0
for b in $(nats "$s" kv ls --names); do
  for k in $(nats "$s" kv ls "$b" | grep -E "^[-/_=.a-zA-Z0-9]+\$" || true); do
    v="$(nats "$s" kv get "$b" "$k" --raw | base64 | tr -d "\n")"
    jq -cn --arg b "$b" --arg k "$k" --arg v "$v" "{bucket: \$b, key: \$k, value_b64: \$v}"
    n=$((n + 1))
  done
done
echo "$n" >&2'
if ! keys="$(MSYS_NO_PATHCONV=1 docker run --rm --network "$net" --env-file "$secrets/nats/backup.env" \
    "$NATS_BOX_IMAGE" sh -c "$export_kv" 2>&1 > "$partial")"; then
  rm -f "$partial"
  die "the NATS KV export failed: $(printf '%s' "$keys" | tail -n 1); older files kept"
fi
keys="$(printf '%s' "$keys" | tail -n 1)"
lines="$(wc -l < "$partial" | tr -d ' ')"
if [ "$lines" != "$keys" ] || ! jq -e -s 'all(.[]; has("bucket") and has("key") and has("value_b64"))' "$partial" >/dev/null; then
  rm -f "$partial"
  die "the NATS KV export holds $lines valid lines for $keys keys; older files kept"
fi
mv "$partial" "$final"
echo "backup: $final ($lines keys in $(jq -r .bucket "$final" | tr -d '\r' | sort -u | wc -l | tr -d ' ') buckets)"
files+=("$final")

for f in "${files[@]}"; do
  [ -n "$remote" ] || break
  bytes="$(wc -c < "$f" | tr -d ' ')"
  rclone copyto "$f" "$remote/$(basename "$f")"
  copied="$(rclone size --json "$remote/$(basename "$f")" | sed -n 's/.*"bytes":\([0-9]*\).*/\1/p')"
  [ "$copied" = "$bytes" ] || die "the copy of $f at $remote has ${copied:-no} bytes, not $bytes"
  echo "backup: copied to $remote/$(basename "$f") ($copied bytes)"
done
if [ -z "$remote" ]; then
  echo "backup: AUTHORITY_BACKUP_REMOTE is not set; the files stayed on this host"
fi

# Rotation: only complete files of this job, older than keep_days.
find "$dir" -maxdepth 1 -type f \( -name 'authority-*.dump' -o -name 'authority_ts-*.dump' -o -name 'nats-kv-*.jsonl' \) \
  -mtime +"$keep_days" -print -delete | sed 's/^/backup: rotated out /'
echo "backup: done ($stamp, kept $keep_days days)"
