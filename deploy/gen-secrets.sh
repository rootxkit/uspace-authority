#!/usr/bin/env bash
# Generates the secrets directory deploy/compose.yaml reads
# (AUTHORITY_SECRETS_DIR), on the host that deploys, never in git:
#
#   deploy/gen-secrets.sh <secrets directory>
#
#   db.env               POSTGRES_PASSWORD of the timescaledb-ha container
#   relational.env       PG_URL  (migrate, api)            derived from db.env
#   timeseries.env       TS_URL  (migrate, api, telemetry)  derived from db.env
#   nats/<process>.env   NATS_URL with that process's own NATS user
#   nats/users.conf      the NATS users                     derived from nats/*.env
#   web.env              WEB_MFA_CHALLENGE_SECRET of web's BFF
#   keys/token-1.pem     token-signing RSA key (SIGNING_KEY_FILES)
#   keys/publication-1.pem  publication JWS RSA key (PUBLICATION_KEY_FILE)
#   keys/pii.key, keys/registry-hash.key, keys/occurrence.key
#                        AES-256 keys, one line of base64 each
#   keys/admin.pw        the first admin's password (BOOTSTRAP_ADMIN_PASSWORD_FILE)
#
# A file that exists is never replaced: a new PII key would leave every
# sealed column unreadable, a new registry hash key every secret part
# unmatchable, a new database password a data directory nobody can open.
# The derived files (relational.env, timeseries.env, users.conf) are
# rewritten from what exists, so they always agree with it. Nothing
# secret is printed: the script names the files it wrote or kept.
#
# Permissions: the directory is 0700 (no other host user reaches
# anything); keys/ and nats/users.conf are world-readable inside it
# because the containers read them as their own users (distroless
# nonroot, nats) through bind mounts, which do not pass through the 0700
# parent. The env files are read by docker compose on the host, 0600.
#
# Needs openssl.
set -euo pipefail
umask 077

dir="${1:?usage: deploy/gen-secrets.sh <secrets directory>}"
processes=(api rid-ingest dp-poller manned-ingest detect tsdb-writer picture-ws backup)

mkdir -p "$dir/keys" "$dir/nats"
chmod 0700 "$dir"
chmod 0755 "$dir/keys" "$dir/nats"

wrote=()
kept=()

# rand_hex <bytes>: URL- and DSN-safe random text.
rand_hex() { openssl rand -hex "$1"; }

# new_file <path> <mode> <command...>: runs the command into a temporary
# file beside the path and moves it into place, only when the path does
# not exist; an existing file is kept as it is.
new_file() {
  local path="$1" mode="$2" tmp; shift 2
  if [ -e "$path" ]; then
    kept+=("${path#"$dir"/}")
    return 0
  fi
  tmp="$(mktemp "$path.XXXXXX")"
  if ! "$@" > "$tmp"; then
    rm -f "$tmp"
    echo "gen-secrets: generating ${path#"$dir"/} failed" >&2
    exit 1
  fi
  if [ ! -s "$tmp" ]; then
    rm -f "$tmp"
    echo "gen-secrets: generating ${path#"$dir"/} produced nothing" >&2
    exit 1
  fi
  chmod "$mode" "$tmp"
  mv "$tmp" "$path"
  wrote+=("${path#"$dir"/}")
}

rsa_key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 2>/dev/null; }
aes_key() { openssl rand -base64 32; }
password() { rand_hex 24; }
db_env() { printf 'POSTGRES_PASSWORD=%s\n' "$(rand_hex 24)"; }
web_env() { printf 'WEB_MFA_CHALLENGE_SECRET=%s\n' "$(rand_hex 32)"; }
nats_env() { printf 'NATS_URL=nats://%s:%s@nats:4222\n' "$1" "$(rand_hex 24)"; }

new_file "$dir/db.env" 0600 db_env
new_file "$dir/web.env" 0600 web_env
new_file "$dir/keys/token-1.pem" 0644 rsa_key
new_file "$dir/keys/publication-1.pem" 0644 rsa_key
new_file "$dir/keys/pii.key" 0644 aes_key
new_file "$dir/keys/registry-hash.key" 0644 aes_key
new_file "$dir/keys/occurrence.key" 0644 aes_key
new_file "$dir/keys/admin.pw" 0644 password
for p in "${processes[@]}"; do
  new_file "$dir/nats/$p.env" 0600 nats_env "$p"
done

# value <file> <name>: the value of NAME=value in an env file.
value() { sed -n "s/^$2=//p" "$1" | tail -n 1; }

pg_password="$(value "$dir/db.env" POSTGRES_PASSWORD)"
case "$pg_password" in
  "" | *[!0-9a-zA-Z]*)
    echo "gen-secrets: db.env holds no POSTGRES_PASSWORD of letters and digits; fix or remove it" >&2
    exit 1 ;;
esac
# Rewritten every run from db.env (they are derived, never edited).
printf 'PG_URL=postgres://postgres:%s@postgres:5432/authority?sslmode=disable\n' "$pg_password" > "$dir/relational.env"
printf 'TS_URL=postgres://postgres:%s@postgres:5432/authority_ts?sslmode=disable\n' "$pg_password" > "$dir/timeseries.env"
chmod 0600 "$dir/relational.env" "$dir/timeseries.env"

# users.conf from the per-process URLs: nats://<user>:<password>@nats:4222.
# Each URL is checked before anything is written.
entries=()
for p in "${processes[@]}"; do
  url="$(value "$dir/nats/$p.env" NATS_URL)"
  creds="${url#nats://}"
  creds="${creds%@*}"
  user="${creds%%:*}"
  pass="${creds#*:}"
  if [ "$user" != "$p" ] || [ -z "$pass" ] || [ "$pass" = "$creds" ]; then
    echo "gen-secrets: nats/$p.env does not hold nats://$p:<password>@nats:4222; fix or remove it" >&2
    exit 1
  fi
  entries+=("$(printf '    {user: "%s", password: "%s"}' "$user" "$pass")")
done
users="$(mktemp "$dir/nats/users.conf.XXXXXX")"
{
  echo "# Generated by deploy/gen-secrets.sh from nats/*.env; do not edit."
  echo "authorization {"
  echo "  users = ["
  printf '%s\n' "${entries[@]}"
  echo "  ]"
  echo "}"
} > "$users"
chmod 0644 "$users"
mv "$users" "$dir/nats/users.conf"

echo "gen-secrets: $dir"
echo "gen-secrets: wrote ${#wrote[@]}: ${wrote[*]:-(none)}"
echo "gen-secrets: kept ${#kept[@]}: ${kept[*]:-(none)}"
echo "gen-secrets: derived relational.env, timeseries.env, nats/users.conf (${#processes[@]} NATS users)"
