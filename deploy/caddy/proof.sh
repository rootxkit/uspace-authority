#!/usr/bin/env bash
# Proves deploy/caddy/authority.snippet against a running Caddy (the
# pinned image), not against its text: every route class reaches the
# upstream it names, /metrics and /readyz reach none, the basemap is
# served with ranges and its cache headers, and the certificate subject
# header reaches an upstream only from a verified client certificate on
# the mTLS route (E-01: each absence is paired with the presence that
# makes it happen).
#
#   deploy/caddy/proof.sh            (make check-deploy runs it)
#
# Stub upstreams inside the same Caddy answer with their own name and the
# subject header they received. A throwaway CA and client certificates
# are made with openssl in a temporary directory. The container is
# removed on exit and its absence checked.
set -euo pipefail

# Schannel (Windows curl) cannot present a PEM client certificate: every
# certificate check would fail, and the refusal check would pass for the
# wrong reason. Refuse to prove anything with it.
if curl -V | head -n 1 | grep -q Schannel && ! curl -V | head -n 1 | grep -q OpenSSL; then
  echo "proof: this curl uses Schannel, which cannot send a PEM client certificate; run it on Linux or in WSL" >&2
  exit 2
fi

CADDY_IMAGE="${CADDY_IMAGE:-caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d}"
port="${PROOF_PORT:-58444}"
host=authority.proof.test
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
name="authority-caddy-proof-$$"

# shellcheck disable=SC2317 # run by the EXIT trap
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$work"
  if [ -n "$(docker ps -aq --filter "name=^${name}\$")" ]; then
    echo "proof: container $name is still present after cleanup" >&2
    exit 1
  fi
}
trap cleanup EXIT

# Git Bash on Windows: a C:/ path, which neither MSYS nor the native
# openssl and docker rewrite (the subjects below are passed unconverted).
if command -v cygpath >/dev/null 2>&1; then work="$(cygpath -m "$work")"; fi

# A CA the site trusts, a client it issued, and a client of another CA.
mkcert() { # <name> <subject>
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "$2" \
    -keyout "$work/$1.key" -out "$work/$1.pem" >/dev/null 2>&1
}
mkclient() { # <name> <subject> <ca name>
  openssl req -newkey rsa:2048 -nodes -subj "$2" \
    -keyout "$work/$1.key" -out "$work/$1.csr" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' > "$work/$1.ext"
  openssl x509 -req -in "$work/$1.csr" -CA "$work/$3.pem" -CAkey "$work/$3.key" \
    -CAcreateserial -days 1 -extfile "$work/$1.ext" -out "$work/$1.pem" >/dev/null 2>&1
}
MSYS_NO_PATHCONV=1 mkcert ca "/O=proof/CN=proof mTLS CA"
MSYS_NO_PATHCONV=1 mkcert otherca "/O=other/CN=other CA"
MSYS_NO_PATHCONV=1 mkclient client "/O=proof/CN=ussp-test-01" ca
MSYS_NO_PATHCONV=1 mkclient stranger "/O=other/CN=stranger" otherca
chmod 0644 "$work"/*.pem "$work"/*.key

# The basemap: SOURCE.json and a bundle file of known bytes.
mkdir -p "$work/basemap/tiles"
printf '{"release":"proof"}\n' > "$work/basemap/SOURCE.json"
printf '0123456789abcdef' > "$work/basemap/tiles/proof.pmtiles"
chmod -R a+rX "$work/basemap"

cp "$here/authority.snippet" "$work/authority.snippet"
cat > "$work/Caddyfile" <<'CADDY'
{
	admin off
	local_certs
	skip_install_trust
	auto_https disable_redirects
	https_port 8443
	http_port 8080
	log {
		output discard
	}
}

import /work/authority.snippet

:9001 {
	respond "upstream=api subject=[{header.X-Client-Cert-Subject}]" 200
}
:9002 {
	respond "upstream=admin subject=[{header.X-Client-Cert-Subject}]" 200
}
:9003 {
	respond "upstream=rid subject=[{header.X-Client-Cert-Subject}]" 200
}
:9004 {
	respond "upstream=dp subject=[{header.X-Client-Cert-Subject}]" 200
}
:9005 {
	respond "upstream=picture subject=[{header.X-Client-Cert-Subject}]" 200
}
:9006 {
	respond "upstream=web subject=[{header.X-Client-Cert-Subject}]" 200
}
CADDY

MSYS_NO_PATHCONV=1 docker run -d --name "$name" \
  -p "127.0.0.1:${port}:8443" \
  -e AUTHORITY_HOST="$host" -e AUTHORITY_MTLS_CA=/work/ca.pem \
  -e AUTHORITY_API_UPSTREAM=127.0.0.1:9001 -e AUTHORITY_ADMIN_UPSTREAM=127.0.0.1:9002 \
  -e AUTHORITY_RID_UPSTREAM=127.0.0.1:9003 -e AUTHORITY_DP_UPSTREAM=127.0.0.1:9004 \
  -e AUTHORITY_PICTURE_UPSTREAM=127.0.0.1:9005 -e AUTHORITY_WEB_UPSTREAM=127.0.0.1:9006 \
  -e AUTHORITY_BASEMAP_DIR=/work/basemap \
  -v "$work:/work:ro" \
  "$CADDY_IMAGE" caddy run --config /work/Caddyfile --adapter caddyfile >/dev/null

fail=0
pass=0
ok() { echo "ok     $*"; pass=$((pass + 1)); }
bad() { echo "FAIL   $*"; fail=1; }

# curl against the proof host. --ssl-no-revoke: Windows curl (Schannel)
# asks for a revocation list the internal CA does not publish; other TLS
# backends ignore it. -k: the site certificate is Caddy's internal one.
pc() { # <path> [curl args...]
  local path="$1"; shift
  curl -sk --max-time 10 --ssl-no-revoke --resolve "$host:$port:127.0.0.1" \
    -w '\n%{http_code}' "$@" "https://$host:$port$path"
}

# Wait on the condition (Caddy serving), never a fixed sleep.
ready=0
for _ in $(seq 1 100); do
  if pc /healthz >/dev/null 2>&1; then ready=1; break; fi
  if [ -z "$(docker ps -q --filter "name=^${name}\$")" ]; then break; fi
  # A bounded poll of the condition: at most 100 x 0.1 s.
  sleep 0.1
done
if [ "$ready" -ne 1 ]; then
  echo "proof: Caddy did not serve; its log:" >&2
  docker logs "$name" 2>&1 | tail -n 20 >&2
  exit 1
fi

expect() { # <label> <want code> <want body substring> <path> [curl args...]
  local label="$1" code="$2" want="$3" path="$4"; shift 4
  local out got body
  out="$(pc "$path" "$@" 2>&1 || true)"
  got="$(printf '%s' "$out" | tail -n 1)"
  body="$(printf '%s' "$out" | sed '$d')"
  if [ "$got" = "$code" ] && { [ -z "$want" ] || [[ "$body" == *"$want"* ]]; }; then
    ok "$label: $path -> $got ${body:+($body)}"
  else
    bad "$label: $path -> ${got:-no answer} ($body), want $code with '$want'"
  fi
}

cert=(--cert "$work/client.pem" --key "$work/client.key")
forged=(-H 'X-Client-Cert-Subject: CN=forged')

# Route classes.
expect "admin"   200 "upstream=admin"   /healthz
expect "rid"     200 "upstream=rid"     /v1/rid/observations -X POST
expect "api"     200 "upstream=api"     /v1/rid/receivers
expect "api"     200 "upstream=api"     /v1/rid/receivers/rx-1/heartbeat -X POST
expect "picture" 200 "upstream=picture" /v1/picture/ws
expect "picture" 200 "upstream=picture" /v1/picture/snapshot
expect "dp"      200 "upstream=dp"      /uss/identification_service_areas/x
expect "dp"      200 "upstream=dp"      /v1/dp/observations/display_data
expect "api"     200 "upstream=api"     /v1/dp/views
expect "api"     200 "upstream=api"     /v1/registry/validate
expect "api"     200 "upstream=api"     /oauth/token -X POST
expect "api"     200 "upstream=api"     /.well-known/jwks.json
expect "web"     200 "upstream=web"     /
expect "web"     200 "upstream=web"     /_bff/session
expect "web"     200 "upstream=web"     /ka/login

# Never routed: answered by Caddy itself, with no upstream body.
for p in /metrics /metrics/x /readyz; do
  out="$(pc "$p" || true)"
  if [ "$(printf '%s' "$out" | tail -n 1)" = 404 ] && [[ "$out" != *upstream=* ]]; then
    ok "internal: $p -> 404 from Caddy"
  else
    bad "internal: $p -> $(printf '%s' "$out" | tr '\n' ' ')"
  fi
done

# The basemap: a range answers 206 with exactly those bytes; the bundle
# is cached a day and SOURCE.json five minutes; a missing file is 404
# from the file server, not web.
hdr="$work/headers"
out="$(curl -sk --max-time 10 --ssl-no-revoke --resolve "$host:$port:127.0.0.1" -D "$hdr" \
  -H 'Range: bytes=2-5' -w '\n%{http_code}' "https://$host:$port/basemap/tiles/proof.pmtiles" || true)"
if [ "$(printf '%s' "$out" | tail -n 1)" = 206 ] && [ "$(printf '%s' "$out" | sed '$d')" = 2345 ] &&
   grep -qi '^cache-control: public, max-age=86400' "$hdr"; then
  ok "basemap: range bytes=2-5 -> 206 '2345', Cache-Control max-age=86400"
else
  bad "basemap: range -> $(printf '%s' "$out" | tr '\n' ' '); headers: $(tr '\r\n' '  ' < "$hdr")"
fi
out="$(curl -sk --max-time 10 --ssl-no-revoke --resolve "$host:$port:127.0.0.1" -D "$hdr" \
  -w '\n%{http_code}' "https://$host:$port/basemap/SOURCE.json" || true)"
if [ "$(printf '%s' "$out" | tail -n 1)" = 200 ] && grep -qi '^cache-control: public, max-age=300' "$hdr"; then
  ok "basemap: SOURCE.json -> 200, Cache-Control max-age=300"
else
  bad "basemap: SOURCE.json -> $(printf '%s' "$out" | tr '\n' ' ')"
fi
out="$(pc /basemap/absent.pmtiles || true)"
if [ "$(printf '%s' "$out" | tail -n 1)" = 404 ] && [[ "$out" != *upstream=* ]]; then
  ok "basemap: a missing file -> 404 from the file server"
else
  bad "basemap: a missing file -> $(printf '%s' "$out" | tr '\n' ' ')"
fi

# Absence: a forged subject without a certificate reaches no upstream,
# on the mTLS route and everywhere else.
expect "forged, no cert" 200 "upstream=api subject=[]"     /oauth/token -X POST "${forged[@]}"
expect "forged, no cert" 200 "upstream=api subject=[]"     /v1/registry/validate "${forged[@]}"
expect "forged, no cert" 200 "upstream=rid subject=[]"     /v1/rid/observations -X POST "${forged[@]}"
expect "forged, no cert" 200 "upstream=picture subject=[]" /v1/picture/ws "${forged[@]}"
expect "forged, no cert" 200 "upstream=web subject=[]"     / "${forged[@]}"

# Presence: a verified certificate's subject reaches the mTLS route, and
# replaces a forged one.
expect "cert" 200 "upstream=api subject=[CN=ussp-test-01,O=proof]" /oauth/token -X POST "${cert[@]}"
expect "cert + forged" 200 "upstream=api subject=[CN=ussp-test-01,O=proof]" /oauth/token -X POST "${cert[@]}" "${forged[@]}"

# A certificate is never forwarded outside the mTLS route.
expect "cert, other route" 200 "upstream=api subject=[]"     /v1/registry/validate "${cert[@]}" "${forged[@]}"
expect "cert, other route" 200 "upstream=dp subject=[]"      /uss/identification_service_areas/x "${cert[@]}"
expect "cert, other route" 200 "upstream=web subject=[]"     / "${cert[@]}"

# A certificate of another CA ends the handshake (verify_if_given
# verifies what is given). Refused means curl's TLS failures: 35 (the
# handshake failed) or 56 (TLS 1.3: the server's alert arrives after the
# client's Finished, as a receive failure). Any other failure, such as 7
# (nothing listening) or 28 (timeout), says nothing about the
# certificate and is not counted as a refusal.
refused_at_handshake() { [ "$1" -eq 35 ] || [ "$1" -eq 56 ]; }

# The control (E-01): a request that fails for another reason is not
# taken for a refusal. Port 1 on loopback has nothing listening.
rc=0
curl -s --max-time 5 --resolve "$host:1:127.0.0.1" "https://$host:1/" >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ] && ! refused_at_handshake "$rc"; then
  ok "control: no listener -> curl exit $rc, not a handshake refusal"
else
  bad "control: no listener -> curl exit $rc, taken for a handshake refusal"
fi

rc=0
out="$(pc /oauth/token -X POST --cert "$work/stranger.pem" --key "$work/stranger.key" 2>/dev/null)" || rc=$?
if [[ "$out" == *upstream=* ]]; then
  bad "untrusted cert: answered ($out)"
elif refused_at_handshake "$rc"; then
  ok "untrusted cert: refused at the handshake (curl exit $rc)"
else
  bad "untrusted cert: curl exit $rc, want 35 or 56 (refused at the handshake)"
fi

echo "proof: $pass checks passed$([ "$fail" -eq 0 ] || echo ', some FAILED')"
exit "$fail"
