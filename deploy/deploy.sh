#!/usr/bin/env bash
# Deploys uspace-authority with deploy/compose.yaml and says what it
# verified (WP-24; LESSONS E-02: a deploy that reports success while
# doing nothing is worse than a failure).
#
#   deploy/deploy.sh --env-file <deployment env> [--env-file <more>]... \
#                    [--project uspace-authority] [-f <extra compose file>]... \
#                    [--verify-only] [--accept-not-ready <service>:<check>]... \
#                    [--unsigned-local-images]
#
# The env files give compose its variables (deploy/compose.yaml's header:
# AUTHORITY_IMAGE and AUTHORITY_WEB_IMAGE by digest, AUTHORITY_HOST, the
# directories, the edge network and addresses). In order:
#
#   1. renders the compose file (refused when a variable is missing);
#   2. checks that both images are references by digest and verifies
#      their cosign signatures and SBOM attestations (deploy/verify-image.sh);
#   3. pulls them by those digests;
#   4. starts postgres and NATS and waits for their health checks;
#   5. runs the one-shot migrate (both trees), reads its exit status and
#      the version it reports for each tree, and stops on a failure;
#   6. restarts the processes one at a time in dependency order
#      (tsdb-writer, rid-ingest, detect, dp-poller, manned-ingest, api,
#      picture-ws, then web), each answering /healthz before the next;
#   7. verifies: every Go process answers /healthz, /readyz (every check
#      printed; a failing one fails the deploy unless it is named with
#      --accept-not-ready, which is printed too), the version its
#      "started" line reports and its last status line; web answers its
#      health check;
#   8. prints what was verified, or which check failed, and exits
#      non-zero on any failure.
#
# With AUTHORITY_EXPECT_VERSION set, a process whose "started" line
# names another version fails 7 (the image's VERSION build argument: CI
# sets it to the commit, so the check proves the new image is running).
#
# --verify-only does 1 and 7 and changes nothing. --unsigned-local-images
# is the CI smoke's: the images are local builds (no registry, no digest),
# so 2 and 3 are skipped and the output says so at every step; a
# reference with a registry host is refused with it.
#
# The probes run from the pinned nats-box image on the project's internal
# network (the Go image has no shell and the admin listener is never
# published), each bounded by curl's own timeout and retry count.
set -euo pipefail

NATS_BOX_IMAGE="${NATS_BOX_IMAGE:-natsio/nats-box:0.18.0@sha256:abdc9f9f0120bb8adfbf674eb037d1551db55356eb198b7bd4ffed377f6950a6}"
here="$(cd "$(dirname "$0")" && pwd)"
go_services=(tsdb-writer rid-ingest detect dp-poller manned-ingest api picture-ws)

project=uspace-authority
mode=deploy
unsigned=0
env_files=()
extra_files=()
accept=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file) env_files+=(--env-file "${2:?--env-file needs a file}"); shift ;;
    -f) extra_files+=(-f "${2:?-f needs a compose file}"); shift ;;
    --project) project="${2:?--project needs a name}"; shift ;;
    --verify-only) mode=verify-only ;;
    --accept-not-ready) accept+=("${2:?--accept-not-ready needs <service>:<check>}"); shift ;;
    --unsigned-local-images) unsigned=1 ;;
    *) echo "deploy: unknown argument $1" >&2; exit 2 ;;
  esac
  shift
done
[ "${#env_files[@]}" -gt 0 ] || { echo "deploy: --env-file is required" >&2; exit 2; }

verified=()
log() { echo "deploy: $*"; }
fail() { echo "deploy: FAIL $*" >&2; exit 1; }
dc() { docker compose -p "$project" "${env_files[@]}" -f "$here/compose.yaml" "${extra_files[@]}" "$@"; }

# 1. Render.
if ! err="$(dc config --quiet 2>&1)"; then
  fail "compose does not render: $err"
fi
rendered="$(dc config --format json)"
image_of() { printf '%s' "$rendered" | jq -j --arg s "$1" '.services[$s].image // ""'; }
go_image="$(image_of api)"
web_image="$(image_of web)"
for s in "${go_services[@]}" migrate; do
  [ "$(image_of "$s")" = "$go_image" ] || fail "$s runs $(image_of "$s"), not the image api runs ($go_image)"
done
internal_net="$(printf '%s' "$rendered" | jq -j '.networks.authority.name // ""')"
[ -n "$internal_net" ] || fail "the rendered compose has no authority network"
log "project $project, images $go_image and $web_image"

# 2, 3. Signatures, then pull by digest.
if [ "$mode" = deploy ]; then
  if [ "$unsigned" -eq 1 ]; then
    for ref in "$go_image" "$web_image"; do
      case "$ref" in
        */*) fail "--unsigned-local-images with $ref: a registry image is always verified" ;;
      esac
    done
    log "SIGNATURES NOT VERIFIED: --unsigned-local-images (local builds $go_image, $web_image; CI smoke only)"
    verified+=("images: local builds, signatures NOT verified (--unsigned-local-images)")
  else
    "$here/verify-image.sh" "$go_image" "$web_image"
    dc pull --quiet postgres nats migrate api web
    verified+=("images: signatures and SBOM attestations verified, pulled by digest")
  fi
fi

# probe <url> [retries]: GET from the pinned tool image on the internal
# network; prints the body, then the status code on its own last line.
probe() {
  MSYS_NO_PATHCONV=1 docker run --rm --network "$internal_net" "$NATS_BOX_IMAGE" \
    curl -sS --max-time 5 --retry "${2:-0}" --retry-delay 1 --retry-all-errors \
    -w '\n%{http_code}' "$1" 2>&1 || true
}
healthy() { # <service>: /healthz answers 200 within about 30 s
  local out
  out="$(probe "http://$1:9090/healthz" 30)"
  [ "$(printf '%s' "$out" | tail -n 1)" = 200 ]
}

if [ "$mode" = deploy ]; then
  # 4. Databases and NATS.
  dc up -d --wait postgres nats >/dev/null 2>&1 || fail "postgres or nats did not become healthy: $(dc ps postgres nats 2>&1 | tail -n 2 | tr '\n' ' ')"
  log "postgres and nats healthy"

  # 5. Migrate, and read what it says.
  dc up -d --no-deps --force-recreate migrate >/dev/null 2>&1 || fail "migrate did not start"
  rc=0
  dc wait migrate >/dev/null 2>&1 || rc=$?
  versions="$(dc logs --no-log-prefix migrate 2>/dev/null | jq -rR 'fromjson? | select(.msg == "tree at version") | "\(.tree)=\(.version)"' | tr -d '\r' | sort | tr '\n' ' ')"
  if [ "$rc" -ne 0 ]; then
    fail "migrate exited $rc: $(dc logs --no-log-prefix migrate 2>/dev/null | tail -n 3 | tr '\n' ' ')"
  fi
  case "$versions" in
    *relational=*timeseries=*) ;;
    *) fail "migrate exited 0 but did not report both trees (got: ${versions:-nothing})" ;;
  esac
  log "migrate exited 0: ${versions% }"
  verified+=("migrate: exit 0, ${versions% }")

  # 6. One process at a time, each healthy before the next.
  for s in "${go_services[@]}"; do
    dc up -d --no-deps "$s" >/dev/null 2>&1 || fail "$s did not start"
    healthy "$s" || fail "$s does not answer /healthz after its restart: $(dc logs --no-log-prefix --tail 5 "$s" 2>&1 | tr '\n' ' ')"
    log "$s restarted, /healthz 200"
  done
  dc up -d --no-deps --wait web >/dev/null 2>&1 || fail "web did not become healthy: $(dc logs --no-log-prefix --tail 5 web 2>&1 | tr '\n' ' ')"
  log "web restarted, healthy"
fi

# 7. Verify every process.
accepted() { # <service> <check>
  local a
  for a in "${accept[@]}"; do [ "$a" = "$1:$2" ] && return 0; done
  return 1
}
bad=0
for s in "${go_services[@]}"; do
  if ! healthy "$s"; then
    echo "deploy: FAIL $s: /healthz does not answer 200" >&2
    bad=1
    continue
  fi
  # No retry: curl retries a 503, and /readyz answers 503 with its reasons.
  out="$(probe "http://$s:9090/readyz")"
  code="$(printf '%s' "$out" | tail -n 1)"
  body="$(printf '%s' "$out" | sed '$d')"
  if ! printf '%s' "$body" | jq -e .checks >/dev/null 2>&1; then
    echo "deploy: FAIL $s: /readyz answered $code without checks: $(printf '%s' "$body" | head -c 200)" >&2
    bad=1
    continue
  fi
  failing="$(printf '%s' "$body" | jq -r '.checks | to_entries[] | select(.value.ok | not) | "\(.key)\t\(.value.error // "")"' | tr -d '\r')"
  passing="$(printf '%s' "$body" | jq -r '[.checks | to_entries[] | select(.value.ok) | .key] | join(",")' | tr -d '\r')"
  ready_note="ready"
  if [ -n "$failing" ]; then
    while IFS=$'\t' read -r check reason; do
      if accepted "$s" "$check"; then
        log "$s: /readyz $check not ready, ACCEPTED by --accept-not-ready: $reason"
        ready_note="not ready ($check accepted)"
      else
        echo "deploy: FAIL $s: /readyz $check not ready: $reason" >&2
        bad=1
        ready_note="NOT READY ($check)"
      fi
    done <<<"$failing"
  elif [ "$code" != 200 ]; then
    echo "deploy: FAIL $s: /readyz answered $code with every check passing" >&2
    bad=1
  fi
  logs="$(dc logs --no-log-prefix "$s" 2>/dev/null | tr -d '\r')"
  version="$(printf '%s\n' "$logs" | jq -rR 'fromjson? | select(.msg == "started") | .version' | tail -n 1)"
  status="$(printf '%s\n' "$logs" | jq -cR 'fromjson? | select(.msg == "status") | del(.counters, .time, .level, .msg, .process) | with_entries(select(.value | type != "object" and type != "array"))' | tail -n 1)"
  [ -n "$version" ] || { echo "deploy: FAIL $s: no started line in its log" >&2; bad=1; }
  if [ -n "${AUTHORITY_EXPECT_VERSION:-}" ] && [ "$version" != "$AUTHORITY_EXPECT_VERSION" ]; then
    echo "deploy: FAIL $s: runs version ${version:-?}, expected $AUTHORITY_EXPECT_VERSION" >&2
    bad=1
  fi
  [ -n "$status" ] || { echo "deploy: FAIL $s: no status line in its log yet" >&2; bad=1; }
  log "$s: /healthz 200, /readyz $ready_note [${passing:-no checks}], version ${version:-?}, status $(printf '%s' "$status" | cut -c1-240)"
  verified+=("$s: /healthz 200, /readyz $ready_note, version ${version:-?}")
done
if [ "$(dc ps --format '{{.Health}}' web 2>/dev/null | tr -d '\r')" = healthy ]; then
  log "web: health check healthy"
  verified+=("web: health check healthy")
else
  echo "deploy: FAIL web: not healthy ($(dc ps --format '{{.Status}}' web 2>&1 | tr -d '\r'))" >&2
  bad=1
fi

# 8. What was verified.
echo "deploy: verified ($mode, project $project):"
for v in "${verified[@]}"; do echo "deploy:   $v"; done
[ "$bad" -eq 0 ] || fail "some checks failed (above)"
echo "deploy: ok, every check above passed"
