#!/usr/bin/env bash
# Regenerates every committed generated file from its source:
#   api/openapi.yaml -> api/gen/api.gen.go (oapi-codegen, api/oapi-codegen.yaml)
# sqlc (internal/store/*/gen) and openapi-typescript (web/src/api/) are
# added here by WP-1 and WP-21.
#
# OUT_DIR (optional) writes into a scratch tree instead of the
# repository, for scripts/verify-generated.sh. GO overrides the go
# binary. The generator version is pinned here and nowhere else.
set -euo pipefail

OAPI_CODEGEN_VERSION=v2.8.0

GO=${GO:-go}
root=$(cd "$(dirname "$0")/.." && pwd)
out=${OUT_DIR:-$root}
cd "$root"

mkdir -p "$out/api/gen"
"$GO" run "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  -config api/oapi-codegen.yaml \
  -o "$out/api/gen/api.gen.go" \
  api/openapi.yaml

echo "generated: api/gen/api.gen.go (oapi-codegen ${OAPI_CODEGEN_VERSION})"
