#!/usr/bin/env bash
# Regenerates every committed generated file from its source:
#   api/openapi.yaml -> api/gen/api.gen.go (oapi-codegen, api/oapi-codegen.yaml)
#   sqlc.yaml        -> internal/store/pg/gen, internal/store/ts/gen/{writer,reader}
#                       (sqlc, from the migration trees and the query files)
# openapi-typescript (web/src/api/) is added here by WP-21.
#
# OUT_DIR (optional) writes into a scratch tree instead of the
# repository, for scripts/verify-generated.sh. GO overrides the go
# binary. The generator versions are pinned here and nowhere else.
set -euo pipefail

OAPI_CODEGEN_VERSION=v2.8.0
SQLC_VERSION=v1.31.1

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

# sqlc resolves every path in sqlc.yaml against the file's directory, so
# a scratch run copies the inputs beside a copy of the file.
sqlc_config=sqlc.yaml
if [ "$out" != "$root" ]; then
  for d in migrations internal/store/pg/queries internal/store/pg/schema \
           internal/store/ts/queries internal/store/ts/schema; do
    mkdir -p "$out/$d"
    cp -R "$d/." "$out/$d/"
  done
  cp sqlc.yaml "$out/sqlc.yaml"
  sqlc_config="$out/sqlc.yaml"
fi
"$GO" run "github.com/sqlc-dev/sqlc/cmd/sqlc@${SQLC_VERSION}" generate -f "$sqlc_config"
echo "generated: internal/store/pg/gen, internal/store/ts/gen (sqlc ${SQLC_VERSION})"
