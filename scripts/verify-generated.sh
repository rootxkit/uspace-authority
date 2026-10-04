#!/usr/bin/env bash
# Regenerates every generated file into a scratch directory and fails on
# any difference from the committed copy, including a generated file
# that was added or removed. It reads nothing over the network but the
# pinned generator modules (from the module cache when present) and
# never compares against another repository.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

OUT_DIR="$scratch" "$root/scripts/generate.sh" >/dev/null

# The generated trees are the ones generate.sh writes.
dirs=(api/gen internal/cisp/cispclient internal/dp/ridapi internal/dp/utmapi internal/store/pg/gen internal/store/ts/gen internal/occurrences/store/gen)
status=0
for d in "${dirs[@]}"; do
  if [ ! -d "$root/$d" ]; then
    echo "missing committed directory: $d (run scripts/generate.sh)"
    status=1
    continue
  fi
  if ! diff -ru "$root/$d" "$scratch/$d"; then
    echo "out of date: $d (run scripts/generate.sh and commit the result)"
    status=1
  fi
done
if [ "$status" -eq 0 ]; then
  echo "generated files up to date: ${dirs[*]}"
fi
exit "$status"
