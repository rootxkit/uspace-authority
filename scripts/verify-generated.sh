#!/usr/bin/env bash
# Regenerates every generated file into a scratch directory and fails on
# any difference from the committed copy. It reads nothing over the
# network but the pinned generator module (from the module cache when
# present) and never compares against another repository.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

OUT_DIR="$scratch" "$root/scripts/generate.sh" >/dev/null

# The list of generated files is the list generate.sh writes.
files=(api/gen/api.gen.go)
status=0
for f in "${files[@]}"; do
  if [ ! -f "$root/$f" ]; then
    echo "missing committed file: $f (run scripts/generate.sh)"
    status=1
    continue
  fi
  if ! diff -u "$root/$f" "$scratch/$f"; then
    echo "out of date: $f (run scripts/generate.sh and commit the result)"
    status=1
  fi
done
if [ "$status" -eq 0 ]; then
  echo "generated files up to date: ${files[*]}"
fi
exit "$status"
