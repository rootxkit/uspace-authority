#!/usr/bin/env bash
# The sibling contracts this system consumes are pinned copies
# (reconciliation M11): every file under api/clients/ except SOURCE,
# the oapi-codegen configurations and embed.go is named by one line of
# api/clients/SOURCE:
#
#   <copy, relative to api/clients/> <owner/repo> <commit> <path in that repo>
#
# This script fetches every file at its commit and fails on any byte
# difference, on a malformed line, on a line whose copy is missing and on
# a copy no line names. It needs the network (raw.githubusercontent.com);
# a fetch that fails is a failure, never a pass. BASE_URL overrides the
# raw host (the CI step that proves a changed copy fails uses the same).
set -euo pipefail
cd "$(dirname "$0")/.."

base=${BASE_URL:-https://raw.githubusercontent.com}
dir=api/clients
source_file=$dir/SOURCE
status=0
checked=0
declare -A named=()

while IFS= read -r line; do
  case "$line" in ''|'#'*) continue ;; esac
  read -r copy repo commit path extra <<<"$line"
  if [ -z "${path:-}" ] || [ -n "${extra:-}" ] || ! [[ "$commit" =~ ^[0-9a-f]{40}$ ]]; then
    echo "check-contracts: $source_file: malformed line: $line" >&2
    status=1
    continue
  fi
  named[$copy]=1
  file="$dir/$copy"
  if [ ! -f "$file" ]; then
    echo "check-contracts: $source_file names $copy but $file is missing" >&2
    status=1
    continue
  fi
  scratch=$(mktemp)
  if ! curl -fsSL --retry 3 "$base/$repo/$commit/$path" -o "$scratch"; then
    echo "check-contracts: cannot fetch $repo@$commit:$path" >&2
    rm -f "$scratch"
    status=1
    continue
  fi
  if diff -u "$scratch" "$file"; then
    echo "check-contracts: $file equals $repo@${commit:0:12}:$path"
    checked=$((checked + 1))
  else
    echo "check-contracts: $file differs from $repo@$commit:$path" >&2
    status=1
  fi
  rm -f "$scratch"
done < "$source_file"

while IFS= read -r copy; do
  copy="${copy#"$dir"/}"
  case "$copy" in SOURCE|embed.go|oapi-codegen.*.yaml) continue ;; esac
  if [ -z "${named[$copy]:-}" ]; then
    echo "check-contracts: $dir/$copy has no line in $source_file" >&2
    status=1
  fi
done < <(find "$dir" -type f | sort)

if [ "$checked" -eq 0 ]; then
  echo "check-contracts: no copy was compared" >&2
  exit 1
fi
if [ "$status" -ne 0 ]; then
  exit "$status"
fi
echo "check-contracts: $checked pinned copies equal their sources"
