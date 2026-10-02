#!/usr/bin/env bash
# Fill the ground volume that detect and rid-ingest mount (WP-11): the
# geoid grids and the Copernicus GLO-30 terrain tiles in the lab's PGM
# container. Nothing large is ever committed; this script is the only way
# the files arrive.
#
#   deploy/fetch-ground.sh DIR                 geoid grids and terrain tiles
#   deploy/fetch-ground.sh --geoid-only DIR    geoid grids only (CI vectors)
#
# Layout written (the processes' configuration in brackets):
#
#   DIR/egm2008-2_5.pgm    [GEOID_FILE] EGM2008 2.5', the Copernicus DEM's geoid
#   DIR/egm96-15.pgm       EGM96 15', for the vectors only (USPACE_GEOID_DIR=DIR)
#   DIR/tiles/<cell>.pgm   [GROUND_DIR=DIR/tiles] one tile per 1 x 1 degree cell
#   DIR/tiles/index.json   the cells fetched and their dataset, or "sea"
#
# Geoid: GeographicLib's distribution of the NGA models (public domain).
# Both the archive and the extracted .pgm are pinned by SHA-256, the same
# pins as uspace-core's scripts/fetch-geoid.sh: a changed download, or a
# corrupted or tampered file, fails here instead of quietly moving every
# Remote ID altitude up or down. A grid already present with the pinned
# hash is kept and nothing is downloaded.
#
# Terrain: the tiles are converted from Copernicus GLO-30 by the lab's
# terrain tooling (uspace-lab owns the PGM writer; core's terrain package
# reads it) and published at TERRAIN_TILES_URL with:
#
#   TERRAIN_TILES_URL/index.json   the lab's index (flat or {"cells": {...}})
#   TERRAIN_TILES_URL/SHA256SUMS   "<sha256>  <file>" for index.json and every tile
#   TERRAIN_TILES_URL/<cell>.pgm   one tile per land cell
#
# SHA256SUMS is itself pinned by TERRAIN_SHA256SUMS_SHA256 (from the lab's
# release notes): every file is verified against it before it replaces
# anything in DIR, and the run fails on the first mismatch. The cells
# fetched are GROUND_CELLS (space-separated), by default every 1 x 1
# degree cell over Georgia (41-43 N, 40-46 E). index.json is rewritten to
# hold only the cells this run has, so a cell that was not fetched is
# unknown ground, never a read failure on every message.
#
# The Copernicus licence requires the attribution wherever an elevation
# is shown (docs/runbooks/ground.md); core's terrain.Attribution is it.
#
# Needs curl, sha256sum, tar with bzip2; jq for the terrain.
set -euo pipefail

geoid_only=0
if [ "${1:-}" = "--geoid-only" ]; then
  geoid_only=1
  shift
fi
dir="${1:?usage: deploy/fetch-ground.sh [--geoid-only] DIR}"

geoid_base=https://downloads.sourceforge.net/project/geographiclib/geoids-distrib
# model  archive sha256  pgm sha256 (uspace-core scripts/fetch-geoid.sh)
grids="
egm96-15 8b1ebad1ebae0a045502d0edb9cc51553da1d3914f01e07470c11b3bed75048e 2a12f13b6df65cdea52432c7fa1b43f34b007148eb817bf032af5af710905caa
egm2008-2_5 d602e13446a4a4a23f39aecfe6a2a0760a1bc6c1b497482c2ebc9f7d513be699 fab040a55dfabe782be89a89b2ba7e4a73183513a9813e24a3f80e7b6ed61dbf
"

default_cells="N41E040 N41E041 N41E042 N41E043 N41E044 N41E045 N41E046
N42E040 N42E041 N42E042 N42E043 N42E044 N42E045 N42E046
N43E040 N43E041 N43E042 N43E043 N43E044 N43E045 N43E046"

need="curl sha256sum tar"
[ "$geoid_only" = 1 ] || need="$need jq"
for tool in $need; do
  command -v "$tool" >/dev/null || { echo "fetch-ground: $tool not found" >&2; exit 1; }
done

sha() { sha256sum "$1" | cut -d' ' -f1; }
get() { curl -fsSL --retry 3 --retry-delay 5 --max-time 900 -o "$2" "$1"; }

mkdir -p "$dir"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- geoid -------------------------------------------------------------
while read -r model archive_sha pgm_sha; do
  [ -n "$model" ] || continue
  pgm="$dir/$model.pgm"
  if [ -f "$pgm" ]; then
    if [ "$(sha "$pgm")" = "$pgm_sha" ]; then
      echo "fetch-ground: $model.pgm present, sha256 ok"
      continue
    fi
    echo "fetch-ground: $model.pgm has the wrong sha256; fetching again" >&2
    rm -f "$pgm"
  fi
  get "$geoid_base/$model.tar.bz2" "$work/$model.tar.bz2"
  got="$(sha "$work/$model.tar.bz2")"
  if [ "$got" != "$archive_sha" ]; then
    echo "fetch-ground: $model archive sha256 $got, expected $archive_sha" >&2
    exit 1
  fi
  tar -xjf "$work/$model.tar.bz2" -C "$work"
  found="$(find "$work" -name "$model.pgm" -print -quit)"
  [ -n "$found" ] || { echo "fetch-ground: $model.pgm not in the archive" >&2; exit 1; }
  got="$(sha "$found")"
  if [ "$got" != "$pgm_sha" ]; then
    echo "fetch-ground: $model.pgm sha256 $got, expected $pgm_sha" >&2
    exit 1
  fi
  mv "$found" "$pgm.part"
  mv "$pgm.part" "$pgm"
  echo "fetch-ground: wrote $pgm"
done <<< "$grids"

if [ "$geoid_only" = 1 ]; then
  echo "fetch-ground: geoid grids in $dir (GEOID_FILE=$dir/egm2008-2_5.pgm, USPACE_GEOID_DIR=$dir)"
  exit 0
fi

# --- terrain -----------------------------------------------------------
base="${TERRAIN_TILES_URL:?TERRAIN_TILES_URL is unset: the base URL of the tiles the lab publishes (or use --geoid-only)}"
sums_pin="${TERRAIN_SHA256SUMS_SHA256:?TERRAIN_SHA256SUMS_SHA256 is unset: the pinned sha256 of the SHA256SUMS the lab publishes}"
cells="${GROUND_CELLS:-$default_cells}"
tiles="$dir/tiles"
mkdir -p "$tiles"

get "$base/SHA256SUMS" "$work/SHA256SUMS"
got="$(sha "$work/SHA256SUMS")"
if [ "$got" != "$sums_pin" ]; then
  echo "fetch-ground: SHA256SUMS sha256 $got, expected $sums_pin" >&2
  exit 1
fi
# want FILE: the pinned sha256 of FILE in SHA256SUMS, or nothing.
want() { awk -v f="$1" '{ n = $2; sub(/^\*/, "", n); if (n == f) { print $1; exit } }' "$work/SHA256SUMS"; }

# verified URL_NAME OUT: download one file and check it against SHA256SUMS.
verified() {
  local expect
  expect="$(want "$1")"
  [ -n "$expect" ] || { echo "fetch-ground: $1 is not in SHA256SUMS" >&2; exit 1; }
  get "$base/$1" "$2"
  local got
  got="$(sha "$2")"
  if [ "$got" != "$expect" ]; then
    echo "fetch-ground: $1 sha256 $got, expected $expect" >&2
    exit 1
  fi
}

verified index.json "$work/index.json"
# The lab's index, flat or {"cells": {...}}, as one flat map.
jq -e 'if has("cells") then .cells else . end | type == "object"' "$work/index.json" >/dev/null ||
  { echo "fetch-ground: index.json is not a map of cells" >&2; exit 1; }
jq 'if has("cells") then .cells else . end' "$work/index.json" > "$work/cells.json"

kept="{}"
for cell in $cells; do
  case "$cell" in
    [NS][0-9][0-9][EW][0-9][0-9][0-9]) ;;
    *) echo "fetch-ground: $cell is not a cell name (N41E044)" >&2; exit 1 ;;
  esac
  dataset="$(jq -r --arg c "$cell" '.[$c] // empty' "$work/cells.json")"
  if [ -z "$dataset" ]; then
    echo "fetch-ground: $cell is not in the lab's index; it stays unknown ground" >&2
    continue
  fi
  if [ "$dataset" != "sea" ]; then
    out="$tiles/$cell.pgm"
    if [ -f "$out" ] && [ "$(sha "$out")" = "$(want "$cell.pgm")" ]; then
      echo "fetch-ground: $cell.pgm present, sha256 ok"
    else
      verified "$cell.pgm" "$work/$cell.pgm"
      mv "$work/$cell.pgm" "$out.part"
      mv "$out.part" "$out"
      echo "fetch-ground: wrote $out ($dataset)"
    fi
  fi
  kept="$(jq --arg c "$cell" --arg d "$dataset" '. + {($c): $d}' <<< "$kept")"
done

jq --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg src "$base" \
  '{cells: ., fetched_at: $at, source: $src}' <<< "$kept" > "$tiles/index.json.part"
mv "$tiles/index.json.part" "$tiles/index.json"
echo "fetch-ground: $(jq 'length' <<< "$kept") cells in $tiles/index.json (GROUND_DIR=$tiles)"
