# Runbook: ground (terrain and geoid)

The authority judges heights against two datasets it holds itself
(WP-11, `internal/ground`): the **geoid**, which turns a GNSS height
above the WGS84 ellipsoid (HAE) into a height above mean sea level
(AMSL), and the **terrain** (a digital elevation model, DEM), which
turns AMSL into a height above the ground at the moment it is judged.
No height above ground is ever stored (LESSONS D-02). Both are files on
a read-only volume mounted into `detect` and `rid-ingest`; neither is in
git or in the image.

| Variable | Process | Meaning |
|---|---|---|
| `GEOID_FILE` | rid-ingest, detect | `egm2008-2_5.pgm`, GeographicLib's EGM2008 2.5' grid |
| `GROUND_DIR` | detect | the tiles `<cell>.pgm` and `index.json` |
| `GROUND_TILE_CACHE` | detect | tiles held in memory, least recently used out first (default 16, about 26 MB each) |
| `GROUND_RETRY_AFTER_S` | detect | how long a tile that could not be read stays unknown before it is read again (default 60) |

## What happens without them

Nothing is guessed (LESSONS D-04, R-07, Z-09):

- **No geoid** (`GEOID_FILE` unset, or a file that cannot be read): a
  Remote ID aircraft's geodetic altitude stays HAE only; `alt_amsl_m` is
  null and the aircraft is not judged vertically. A pressure altitude is
  never AMSL either way (R-08). A WGS84 zone limit is not judged.
- **No terrain** (`GROUND_DIR` unset): an AGL zone limit is not judged:
  a PROHIBITED or REQ_AUTHORIZATION zone warns with `limit_not_judged`
  and `not_judged: ["AGL"]`, a CONDITIONAL zone is not evaluated; the
  120 m height limit is not evaluated (counted
  `height_checks_not_evaluated`).
- **Unknown ground** (a cell not fetched, a nodata sample, a tile that
  cannot be read, an `index.json` that cannot be read): the same as no
  terrain at that position, with reason `ground_unknown`. A sea cell is
  0 m.

Each process says so at start and on every status line:

```
{"msg":"ground datasets","terrain":"loaded","terrain_datasets":["COP-DEM GLO-30"],
 "terrain_cells":21,"terrain_tiles_cached":0,"terrain_retry_after_s":60,
 "terrain_attribution":"Produced using Copernicus WorldDEM-30 ...",
 "geoid":"loaded","geoid_description":"WGS84 EGM2008, 2.5-minute grid","geoid_mapped":true}
{"level":"WARN","msg":"terrain not configured: AGL zone limits are not judged (limit_not_judged) and the height limit is not evaluated", ...}
{"level":"WARN","msg":"geoid unavailable: no AMSL altitude from a geodetic (HAE) one: ...","reason":"GEOID_FILE: open ...: no such file or directory"}
```

The states are `loaded`, `not configured` and `unavailable` (with the
reason). `geoid_mapped` and `terrain_mapped` say whether the grid and
the last tile read are read-only memory maps of their files (uspace-core
`geoid.LoadMapped`, `terrain.MappedDirOpener`): `true` on linux, so the
processes on one host (detect, dp-poller, rid-ingest) share one copy of
EGM2008 and of each tile in the page cache; `false` where core reads the
file into memory instead. `terrain_mapped` appears once a tile has been
read; dp-poller and rid-ingest say `geoid_mapped` beside `geoid_grid`.
A mapped file must be replaced by renaming a new one over it, never
rewritten in place (the process would fault). The counters on the status line and `/metrics`:

| Component | Counter | Meaning |
|---|---|---|
| `ground` | `ground_known`, `ground_unknown`, `ground_not_configured` | lookups by answer |
| `ground` | `ground_terrain_unavailable` | lookups answered unknown because `index.json` could not be read |
| `ground` | `undulation_unavailable`, `geoid_lookup_failed` | lookups without an undulation; positions the grid refused |
| `terrain` | `tiles_loaded` | tiles read into the cache (the cache misses) |
| `terrain` | `tiles_evicted` | tiles dropped past `GROUND_TILE_CACHE` |
| `terrain` | `tile_read_failed`, `tile_read_retried`, `tile_unavailable` | a listed tile that is missing or unreadable, its retries, and the answers left unknown because of it |
| `terrain` | `unknown_cell`, `nodata`, `invalid_position` | positions outside the fetched cells, beside a nodata sample, or invalid |
| `ridpipe` | `alt_amsl_unavailable_no_geoid`, `geoid_failed` | Remote ID altitudes left HAE only |

A `tile_read_failed` that keeps growing once a minute is a tile listed
in `index.json` and missing or corrupt on the volume: fetch again.

## Fetching

```
deploy/fetch-ground.sh --geoid-only /srv/ground          # the geoid grids
TERRAIN_TILES_URL=<lab release URL> \
TERRAIN_SHA256SUMS_SHA256=<pinned hash from the release notes> \
deploy/fetch-ground.sh /srv/ground                       # grids and tiles
```

It writes `egm2008-2_5.pgm` (`GEOID_FILE`), `egm96-15.pgm` (vectors
only), and `tiles/<cell>.pgm` with `tiles/index.json` (`GROUND_DIR`).

- The geoid grids come from GeographicLib's distribution of the NGA
  models and are pinned by SHA-256, archive and extracted file (the
  same pins as uspace-core's `scripts/fetch-geoid.sh`). A grid already
  present with the right hash is kept; one with the wrong hash is
  fetched again; a download with the wrong hash fails the run.
- The tiles are Copernicus GLO-30 cells converted by the lab's terrain
  tooling into the PGM container core reads. The script downloads the
  lab's published `SHA256SUMS` (pinned by `TERRAIN_SHA256SUMS_SHA256`),
  `index.json` and each tile, checks every file before it replaces
  anything, and writes an `index.json` holding only the cells it has.
  `GROUND_CELLS` lists the cells; the default is every 1 x 1 degree
  cell over Georgia, N41E040 to N43E046.
- Restart `detect` and `rid-ingest` after a fetch; the files are read at
  start (tiles on first use).

## Licence and attribution

- Copernicus DEM GLO-30: free to use; its licence requires this notice
  wherever elevations derived from it are shown (LESSONS D-05), and the
  console shows it beside every height above ground:

  > Produced using Copernicus WorldDEM-30 (c) DLR e.V. 2010-2014 and (c)
  > Airbus Defence and Space GmbH 2014-2018 provided under COPERNICUS by
  > the European Union and ESA; all rights reserved.

  The text is core's `terrain.Attribution` and is on the status line.
  Acceptance of the licence for the national system is open with the
  owner (plan Q-A13, spec Q10).
- EGM2008 and EGM96 (NGA, through GeographicLib): public domain.

## Accuracy to show operators

The DEM is a **surface model**: it measures roofs and canopy, not bare
ground. A height above it errs low: safe for clearance, a few metres
early for the 120 m limit (D-05). Show the dataset and the sample
spacing beside every number (`terrain.Elevation.Dataset`, `SpacingM`).

Measured against flight-controller terrain (LESSONS D-07, predecessor
P5-00 measurement table): 95 % of points on GLO-30 agree within
**4.3 m on plains** and **6.9 m in mountains**, maximum **14.4 m**.
Tbilisi on GLO-90 disagreed by 27 m, from 90 m spacing and a different
flight-controller source compounded, not because cities are worse; the
authority uses GLO-30.

The geoid: EGM2008 is the default because the Copernicus DEM is on it.
N is about 15.9 m at Tbilisi and 22.5 m at Batumi; EGM96 differs from
EGM2008 by -2.3 to +4.7 m over Georgia. A height computed on HAE as if
it were AMSL is off by N, which is why no geoid means no AMSL.

## Daylight

ED-318 zones may start or end at sunrise, sunset or civil twilight.
`ground.Daylight()` is core's `ed318.NOAADaylight` (NOAA's algorithm,
within one minute between 72 degrees north and south); it agrees with
published times for Tbilisi on 21 June and 21 December 2026 within the
2 minutes WP-11 asks (`internal/ground/daylight_test.go`). Terrain and
height above sea level are not taken into account: on a ridge the sun
rises earlier.
