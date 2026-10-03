# manned-ingest runbook (WP-15)

`manned-ingest` is the authority's client of the ANSP's manned traffic
information service (spec 02 F4, Reg. (EU) 2021/665 ATS.OR.127(a)). It
reads the ANSP's stream, publishes every manned aircraft on `man.v1` for
the picture, writes it to `manned_tracks` through tsdb-writer and says
how the feed is doing on `src.v1.ansp_feed.*`. It never sends anything
towards an aircraft and never opens a database.

## The contract

Everything on the wire is the ANSP's, pinned in `api/clients/` at the
commit `api/clients/SOURCE` records (CI fetches and diffs every copy):

| What | Where |
|---|---|
| `GET /v1/manned-traffic/snapshot?bbox=` | `api/clients/ansp.yaml` (`MannedSnapshot`) |
| `WS /v1/manned-traffic/stream?bbox=` | `api/clients/ansp.yaml` (`MannedStreamFrame`) |
| `track/manned/v1` | `api/clients/ansp-schemas/track/manned/v1.json` |

A bump of the ANSP's contract is a `build:` commit that changes the
copies and their SOURCE lines together; `TestBodyMembersAreTheSchemas`
fails when a member is added or renamed and the code has not followed.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `ANSP_BASE_URL` | unset | the ANSP's published base URL; its host is the token audience. Unset: nothing is connected and the feed says `unavailable` (`ansp_unconfigured`) |
| `MANNED_BBOX` | unset | `west,south,east,north`: Georgia or the designated areas. Unset: the ANSP's relevance filter alone decides |
| `AUTHORITY_MTLS_MODE` | `required` | `required`: `MANNED_CLIENT_CERT` and `MANNED_CLIENT_KEY` are presented to the ANSP and must be readable, or the process does not start. `off` (lab, staging): no certificate, said at error level at start and on every status line |
| `MANNED_CLIENT_ID`, `MANNED_CLIENT_SECRET_FILE`, `MANNED_TOKEN_URL` / `ISSUER_URL` | `authority-01` | this system's client at its own token service; the token has scope `ansp.traffic` and `aud` the ANSP's host. Without a secret every connection is refused locally (`no_token`) |
| `MANNED_FEED_INSTANCE` | `ansp` | the feed's own source instance |
| `MANNED_STALE_AFTER_S` | 5 | no frame (status frames included) for this long: `stale` |
| `MANNED_LAG_AFTER_S` | 15 | the freshest live aircraft older than this on arrival: `lagging` with `lag_s` |
| `MANNED_SILENT_RECONNECT_S` | 15 | a connection silent this long is closed and opened again |
| `MANNED_BACKOFF_MIN_MS` / `_MAX_MS` | 500 / 30000 | reconnection backoff, jittered; it never stops |
| `MANNED_MAX_AIRCRAFT`, `MANNED_MAX_FRAME_BYTES`, `MANNED_MAX_SNAPSHOT_*`, `MANNED_MAX_ADAPTERS`, `MANNED_ROWS_QUEUE` | see `--help` | bounds; each overflow is a counter |

The client of `MANNED_CLIENT_ID` needs the scope `ansp.traffic` and the
ANSP's host among its audiences (`/v1/oauth/clients`); the ANSP must
know this system's certificate subject (its `ANSP_MTLS_MODE`).

## What a frame becomes

- `track/manned/v1`: the body is validated against the ANSP's schema
  (refused: `aircraft_refused_schema`); an adapter switched off here is
  refused (`aircraft_refused_source_disabled`). Placement: the frame's
  samples and the ANSP's write time (`captured_at + age_s`) go through
  `timeplace.PlaceBatch`, which puts the write time at this system's
  arrival, so `captured_at` = arrival minus the ANSP's age and the
  ANSP's clock does not matter; past 120 s the sample is placed at the
  bound (`placements_clamped`); a frame without `rx_ts` is placed at
  arrival with `time_source: system` (`placed_at_arrival_without_rx_ts`).
  The body is published as the ANSP wrote it: `alt_pressure_m` is
  pressure altitude and never AMSL, `alt_wgs84_m` is null when the source
  gave none.
- `console/status/v1`: the ANSP's `degraded[]`, `sources[]` and
  `adapters[]` are kept; an adapter it calls `stale` or `down` ages its
  aircraft `stale`, one `disabled` ages them `source_disabled`.
- `console/snapshot/v1`: its aircraft are one batch.
- Anything else: `frames_unknown_schema_skipped`, never a disconnection.

Per aircraft one state is kept: an older sample, or the same sample
again (the snapshot after a reconnection), is skipped
(`duplicates_skipped`, `older_samples_skipped`); the same sample in a
later state is republished in that state with its own placement.
Samples are ordered by their own time, but never later than
`MANNED_MAX_SOURCE_AHEAD_MS` (5 s) after they arrived: one stamped
further ahead (an adapter clock jump) is counted
`source_time_in_future` and ordered at its arrival, so the genuine
samples after it are not skipped as older. An aircraft is aged, never removed by this process; the picture removes an
aircraft older than `stale_after_s` on its own, and says
`manned_unavailable` while the feed is not live.

## Feed states

| `feed_state` | `src.v1` `state` | Meaning |
|---|---|---|
| `healthy` | `live` | connected and fed |
| `lagging` | `live`, `lagging: true`, `lag_s` | frames arrive but the freshest aircraft is old (B-03) |
| `stale` | `stale` | connected, no frame for `MANNED_STALE_AFTER_S` |
| `unavailable` | `down`, `unavailable_since`, `reason` | the socket is down (`not_connected`, `connection_closed`, `connection_refused`, `connection_silent`, `no_token`, `ansp_unconfigured`). The ANSP's data is not lost (B-04): it was simply not received |
| `disabled` | `disabled`, `disabled_by`, `disabled_by_who` | switched off by source control |

`src.v1.ansp_feed.<MANNED_FEED_INSTANCE>` carries the feed;
`src.v1.ansp_feed.<adapter>` carries each ANSP adapter's own status with
this system's switch, and the feed's reachability, laid over it
(`feed_state`, `via`).

## Source control

Switch `ansp_feed` (the type) or `ansp_feed/<MANNED_FEED_INSTANCE>` off:
the stream closes within a second, every aircraft is republished
`source_disabled`, the status says disabled by whom; on again, it
reconnects. Switch one adapter off (`ansp_feed/adsb-tbs`): its frames
are refused and its aircraft aged `source_disabled`; the others pass.

## Rows

`manned_tracks` (timeseries 00012) holds one row per published message.
Its time is the sample's `captured_at` on the ANSP's clock
(`source_captured_at`), which names a sample across reconnections and
restarts, so the dedupe key writes each state of a sample once.
`captured_at` is this system's placement. Rows that cannot be handed to
tsdb-writer are counted and recorded as a writer gap
(`manned_handover_failed`). Evidence packs include the rows around the
evidence (`INCIDENTS_MANNED_MARGIN_M`, docs/runbooks/incidents.md).

## Checks

- `make integration` runs `TestIntegrationMannedTrafficOnThePicture`
  (cmd/picture-ws): the recorded file served by the fake ANSP over mTLS
  reaches the console with trust surveillance and an age, lands in
  `manned_tracks`; a 30 s ANSP outage is `down` since that instant and
  `manned_unavailable` on every status, and resumption publishes and
  writes nothing twice; switching the feed off closes the stream.
- The recording (`internal/ltest/fakeansp/testdata/adsb-recording.jsonl`)
  is synthetic, in the ANSP's body shape; it is not a capture of real
  traffic.
