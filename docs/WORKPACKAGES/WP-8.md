# WP-8: the Remote ID pipeline and the track format

Branch `feat/WP-8-rid-pipeline`. Milestone A-M2. Owns `internal/ridpipe`,
`internal/track`, `schemas/track/telemetry/v1.json`, the `tracks`
hypertable migration (writer in WP-9), the `ident.v1` subject, and the
decoded columns of `rid_observations`. Depends on WP-3 (projection
reader), WP-7 (`ridpipe.Sink`), WP-10 (bus, cell), WP-11 (geoid).
Consumers: WP-12, WP-13, WP-14 (shares `internal/track` and the
identification step), WP-25.

Safety-relevant: every identification and every position the picture
shows for a broadcast passes here. Reviewed adversarially.

## Read first

1. `docs/PLAN.md` §1.2 D4, D6, §2.1, §6, §8, §14 Q-A8.
2. Spec `02 F9` (decoding rules are the authority's), `04 §2` (envelope,
   trust, `captured_at`, `time_source`, `backlog`), `04 §3.1`
   `track/telemetry/v1` and the altitude rules, `04 §3.2`
   identification, `05 §3` cells.
3. `uspace-core`: `odid.Decode` and `DecodeOptions`, `timeplace.PlaceBroadcast`
   / `Times`, `rid.Tracker` (`Settings`, `Frame`, `Observation`, `Take`,
   `Forget`), `rid.AircraftID`, `rid.UnidentifiedID`,
   `rid.AltitudeSelector`, `rid.VelocityNED`, `rid.Airborne`,
   `geoid.Undulator`, `identify.ResolveRemoteID` / `ResolveBroadcast`
   / `Unavailable` / `SerialConflict`, `identify.RemoteIDIdentity`,
   `core.Identification`, `core.Times`, `core.Trust`.
4. LESSONS R-01..R-05, R-07..R-13, R-17, I-01..I-07, G-01, G-02, G-05,
   G-09, G-12, T-01, T-07, T-08, T-11, T-12, D-03, E-03, E-09, E-10;
   scenarios SC-05 (step 3: no geoid → no AMSL), SC-06, SC-09 (as the
   authority sees it: D6), SC-10, SC-11, SC-22.
5. Reference only: utm `gateway/remote_id.py`, `gateway/odid.py`,
   `gateway/remote_id_match.py`, `gateway/identification.py`,
   `docs/runbooks/u02-identification.md`.

## What to build

### `internal/track`

- The Go struct for `track/telemetry/v1` with the envelope of `04 §2`
  and the fields of `04 §3.1`, JSON tags equal to the schema, the schema
  file in `schemas/`, a validator that refuses `trust: simulated` and
  `source: sitl` (T11), `Subject(cell3, cell5, trackID)`, and
  `Publish(bus, track)`.
- `IdentChange` for `ident.v1.<track_id>`: emitted when a track's
  identification block changes (status, reason, mismatch).

### `internal/ridpipe`

One `Pipeline` per `rid-ingest` process; `Sink.Observe(batch)` is what
WP-7 calls. Steps per observation, each a function with its own counters:

1. **Decode** (`odid.Decode`, R-01..R-04): refusals counted by phrase;
   Self-ID and Authentication skipped; unknown values are nil, never
   numbers. The decoded columns are written back into the
   `rid_observations` row (serial, operator_reg, id_type, lat, lon,
   alt_wgs84_m, alt_pressure_m, height_m, height_ref, speed_ms,
   track_deg, vspeed_ms, status, ts_broadcast).
2. **Identity per transmitter** (`rid.Tracker`, settings from policy:
   identity TTL 15 s, max gap 3 s, identify within 4 s; I-01..I-04,
   R-13): one tracker per process keyed by transmitter across receivers
   (I-03 borrowing), bounded (E-10), `Forget` on tick; an unidentified
   track id from `rid.UnidentifiedID(transmitter)`, an identified one
   from `rid.AircraftID(idType, uaID)` (I-06; D6: the same id the DP path
   uses for the same serial).
3. **Time placement** (`timeplace.PlaceBroadcast` with the receiver's
   `rx_ts` and the declared accuracy; T-07, T-08): `captured_at`,
   `time_source`, fallback counted; batch rows keep their spacing
   (T-02 is for network placement; here each observation has its own
   `rx_ts`); a missing `rx_ts` is placed at arrival and counted (T-12);
   `backlog` copied from the batch (T-04).
4. **Altitude** (`rid.AltitudeSelector` with the geoid from WP-11; R-07,
   R-08): `alt_amsl_m` from HAE and the undulation; pressure fallback
   with the 10 s hold; `alt_source`; with no geoid configured
   `alt_amsl_m` is nil, counted, and the startup line says such aircraft
   are not judged vertically (SC-05 step 3, SC-22).
5. **Velocity and airborne** (`rid.VelocityNED`, `rid.Airborne`; R-10,
   R-11): nil, not zero, without a direction; `flying` from status.
6. **Identification** (`identify.ResolveRemoteID` over the
   `registry.ProjectionReader` snapshot; G-01, G-02, G-05, G-12, I-05):
   `basis: as_broadcast`; `registry_unavailable` while the projection
   has never loaded (SC-22); the broadcast operator number compared on
   its public part. (D6: no authenticated rows exist here, so
   `JudgeFleet` is not called; the `serial_conflict` reason cannot arise
   from this process. Document it in `doc.go`.)
7. **Publish**: one `track/telemetry/v1` per published `Observation`
   (`Tracker.Take` returns nil for a frame that publishes nothing,
   R-13), `trust: broadcast`, `source: direct_rid`, `source_instance:
   <receiver id>`, `cell` from `internal/cell`, on
   `trk.v1.<cell3>.<cell5>.<track_id>`; the identification change on
   `ident.v1` when it differs from the last one published for the id
   (bounded map, E-10); the `tracks` row to `tsw.v1.tracks`.

Every step's counters are on the status line and `/metrics`; the first
occurrence of each refusal is logged, then rate-limited per key (E-09:
a spoofer alternating serials must not fill the log).

## Tests

- Vectors through `RunOwned("authority")`: `odid_decode.json` (frames →
  decoded columns of the row: the adapter's mapping), `rid_time.json`
  broadcast cases (observation → `captured_at`/`time_source`),
  `rid_identity.json` (frame sequences → published observations and
  counters), `pressure_altitude.json` (→ `alt_amsl_m`, `alt_source`),
  `identification_status.json` broadcast and remote-id-block kinds (→
  the identification block on the published track). Each test maps
  wire → this repo's adapter → core and compares the adapter's output;
  none re-implements a judgement.
- E-03: the ODID timestamp offset is derived in the test by diffing two
  encoded frames (`odid.Encode`), not written down.
- Scenarios (in-process, simulated clocks, `internal/ltest` receiver):
  SC-10 (serial change on a reused address with 30 % drops, with the
  control run under the old 60 s rules proving the test can detect the
  bug, E-01), SC-11 (2 s receiver latency → placed at broadcast time),
  SC-06 rows 1, 2 (direct), 3, 5 (statuses and the unidentified second
  transmitter), SC-22 (no geoid, no projection: nil altitude, null
  identification, both visible on the status line).
- E-10: tracker transmitter bound, ident-change map bound.
- Benchmarks `BenchmarkPipelineObserve` (target ≤ 200 µs per
  observation at one core, plan §8).

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] A simulated receiver's frames for three aircraft appear as
  `trk.v1` messages with the right ids, altitudes, times and
  identification in the integration test; `tracks` rows written through
  WP-9.
- [ ] The five vector files above pass through the adapters; counts in
  the PR.
- [ ] CHANGELOG line; `internal/ridpipe/doc.go` and `internal/track/doc.go`.

## Commits

`feat(track): the track/telemetry/v1 message, schema and subjects [WP-8 A-M2]`,
`feat(ridpipe): decode, identity per transmitter and time placement for direct Remote ID [WP-8 A-M2]`,
`feat(ridpipe): AMSL through the geoid with the pressure fallback and hold [WP-8 A-M2]`,
`feat(ridpipe): resolve every broadcast against the registry projection [WP-8 A-M2]`,
`test(ridpipe): run the Remote ID vectors through the ingest adapters [WP-8 A-M2]`.
