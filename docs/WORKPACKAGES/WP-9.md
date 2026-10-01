# WP-9: the telemetry writer

Branch `feat/WP-9-tsdb-writer`. Milestone A-M2. Owns `cmd/tsdb-writer`,
the writer side of `internal/store/ts`, the `writer_gaps` table, the
hypertable policies (chunking, compression, retention) for every
hypertable, and `schemas/tsw/*`. Depends on WP-1. Hypertable *columns*
are owned by the WP that defines the data (`rid_observations` WP-7,
`tracks` WP-8, `ussp_flights` WP-14, `manned_tracks` WP-15); this WP owns
the mechanics and the policies and provides the `Writer` those WPs
register their tables with. Consumers: WP-7, WP-8, WP-14, WP-15, WP-27.

## Read first

1. `docs/PLAN.md` §2 rules, §4.2, §6 (`tsw.v1`, `ingest.v1`), §8
   (storage), §10.
2. Spec `03` conventions (hypertables, the only writer), `05 §4`
   (retention, compression, `compress_segmentby`/`orderby`), `05 §5`
   (TimescaleDB writer row), `05 §6` (TimescaleDB and NATS failure
   domains), `05 §7` (storage criterion).
3. LESSONS B-05, B-06, B-07, B-08, B-12, B-13, C-13, E-02, E-09, E-10;
   scenario SC-18.
4. Reference only: utm `gateway/state_writer.py`,
   `gateway/ingest_store_pg.py`, `gateway/retention.py`,
   `docs/decisions/002-drain-rate-requirement.md`.

## What to build

- `cmd/tsdb-writer`: JetStream pull consumers on `tsw.v1.<table>` (one
  per table, explicit ack, `max_ack_pending` bounded) and on
  `ingest.v1.<cell3>` (raw observation rows); batches rows per table
  (by count ≤ 1000 or 500 ms), writes with `pgx` `CopyFrom`, acks after
  the copy commits (B-05). The in-memory queue per table is bounded to
  10 s of rows; beyond it the consumer stops pulling (JetStream holds
  the rest for its retention) and the status line says `spilling`; a
  message older than the stream's retention is lost **by JetStream**
  and the writer records the gap it observes (sequence jump) in
  `writer_gaps` (B-13).
- Idempotent writes: every hypertable has a dedupe key
  (`rid_observations`: `(receiver_id, transmitter, rx_ts, payload_hash)`;
  `tracks`: `(track_id, source_instance, captured_at)`; the others per
  their WP) with `ON CONFLICT DO NOTHING` through a staging copy, so a
  redelivered batch writes nothing twice (B-05).
- `writer_gaps(table, from_seq, to_seq, cause, count, at)` and the
  counters `rows_written`, `rows_deduplicated`, `batches`, `spills`,
  `gaps` on the status line and `/metrics`.
- Policies (migrations in `migrations/timeseries/`): 1-day chunks;
  compression after 7 days with `segmentby` and `orderby` per table
  (`05 §4`); retention 90 days online for `rid_observations`, `tracks`,
  `manned_tracks` (archive before drop is WP-27; until then the
  retention policy is **not** added, documented); `ussp_flights`
  retention 24 h (WP-14 adds the table and this WP's helper adds the
  policy and the hourly `older_than_24h` check that fails loudly).
- Roles: the writer role has `INSERT` and `SELECT`; `UPDATE` and
  `DELETE` are not granted to any application role on hypertables
  (`06` T7); a test asserts the refusal (and the insert beside it, E-01).
- `store/ts.Writer` library interface used by the adapters:
  `Enqueue(table, rows)` publishes to `tsw.v1.<table>`; the adapters
  never open the database.

## Tests

- Integration: batches written and read back; redelivery writes nothing
  twice; TimescaleDB stopped for 60 s then started → every row arrives,
  none duplicated, `spills` counted (SC-18 as the writer sees it;
  E-02: read the success status line after recovery); a forced
  sequence gap recorded in `writer_gaps`; compression job runs on a
  backdated chunk; the 24 h retention check reports empty on a clean
  table and non-empty after a backdated insert (E-01).
- E-10: queue bound per table; a table with 11 s of rows stops pulling.
- Load smoke: 3000 rows/s for 60 s on the CI runner; writer queue depth
  stays under 10 s (`05 §7`).

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] The load smoke numbers and the recovery run in the PR.
- [ ] `docs/runbooks/tsdb-writer.md`: what `spilling`, `gap` and
  `deduplicated` mean, and what an operator does about each.
- [ ] CHANGELOG line; `cmd/tsdb-writer` doc and `internal/store/ts/doc.go`.

## Commits

`feat(tsdb-writer): batched idempotent COPY writer with a bounded queue and gap records [WP-9 A-M2]`,
`feat(store): chunk, compression and retention policies per hypertable [WP-9 A-M2]`,
`test(tsdb-writer): rows survive a database outage without loss or duplication [WP-9 A-M2]`.
