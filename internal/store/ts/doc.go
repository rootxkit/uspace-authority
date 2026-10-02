// Package ts is the telemetry database (TimescaleDB) with three query
// sets: the writer (tsdb-writer only, role authority_ts_writer), the
// reader (hot-path processes and api's record reads, role
// authority_ts_reader, SELECT only) and the projector (api's writes of
// the projection tables, role authority_ts_projector, WP-3).
// internal/store's doc.go describes the whole store.
//
// The writer side (WP-9):
//
//   - Writer is how an adapter hands rows to tsdb-writer: Enqueue
//     publishes a RowsMessage on tsw.v1.<table> (EnqueueGap a GapMessage
//     on tsw.v1.writer_gaps) and returns once JetStream has it. BusWriter
//     is the JetStream implementation. Adapters never open the database.
//   - Table and Tables register the hypertables tsdb-writer writes, with
//     their columns in COPY order; DecodeRow maps a row of a message
//     onto them and refuses a missing, mistyped or unknown member. A WP
//     that adds a hypertable (tracks WP-8, ussp_flights WP-14,
//     manned_tracks WP-15) adds its Table here with its migration and
//     calls authority_hypertable_policies (timeseries 00005) for its
//     chunking, compression and retention.
//   - WriterPool.Write stores parts in one transaction: COPY into a
//     session staging table, INSERT .. ON CONFLICT DO NOTHING into the
//     hypertable, so a redelivered row whose dedupe key is stored is
//     counted as a duplicate and not written twice (B-05).
//     rid_observations' key is (frame_id, ingest_ts): frame_id is the
//     hash of (receiver_id, transmitter, receiver_ts, payload_sha256) and
//     a hypertable's unique index must hold its time column.
//   - Gap is a writer_gaps row (B-13); WriterGaps its table.
//   - WriterPool.OlderThan is the retention check of a table with a
//     retention period.
//
// No application role holds UPDATE or DELETE on a hypertable (spec 06
// T7); an integration test proves the refusal beside the insert.
package ts
