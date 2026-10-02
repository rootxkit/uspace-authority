-- WP-9: the telemetry writer's tables and the policies of every
-- hypertable (docs/PLAN.md §4.2, spec 05 §4, LESSONS B-05, B-13).
--
-- writer_gaps     every hole in what reached the hypertables, with its
--                 cause and how much (B-13: holes are holes). Written by
--                 tsdb-writer only, once per hole (dedupe_key), in the
--                 same transaction as the rows written beside it:
--                   ingest_queue_full, ingest_queue_age,
--                   ingest_queue_corrupt  rid-ingest shed queued batches
--                                         (its tsw.v1.writer_gaps
--                                         records; from_seq/to_seq
--                                         number the INGEST stream)
--                   stream_retention      the TSW stream aged messages
--                                         out before tsdb-writer read
--                                         them (a jump in the stream
--                                         sequences it was delivered)
--                   malformed             a TSW message the writer could
--                                         not read
--                   rejected              rows the database refused
--                                         (a CHECK or type error)
--                 count is in count_unit: rows when the rows were known,
--                 messages when only TSW messages were seen. A
--                 stream_retention count is the number of TSW messages
--                 lost in the hole, whatever their table: one stream
--                 carries every table, so the lost messages of one table
--                 cannot be told from another's, and the count is an
--                 upper bound for table_name.
--                 The brief's column `table` is table_name here (TABLE
--                 is a reserved word).
--
-- The dedupe key of rid_observations (B-05): frame_id is the hash of
-- (receiver_id, transmitter, receiver_ts, payload_sha256), and a unique
-- index on a hypertable must hold its time column, so the key is
-- (frame_id, ingest_ts). A redelivered TSW message carries the same
-- ingest_ts and writes nothing twice (INSERT .. ON CONFLICT DO NOTHING
-- from a staging copy). It replaces 00004's non-unique frame index.
--
-- Policies (spec 05 §4): 1-day chunks; compression after 7 days with a
-- segmentby and orderby per table; retention 90 days online for
-- rid_observations, tracks and manned_tracks is NOT added here: the
-- archive before the drop is WP-27, and a retention policy without it
-- would delete evidence. The 24 h retention of ussp_flights (F3411
-- NetDpMaxDataRetentionPeriodSeconds) is added by WP-14's migration
-- with authority_hypertable_policies below, and tsdb-writer checks
-- hourly that nothing older remains.
--
-- authority_hypertable_policies(table, segmentby, orderby,
-- compress_after, retention) is the helper the later hypertables'
-- migrations call (tracks WP-8, ussp_flights WP-14, manned_tracks
-- WP-15): it sets the 1-day chunk interval, compression with the given
-- segmentby/orderby after compress_after (none when NULL) and a
-- retention policy when retention is not NULL. Each is idempotent.
--
-- Roles (spec 06 T7): the writer role keeps INSERT and SELECT on every
-- hypertable (00002's default privileges) and is granted TEMPORARY on
-- this database for its staging tables; no application role holds
-- UPDATE or DELETE on a hypertable.

-- +goose Up
CREATE TABLE writer_gaps (
    dedupe_key  text        PRIMARY KEY,
    table_name  text        NOT NULL,
    stream      text        NOT NULL,
    from_seq    bigint      NOT NULL CHECK (from_seq >= 0),
    to_seq      bigint      NOT NULL CHECK (to_seq >= from_seq),
    cause       text        NOT NULL,
    count       bigint      NOT NULL CHECK (count >= 0),
    count_unit  text        NOT NULL CHECK (count_unit IN ('rows', 'messages')),
    at          timestamptz NOT NULL,
    receiver_id text,
    detail      text,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX writer_gaps_table_at_idx ON writer_gaps (table_name, at DESC);

REVOKE ALL ON writer_gaps FROM authority_ts_projector;

-- +goose StatementBegin
DO $$
BEGIN
  EXECUTE format('GRANT TEMPORARY ON DATABASE %I TO authority_ts_writer', current_database());
END
$$;
-- +goose StatementEnd

DROP INDEX IF EXISTS rid_observations_frame_idx;
CREATE UNIQUE INDEX rid_observations_dedupe_idx ON rid_observations (frame_id, ingest_ts DESC);

-- +goose StatementBegin
CREATE FUNCTION authority_hypertable_policies(
    tbl            regclass,
    segmentby      text,
    orderby        text,
    compress_after interval,
    retention      interval
) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  PERFORM set_chunk_time_interval(tbl, INTERVAL '1 day');
  IF compress_after IS NOT NULL THEN
    EXECUTE format('ALTER TABLE %s SET (timescaledb.compress, timescaledb.compress_segmentby = %L, timescaledb.compress_orderby = %L)',
                   tbl, segmentby, orderby);
    PERFORM add_compression_policy(tbl, compress_after, if_not_exists => true);
  END IF;
  IF retention IS NOT NULL THEN
    PERFORM add_retention_policy(tbl, retention, if_not_exists => true);
  END IF;
END
$$;
-- +goose StatementEnd

SELECT authority_hypertable_policies('rid_observations', 'transmitter', 'ingest_ts DESC, frame_id', INTERVAL '7 days', NULL);

-- +goose Down
SELECT remove_compression_policy('rid_observations', if_exists => true);
-- +goose StatementBegin
DO $$
BEGIN
  -- Compressed chunks are decompressed before compression is switched
  -- off; a Down never drops a row.
  PERFORM decompress_chunk(c, if_compressed => true) FROM show_chunks('rid_observations') c;
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM authority_ts_writer', current_database());
END
$$;
-- +goose StatementEnd
ALTER TABLE rid_observations SET (timescaledb.compress = false);
DROP FUNCTION IF EXISTS authority_hypertable_policies(regclass, text, text, interval, interval);
DROP INDEX IF EXISTS rid_observations_dedupe_idx;
CREATE INDEX rid_observations_frame_idx ON rid_observations (frame_id, ingest_ts DESC);
DROP TABLE IF EXISTS writer_gaps;
