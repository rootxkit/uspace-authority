-- WP-8: writer_positions, the highest TSW stream sequence tsdb-writer has
-- written for each table, updated in the transaction of the rows it
-- covers (LESSONS B-13: holes are holes).
--
-- A purge of the TSW stream (`nats stream purge TSW`) moves every
-- consumer's acknowledgement floor past the purged messages, so a writer
-- that starts after it sees no step in the sequences it is delivered and
-- WP-9 recorded nothing. The floor only ever moves past sequences this
-- writer wrote, except by a purge (or a delete); a floor beyond the
-- position stored here is therefore a purge while the writer was not
-- consuming, and tsdb-writer records it in writer_gaps as stream_purge
-- before it pulls anything (internal/tswriter).
--
-- Not a hypertable: one row per (table, stream), so the writer role is
-- granted UPDATE on it; it still holds neither UPDATE nor DELETE on any
-- hypertable.

-- +goose Up
CREATE TABLE writer_positions (
    table_name  text        NOT NULL,
    stream      text        NOT NULL,
    last_seq    bigint      NOT NULL CHECK (last_seq >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (table_name, stream)
);

GRANT SELECT, INSERT, UPDATE ON writer_positions TO authority_ts_writer;
REVOKE ALL ON writer_positions FROM authority_ts_projector;

-- +goose Down
DROP TABLE IF EXISTS writer_positions;
