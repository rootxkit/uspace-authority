-- WP-8 (LESSONS S-35, I-03): which receiver's Basic ID identified a
-- direct Remote ID track. A receiver that hears only Locations borrows
-- the fresh identity another receiver heard for the same transmitter;
-- the track's source_instance is the receiver that heard the Location,
-- identity_receiver the one that lent the identity (itself when it heard
-- both). Null for an unidentified track and for sources without one.

-- +goose Up
ALTER TABLE tracks ADD COLUMN identity_receiver text;

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
  -- Dropping a column of a compressed hypertable needs its chunks
  -- decompressed first; a Down never drops a row.
  PERFORM decompress_chunk(c, if_compressed => true) FROM show_chunks('tracks') c;
END
$$;
-- +goose StatementEnd
ALTER TABLE tracks DROP COLUMN IF EXISTS identity_receiver;
