-- WP-27: the archive of the telemetry hypertables beyond their online
-- window (spec 05 §4, 06 §2 T7, 06 §5; docs/PLAN.md §4.2;
-- docs/runbooks/retention.md).
--
-- rid_observations, tracks and manned_tracks keep RETENTION_ONLINE_DAYS
-- online (90 days, pending GCAA). api's archive job exports each chunk
-- older than that to the archive store (ARCHIVE_URL) as gzip-compressed
-- newline-delimited JSON, reads the object back and checks its hash and
-- row count, and only then drops the chunk. No blanket retention policy
-- is added for these tables: a chunk is dropped by
-- authority_archive_drop_chunk, which refuses unless the chunk is
-- recorded here as archived with the very row count the chunk still
-- holds, and never inside the 30-day floor of operational records
-- (2021/664 Art. 15(1)(g)). So nothing is dropped unarchived, and a row
-- written into an old chunk after its export keeps the chunk online
-- until it is exported again.
--
-- archive_chunks is the ledger, one row per chunk the job exported:
--   state       exporting (an export started; a restart re-exports it),
--               archived (the object is verified), dropped (the chunk
--               is gone; the object is the only copy)
--   object_key  the object in the archive store; manifest_key its
--               manifest beside it
--   rows, bytes, sha256  what was written and verified
--   pii_redacted   rid_observations frames whose remote pilot position
--               was removed from the archived copy (06 §5)
--   payloads_dropped  frames that could not be decoded, so their payload
--               was left out of the archived copy (the position could
--               not be removed from them otherwise)
--   *_audited   the step is in the relational audit log (api
--               writes it in its own database after this commit and
--               catches up on a restart)
--   object_deleted_at  the archived object was deleted after
--               RETENTION_ARCHIVE_YEARS
--
-- authority_ts_archiver is api's role for this job: SELECT on the three
-- hypertables, the ledger, and EXECUTE on the two functions. It holds no
-- DELETE anywhere; tsdb-writer's role gets nothing here.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authority_ts_archiver') THEN
    CREATE ROLE authority_ts_archiver NOLOGIN;
  END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
  NULL; -- created concurrently by another database's migration
END
$$;
-- +goose StatementEnd

CREATE TABLE archive_chunks (
    hypertable        text        NOT NULL CHECK (hypertable IN ('rid_observations', 'tracks', 'manned_tracks')),
    chunk_name        text        NOT NULL CHECK (chunk_name <> '' AND length(chunk_name) <= 256),
    range_start       timestamptz NOT NULL,
    range_end         timestamptz NOT NULL CHECK (range_end > range_start),
    state             text        NOT NULL CHECK (state IN ('exporting', 'archived', 'dropped')),
    object_key        text        NOT NULL CHECK (object_key <> '' AND length(object_key) <= 1024),
    manifest_key      text        NOT NULL CHECK (manifest_key <> '' AND length(manifest_key) <= 1024),
    rows              bigint      CHECK (rows >= 0),
    bytes             bigint      CHECK (bytes >= 0),
    sha256            text        CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$'),
    pii_redacted      bigint      NOT NULL DEFAULT 0 CHECK (pii_redacted >= 0),
    payloads_dropped  bigint      NOT NULL DEFAULT 0 CHECK (payloads_dropped >= 0),
    attempts          integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error        text        CHECK (length(last_error) <= 2000),
    started_at        timestamptz NOT NULL DEFAULT now(),
    archived_at       timestamptz,
    dropped_at        timestamptz,
    archive_audited   boolean     NOT NULL DEFAULT false,
    drop_audited      boolean     NOT NULL DEFAULT false,
    object_deleted_at timestamptz,
    delete_audited    boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (hypertable, chunk_name),
    CHECK (state = 'exporting' OR (rows IS NOT NULL AND bytes IS NOT NULL AND sha256 IS NOT NULL AND archived_at IS NOT NULL)),
    CHECK ((state = 'dropped') = (dropped_at IS NOT NULL)),
    CHECK (object_deleted_at IS NULL OR state = 'dropped')
);

CREATE INDEX archive_chunks_range ON archive_chunks (range_end);

REVOKE ALL ON archive_chunks FROM authority_ts_writer, authority_ts_projector;
GRANT SELECT ON archive_chunks TO authority_ts_reader;

-- authority_archive_chunks lists the chunks of one of the three tables
-- whose range ended at or before older_than, oldest first.
-- +goose StatementBegin
CREATE FUNCTION authority_archive_chunks(tbl text, older_than timestamptz)
RETURNS TABLE (chunk_name text, range_start timestamptz, range_end timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF tbl NOT IN ('rid_observations', 'tracks', 'manned_tracks') THEN
    RAISE EXCEPTION 'archive: % is not an archived hypertable', tbl USING ERRCODE = 'invalid_parameter_value';
  END IF;
  RETURN QUERY
  SELECT format('%I.%I', c.chunk_schema, c.chunk_name), c.range_start, c.range_end
  FROM timescaledb_information.chunks c
  WHERE c.hypertable_schema = 'public' AND c.hypertable_name = tbl AND c.range_end <= older_than
  ORDER BY c.range_start, c.chunk_name;
END
$$;
-- +goose StatementEnd

-- authority_archive_drop_chunk drops one archived chunk: the ledger must
-- say archived with expected_rows, the chunk must still hold exactly
-- that many rows in its range, and its range must have ended 30 days
-- ago at least. It returns the dropped chunk and marks the ledger row.
-- +goose StatementBegin
CREATE FUNCTION authority_archive_drop_chunk(tbl text, chunk text, expected_rows bigint)
RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  rec     archive_chunks%ROWTYPE;
  timecol text;
  n       bigint;
  dropped text[];
BEGIN
  timecol := CASE tbl WHEN 'rid_observations' THEN 'ingest_ts' WHEN 'tracks' THEN 'captured_at'
                      WHEN 'manned_tracks' THEN 'source_captured_at' END;
  IF timecol IS NULL THEN
    RAISE EXCEPTION 'archive: % is not an archived hypertable', tbl USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT * INTO rec FROM archive_chunks a WHERE a.hypertable = tbl AND a.chunk_name = chunk FOR UPDATE;
  IF NOT FOUND OR rec.state <> 'archived' THEN
    RAISE EXCEPTION 'archive: % of % is not recorded as archived; it is not dropped', chunk, tbl
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  IF rec.rows IS DISTINCT FROM expected_rows THEN
    RAISE EXCEPTION 'archive: % was archived with % rows, not %', chunk, rec.rows, expected_rows
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  IF rec.range_end > now() - interval '30 days' THEN
    RAISE EXCEPTION 'archive: % ends inside the 30-day floor (2021/664 Art. 15(1)(g))', chunk
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  EXECUTE format('SELECT count(*) FROM %I WHERE %I >= $1 AND %I < $2', tbl, timecol, timecol)
    INTO n USING rec.range_start, rec.range_end;
  IF n <> rec.rows THEN
    RAISE EXCEPTION 'archive: % holds % rows now and % were archived; it is exported again before any drop', chunk, n, rec.rows
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  SELECT array_agg(d) INTO dropped
  FROM drop_chunks(tbl::regclass, older_than => rec.range_end, newer_than => rec.range_start) d;
  IF dropped IS DISTINCT FROM ARRAY[chunk] THEN
    RAISE EXCEPTION 'archive: dropping % would drop %; nothing is dropped', chunk, dropped
      USING ERRCODE = 'object_not_in_prerequisite_state';
  END IF;
  UPDATE archive_chunks a SET state = 'dropped', dropped_at = now()
  WHERE a.hypertable = tbl AND a.chunk_name = chunk;
  RETURN now();
END
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION authority_archive_chunks(text, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION authority_archive_drop_chunk(text, text, bigint) FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO authority_ts_archiver;
GRANT SELECT ON goose_db_version_timeseries TO authority_ts_archiver;
GRANT SELECT ON rid_observations, tracks, manned_tracks TO authority_ts_archiver;
GRANT SELECT, INSERT, UPDATE ON archive_chunks TO authority_ts_archiver;
GRANT EXECUTE ON FUNCTION authority_archive_chunks(text, timestamptz) TO authority_ts_archiver;
GRANT EXECUTE ON FUNCTION authority_archive_drop_chunk(text, text, bigint) TO authority_ts_archiver;

-- +goose Down
REVOKE ALL ON FUNCTION authority_archive_drop_chunk(text, text, bigint) FROM authority_ts_archiver;
REVOKE ALL ON FUNCTION authority_archive_chunks(text, timestamptz) FROM authority_ts_archiver;
DROP FUNCTION IF EXISTS authority_archive_drop_chunk(text, text, bigint);
DROP FUNCTION IF EXISTS authority_archive_chunks(text, timestamptz);
DROP TABLE IF EXISTS archive_chunks;
REVOKE ALL ON rid_observations, tracks, manned_tracks FROM authority_ts_archiver;
REVOKE ALL ON goose_db_version_timeseries FROM authority_ts_archiver;
REVOKE USAGE ON SCHEMA public FROM authority_ts_archiver;
