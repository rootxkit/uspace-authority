-- WP-27: retention of the relational records, legal holds, the job
-- ledger and the USSP daily records (spec 05 §4, 06 §2 T7, 06 §5,
-- 02 F7, 08 Q8; docs/PLAN.md §14 Q-A15, Q-A18;
-- docs/runbooks/retention.md).
--
-- The periods are configuration (RETENTION_*), the spec's defaults
-- pending GCAA and the DPO (Q8). What the database adds is the guard:
-- the application role still holds no DELETE on violations and no
-- UPDATE or DELETE on events; it deletes only through the SECURITY
-- DEFINER functions below, which
--   - refuse a cutoff inside the regulatory floor (30 days for
--     operational records, 2021/664 Art. 15(1)(g); a year for the
--     audit log), whatever the configuration says,
--   - delete a bounded batch per call (the caller commits each batch
--     with its events row, so nothing slow runs inside a transaction),
--   - take legal_holds in SHARE mode first, so a hold being placed
--     waits for the batch and a batch never misses a hold committed
--     before it,
--   - never touch a row under an active legal hold, a violation an
--     incident was opened from (incidents are kept indefinitely), or
--     anything an open incident's aircraft names.
--
-- legal_holds: a hold covers
--   - the violations named in violation_ids, whenever they were;
--   - with a window [window_from, window_to): the rows of that time,
--     all of them when no list is given, else those of the listed
--     track_ids and serials;
--   - without a window: the rows of the listed track_ids and serials,
--     at any time.
-- A hold is released, never deleted; its other columns never change
-- (trigger). Placing and releasing are events rows.
--
-- job_runs is the ledger of the periodic jobs (retention, archive,
-- audit and evidence verification, the USSP daily records): when each
-- run started and ended on the database clock and what it did, so a
-- restart neither skips a due run nor runs a finished one again.
--
-- audit_dropped_months is the anchor of the hash chain once the oldest
-- month of events has been dropped after its retention: the month's
-- row count, id range and last hash, so the verification of the next
-- month links its first row to the dropped month's last hash. The same
-- figures are in the audit_month_dropped events row, which is itself in
-- the chain.
--
-- ussp_daily_records: one row per (USSP, day) the daily records pull
-- tried: fetched (the bundle's hash, size and archive key) or missing
-- (why), with the attempts. A day still missing after the grace period
-- is an alarm (02 F7) and an events row, once. object_deleted_at is
-- set when the bundle was deleted after RETENTION_ARCHIVE_YEARS.

-- +goose Up
CREATE TABLE legal_holds (
    hold_id        text        PRIMARY KEY CHECK (hold_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    case_ref       text        NOT NULL CHECK (case_ref <> '' AND length(case_ref) <= 200),
    reason         text        NOT NULL CHECK (reason <> '' AND length(reason) <= 2000),
    window_from    timestamptz,
    window_to      timestamptz,
    track_ids      text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(track_ids) <= 64),
    serials        text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(serials) <= 64),
    violation_ids  text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(violation_ids) <= 64),
    placed_by      text        NOT NULL CHECK (placed_by <> ''),
    placed_at      timestamptz NOT NULL DEFAULT now(),
    released_by    text        CHECK (released_by <> ''),
    released_at    timestamptz,
    release_reason text        CHECK (length(release_reason) <= 2000),
    CHECK ((window_from IS NULL) = (window_to IS NULL)),
    CHECK (window_to IS NULL OR window_to > window_from),
    CHECK (window_from IS NOT NULL OR cardinality(track_ids) + cardinality(serials) + cardinality(violation_ids) > 0),
    CHECK ((released_at IS NULL) = (released_by IS NULL))
);

CREATE INDEX legal_holds_active ON legal_holds (placed_at) WHERE released_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION legal_holds_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'legal_holds: a hold is released, never deleted' USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF OLD.released_at IS NOT NULL THEN
    RAISE EXCEPTION 'legal_holds: hold % is already released', OLD.hold_id USING ERRCODE = 'insufficient_privilege';
  END IF;
  IF (NEW.hold_id, NEW.case_ref, NEW.reason, NEW.window_from, NEW.window_to, NEW.track_ids, NEW.serials,
      NEW.violation_ids, NEW.placed_by, NEW.placed_at)
     IS DISTINCT FROM
     (OLD.hold_id, OLD.case_ref, OLD.reason, OLD.window_from, OLD.window_to, OLD.track_ids, OLD.serials,
      OLD.violation_ids, OLD.placed_by, OLD.placed_at) THEN
    RAISE EXCEPTION 'legal_holds: only the release columns of a hold may change' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER legal_holds_guard
    BEFORE UPDATE OR DELETE ON legal_holds
    FOR EACH ROW EXECUTE FUNCTION legal_holds_guard();

CREATE TABLE job_runs (
    run_id      bigserial   PRIMARY KEY,
    job         text        NOT NULL CHECK (job ~ '^[a-z][a-z0-9_]{0,63}$'),
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    outcome     text        CHECK (outcome IN ('ok', 'failed')),
    summary     jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(summary) = 'object'),
    CHECK ((finished_at IS NULL) = (outcome IS NULL))
);

CREATE INDEX job_runs_job ON job_runs (job, started_at DESC);

CREATE TABLE audit_dropped_months (
    month       timestamptz PRIMARY KEY,
    partition   text        NOT NULL,
    rows        bigint      NOT NULL CHECK (rows >= 0),
    first_id    bigint,
    last_id     bigint,
    last_hash   text        CHECK (last_hash ~ '^[0-9a-f]{64}$'),
    dropped_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((rows = 0) = (last_hash IS NULL))
);

CREATE TABLE ussp_daily_records (
    ussp_code    text        NOT NULL CHECK (ussp_code ~ '^[A-Z0-9]{1,8}$'),
    day          timestamptz NOT NULL CHECK (day = date_trunc('day', day AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'),
    state        text        NOT NULL CHECK (state IN ('fetched', 'missing')),
    sha256       text        CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes   bigint      CHECK (size_bytes >= 0),
    archive_key  text        CHECK (length(archive_key) <= 1024),
    attempts     integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error   text        CHECK (length(last_error) <= 2000),
    alarmed      boolean     NOT NULL DEFAULT false,
    first_tried  timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    object_deleted_at timestamptz,
    PRIMARY KEY (ussp_code, day),
    CHECK ((state = 'fetched') = (sha256 IS NOT NULL AND archive_key IS NOT NULL AND size_bytes IS NOT NULL))
);

CREATE INDEX ussp_daily_records_missing ON ussp_daily_records (day) WHERE state = 'missing';

CREATE INDEX violations_closed ON violations (closed_at, violation_id) WHERE closed_at IS NOT NULL;

-- authority_violation_held: the hold rule of a violation (the header).
-- +goose StatementBegin
CREATE FUNCTION authority_violation_held(v violations) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM incidents i WHERE i.source_violation_id = v.violation_id)
      OR EXISTS (
           SELECT 1 FROM incidents i JOIN incident_aircraft a ON a.incident_id = i.incident_id
           WHERE i.status <> 'closed'
             AND (v.track_id = ANY (a.track_ids) OR (v.serial IS NOT NULL AND v.serial = a.serial)))
      OR EXISTS (
           SELECT 1 FROM legal_holds h
           WHERE h.released_at IS NULL
             AND (v.violation_id = ANY (h.violation_ids)
                  OR ((h.window_from IS NULL
                       OR (v.opened_at < h.window_to AND COALESCE(v.closed_at, 'infinity') >= h.window_from))
                      AND ((h.window_from IS NOT NULL AND cardinality(h.track_ids) + cardinality(h.serials) + cardinality(h.violation_ids) = 0)
                           OR v.track_id = ANY (h.track_ids)
                           OR (v.serial IS NOT NULL AND v.serial = ANY (h.serials))))))
$$;
-- +goose StatementEnd

-- authority_holds_gate takes legal_holds in SHARE mode for the rest of
-- the caller's transaction: a deletion that checked the holds inside it
-- cannot miss a hold placed meanwhile (placing one waits).
-- +goose StatementBegin
CREATE FUNCTION authority_holds_gate() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  LOCK TABLE legal_holds IN SHARE MODE;
END
$$;
-- +goose StatementEnd

-- authority_retention_delete_violations deletes at most max_rows closed
-- violations closed before cutoff that nothing holds, oldest first, and
-- returns their ids.
-- +goose StatementBegin
CREATE FUNCTION authority_retention_delete_violations(cutoff timestamptz, max_rows integer)
RETURNS SETOF text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF max_rows IS NULL OR max_rows < 1 OR max_rows > 10000 THEN
    RAISE EXCEPTION 'retention: batch of % rows is outside 1 to 10000', max_rows USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF cutoff IS NULL OR cutoff > now() - interval '30 days' THEN
    RAISE EXCEPTION 'retention: cutoff % is inside the 30-day floor (2021/664 Art. 15(1)(g))', cutoff
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  LOCK TABLE legal_holds IN SHARE MODE;
  RETURN QUERY
  WITH victims AS (
    SELECT v.violation_id FROM violations v
    WHERE v.closed_at IS NOT NULL AND v.closed_at < cutoff AND NOT authority_violation_held(v)
    ORDER BY v.closed_at, v.violation_id
    LIMIT max_rows
    FOR UPDATE OF v SKIP LOCKED
  )
  DELETE FROM violations d USING victims WHERE d.violation_id = victims.violation_id
  RETURNING d.violation_id;
END
$$;
-- +goose StatementEnd

-- authority_retention_drop_events_month drops the oldest month of
-- events when it ended before cutoff and nothing holds it, after
-- recording its anchor in audit_dropped_months, and returns
-- {partition, held, rows, first_id, last_id, last_hash}. A held month
-- is returned with held true and kept. Months are dropped oldest first,
-- one per call, so the anchor is always the newest dropped month.
-- +goose StatementBegin
CREATE FUNCTION authority_retention_drop_events_month(month_start timestamptz, cutoff timestamptz)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  m_start timestamptz := date_trunc('month', month_start AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
  m_end   timestamptz := (date_trunc('month', month_start AT TIME ZONE 'UTC') + interval '1 month') AT TIME ZONE 'UTC';
  part    text := 'events_' || to_char(month_start AT TIME ZONE 'UTC', 'YYYY_MM');
  oldest  text;
  n       bigint;
  lo      bigint;
  hi      bigint;
  h       text;
  is_held boolean;
BEGIN
  IF m_start <> month_start THEN
    RAISE EXCEPTION 'retention: % is not the first instant of a UTC month', month_start USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF cutoff IS NULL OR cutoff > now() - interval '365 days' THEN
    RAISE EXCEPTION 'retention: cutoff % is inside the audit log''s one-year floor', cutoff USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF m_end > cutoff THEN
    RAISE EXCEPTION 'retention: % ends after the cutoff %', part, cutoff USING ERRCODE = 'invalid_parameter_value';
  END IF;
  SELECT min(c.relname) INTO oldest
  FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
  WHERE i.inhparent = 'events'::regclass;
  IF oldest IS DISTINCT FROM part THEN
    RAISE EXCEPTION 'retention: % is not the oldest month of events (%)', part, oldest USING ERRCODE = 'invalid_parameter_value';
  END IF;
  LOCK TABLE legal_holds IN SHARE MODE;
  EXECUTE format(
    'SELECT EXISTS (SELECT 1 FROM legal_holds h WHERE h.released_at IS NULL AND h.window_from < %L AND h.window_to > %L)
         OR EXISTS (SELECT 1 FROM %I e WHERE e.entity_id IN (
               SELECT unnest(h.violation_ids) FROM legal_holds h WHERE h.released_at IS NULL
               UNION ALL SELECT i.incident_id FROM incidents i WHERE i.status <> ''closed''))',
    m_end, m_start, part) INTO is_held;
  IF is_held THEN
    RETURN jsonb_build_object('partition', part, 'held', true);
  END IF;
  EXECUTE format('SELECT count(*), min(id), max(id) FROM %I', part) INTO n, lo, hi;
  IF n > 0 THEN
    EXECUTE format('SELECT hash FROM %I WHERE id = $1', part) INTO h USING hi;
  END IF;
  INSERT INTO audit_dropped_months (month, partition, rows, first_id, last_id, last_hash)
  VALUES (m_start, part, n, lo, hi, h);
  EXECUTE format('ALTER TABLE events DETACH PARTITION %I', part);
  EXECUTE format('DROP TABLE %I', part);
  RETURN jsonb_build_object('partition', part, 'held', false, 'rows', n, 'first_id', lo, 'last_id', hi, 'last_hash', h);
END
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION authority_violation_held(violations) FROM PUBLIC;
REVOKE ALL ON FUNCTION authority_holds_gate() FROM PUBLIC;
REVOKE ALL ON FUNCTION authority_retention_delete_violations(timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION authority_retention_drop_events_month(timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION authority_violation_held(violations) TO authority_app;
GRANT EXECUTE ON FUNCTION authority_holds_gate() TO authority_app;
GRANT EXECUTE ON FUNCTION authority_retention_delete_violations(timestamptz, integer) TO authority_app;
GRANT EXECUTE ON FUNCTION authority_retention_drop_events_month(timestamptz, timestamptz) TO authority_app;

GRANT SELECT, INSERT ON legal_holds TO authority_app;
GRANT UPDATE (released_by, released_at, release_reason) ON legal_holds TO authority_app;
GRANT SELECT, INSERT, UPDATE ON job_runs TO authority_app;
GRANT USAGE ON SEQUENCE job_runs_run_id_seq TO authority_app;
GRANT SELECT ON audit_dropped_months TO authority_app;
GRANT SELECT, INSERT, UPDATE ON ussp_daily_records TO authority_app;

-- +goose Down
DROP FUNCTION IF EXISTS authority_retention_drop_events_month(timestamptz, timestamptz);
DROP FUNCTION IF EXISTS authority_retention_delete_violations(timestamptz, integer);
DROP FUNCTION IF EXISTS authority_holds_gate();
DROP FUNCTION IF EXISTS authority_violation_held(violations);
DROP INDEX IF EXISTS violations_closed;
DROP TABLE IF EXISTS ussp_daily_records;
DROP TABLE IF EXISTS audit_dropped_months;
DROP TABLE IF EXISTS job_runs;
DROP TABLE IF EXISTS legal_holds;
DROP FUNCTION IF EXISTS legal_holds_guard();
