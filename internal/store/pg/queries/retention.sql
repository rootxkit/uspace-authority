-- WP-27: retention, legal holds, the job ledger, the hash-chain anchor
-- and the USSP daily records (migration 00024_retention).

-- name: InsertLegalHold :one
INSERT INTO legal_holds (hold_id, case_ref, reason, window_from, window_to, track_ids, serials, violation_ids, placed_by)
VALUES (sqlc.arg(hold_id), sqlc.arg(case_ref), sqlc.arg(reason), sqlc.narg(window_from), sqlc.narg(window_to),
        sqlc.arg(track_ids)::text[], sqlc.arg(serials)::text[], sqlc.arg(violation_ids)::text[], sqlc.arg(placed_by))
RETURNING *;

-- name: GetLegalHold :one
SELECT * FROM legal_holds WHERE hold_id = sqlc.arg(hold_id);

-- name: ListLegalHolds :many
-- Newest first; active only unless include_released.
SELECT * FROM legal_holds
WHERE (sqlc.arg(include_released)::boolean OR released_at IS NULL)
ORDER BY placed_at DESC, hold_id DESC
LIMIT sqlc.arg(max_rows);

-- name: ReleaseLegalHold :one
UPDATE legal_holds SET released_by = sqlc.arg(released_by), released_at = now(), release_reason = sqlc.arg(release_reason)
WHERE hold_id = sqlc.arg(hold_id) AND released_at IS NULL
RETURNING *;

-- name: ActiveLegalHolds :many
-- Every active hold, for the telemetry and archive checks; one more
-- than max_rows tells the caller the bound was reached (it then holds
-- everything: fail closed).
SELECT * FROM legal_holds WHERE released_at IS NULL ORDER BY placed_at, hold_id LIMIT sqlc.arg(max_rows);

-- name: CountActiveLegalHolds :one
SELECT count(*)::bigint AS n FROM legal_holds WHERE released_at IS NULL;

-- name: HoldsGate :exec
-- legal_holds in SHARE mode until the transaction ends.
SELECT authority_holds_gate();

-- name: HeldViolationRefs :many
-- The aircraft and times of the violations an active hold names, so
-- their telemetry is held with them.
SELECT v.violation_id, v.track_id, v.serial, v.opened_at, v.closed_at
FROM violations v
WHERE v.violation_id IN (SELECT unnest(h.violation_ids) FROM legal_holds h WHERE h.released_at IS NULL)
ORDER BY v.violation_id
LIMIT sqlc.arg(max_rows);

-- name: OpenIncidentAircraft :many
-- The aircraft of every incident not closed, with when it occurred:
-- their telemetry around that time is held.
SELECT i.incident_id, i.occurred_at, a.serial, a.track_ids
FROM incidents i JOIN incident_aircraft a ON a.incident_id = i.incident_id
WHERE i.status <> 'closed'
ORDER BY i.incident_id, a.id
LIMIT sqlc.arg(max_rows);

-- name: IncidentAircraftAround :many
-- The aircraft of the incidents (any status) that occurred in
-- [from_ts, to_ts): their remote pilot positions are kept in the
-- archive of that time (06 §5).
SELECT i.incident_id, a.serial, a.track_ids
FROM incidents i JOIN incident_aircraft a ON a.incident_id = i.incident_id
WHERE i.occurred_at >= sqlc.arg(from_ts) AND i.occurred_at < sqlc.arg(to_ts)
ORDER BY i.incident_id, a.id
LIMIT sqlc.arg(max_rows);

-- name: OpenIncidentsAround :one
-- Whether an incident not closed occurred in [from_ts, to_ts) (an
-- archived object of that time is then kept).
SELECT EXISTS (
    SELECT 1 FROM incidents WHERE status <> 'closed' AND occurred_at >= sqlc.arg(from_ts) AND occurred_at < sqlc.arg(to_ts)
)::boolean AS held;

-- name: DeleteExpiredViolations :many
-- One batch: closed violations older than the period, held ones never
-- (authority_retention_delete_violations).
SELECT authority_retention_delete_violations(now() - make_interval(years => sqlc.arg(years)::integer),
                                             sqlc.arg(max_rows)::integer)::text AS violation_id;

-- name: OldestEventsPartition :one
SELECT c.relname::text AS partition
FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
WHERE i.inhparent = 'events'::regclass
ORDER BY c.relname
LIMIT 1;

-- name: AuditCutoff :one
SELECT (now() - make_interval(years => sqlc.arg(years)::integer))::timestamptz AS cutoff;

-- name: DropEventsMonth :one
-- {partition, held, rows, first_id, last_id, last_hash} (jsonb).
SELECT authority_retention_drop_events_month(sqlc.arg(month_start)::timestamptz,
                                             now() - make_interval(years => sqlc.arg(years)::integer))::jsonb AS result;

-- name: DroppedMonthAnchor :one
-- The hash the oldest kept month's first row links to: the last hash
-- of the newest non-empty month dropped before it.
SELECT month, last_hash::text AS last_hash FROM audit_dropped_months
WHERE month < sqlc.arg(month)::timestamptz AND last_hash IS NOT NULL
ORDER BY month DESC LIMIT 1;

-- name: ListDroppedMonths :many
SELECT * FROM audit_dropped_months ORDER BY month DESC LIMIT sqlc.arg(max_rows);

-- name: EventsMonths :many
-- Every month that holds events, oldest first (the partitions).
SELECT c.relname::text AS partition
FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
WHERE i.inhparent = 'events'::regclass
ORDER BY c.relname
LIMIT sqlc.arg(max_rows);

-- name: EventRecorded :one
-- Whether an events row of this type names the entity already: the
-- retention steps recorded after a commit in the other database are
-- recorded once, also when a restart repeats them.
SELECT EXISTS (
    SELECT 1 FROM events WHERE entity_type = sqlc.arg(entity_type) AND entity_id = sqlc.arg(entity_id)
                           AND event_type = sqlc.arg(event_type)
)::boolean AS recorded;

-- name: StartJobRun :one
INSERT INTO job_runs (job) VALUES (sqlc.arg(job)) RETURNING run_id, started_at;

-- name: FinishJobRun :exec
UPDATE job_runs SET finished_at = now(), outcome = sqlc.arg(outcome), summary = sqlc.arg(summary)
WHERE run_id = sqlc.arg(run_id) AND finished_at IS NULL;

-- name: JobDue :one
-- Whether job is due on the database clock: no successful run started
-- within every_s (or, monthly, in this UTC calendar month), and no
-- failed or unfinished attempt started within retry_s.
SELECT (NOT EXISTS (
          SELECT 1 FROM job_runs r WHERE r.job = sqlc.arg(job) AND r.outcome = 'ok'
            AND CASE WHEN sqlc.arg(monthly)::boolean
                     THEN date_trunc('month', r.started_at AT TIME ZONE 'UTC') = date_trunc('month', now() AT TIME ZONE 'UTC')
                     ELSE r.started_at > now() - make_interval(secs => sqlc.arg(every_s)::double precision) END)
        AND NOT EXISTS (
          SELECT 1 FROM job_runs r WHERE r.job = sqlc.arg(job) AND r.outcome IS DISTINCT FROM 'ok'
            AND r.started_at > now() - make_interval(secs => sqlc.arg(retry_s)::double precision)))::boolean AS due;

-- name: LatestJobRuns :many
-- Each job's newest run (ok, failed or unfinished).
SELECT DISTINCT ON (job) run_id, job, started_at, finished_at, outcome, summary
FROM job_runs ORDER BY job, started_at DESC;

-- name: DBClock :one
SELECT now()::timestamptz AS db_now;

-- name: USSPDay :one
SELECT * FROM ussp_daily_records WHERE ussp_code = sqlc.arg(ussp_code) AND day = sqlc.arg(day);

-- name: RecordUSSPDayFetched :exec
INSERT INTO ussp_daily_records (ussp_code, day, state, sha256, size_bytes, archive_key, attempts)
VALUES (sqlc.arg(ussp_code), sqlc.arg(day), 'fetched', sqlc.arg(sha256), sqlc.arg(size_bytes), sqlc.arg(archive_key), 1)
ON CONFLICT (ussp_code, day) DO UPDATE
SET state = 'fetched', sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes, archive_key = EXCLUDED.archive_key,
    attempts = ussp_daily_records.attempts + 1, last_error = NULL, updated_at = now();

-- name: RecordUSSPDayMissing :one
INSERT INTO ussp_daily_records (ussp_code, day, state, attempts, last_error)
VALUES (sqlc.arg(ussp_code), sqlc.arg(day), 'missing', 1, sqlc.arg(last_error))
ON CONFLICT (ussp_code, day) DO UPDATE
SET attempts = ussp_daily_records.attempts + 1, last_error = EXCLUDED.last_error, updated_at = now()
WHERE ussp_daily_records.state = 'missing'
RETURNING *;

-- name: MarkUSSPDayAlarmed :exec
UPDATE ussp_daily_records SET alarmed = true, updated_at = now()
WHERE ussp_code = sqlc.arg(ussp_code) AND day = sqlc.arg(day) AND state = 'missing';

-- name: MissingUSSPDays :many
-- The days still missing that raised the alarm, newest first.
SELECT * FROM ussp_daily_records WHERE state = 'missing' AND alarmed ORDER BY day DESC, ussp_code LIMIT sqlc.arg(max_rows);

-- name: ExpiredUSSPDays :many
-- Fetched bundles past the archive period, oldest first.
SELECT * FROM ussp_daily_records
WHERE state = 'fetched' AND object_deleted_at IS NULL AND day < now() - make_interval(years => sqlc.arg(years)::integer)
ORDER BY day, ussp_code LIMIT sqlc.arg(max_rows);

-- name: MarkUSSPDayDeleted :exec
UPDATE ussp_daily_records SET object_deleted_at = now(), updated_at = now()
WHERE ussp_code = sqlc.arg(ussp_code) AND day = sqlc.arg(day) AND object_deleted_at IS NULL;

-- name: OperatingUSSPs :many
-- The USSPs whose daily records are pulled: on the USSP list (02 F1),
-- with a base URL.
SELECT code, client_id, base_url, operations_started_at FROM certificates
WHERE holder = 'ussp' AND status IN ('operating', 'limited') AND operations = 'operating'
  AND issued_at <= now() AND valid_until > now() AND base_url <> ''
ORDER BY code
LIMIT sqlc.arg(max_rows);

-- name: PacksToReverify :many
-- Every evidence pack in creation order after a cursor, for the
-- monthly re-verification.
SELECT incident_id, pack_id, created_at FROM evidence_packs
WHERE (created_at, pack_id) > (sqlc.arg(after_created)::timestamptz, sqlc.arg(after_pack)::text)
ORDER BY created_at, pack_id
LIMIT sqlc.arg(max_rows);

-- name: LatestChainVerifications :many
-- Each month's newest audit_chain_verified row: whether it held and
-- when, so a broken month stays an alarm across a restart.
SELECT DISTINCT ON (entity_id) entity_id::text AS month, ts, COALESCE((payload->>'intact')::boolean, false)::boolean AS intact,
       COALESCE(payload->'broken'->>'reason', '')::text AS reason
FROM events
WHERE entity_type = 'events' AND event_type = 'audit_chain_verified' AND entity_id IS NOT NULL
ORDER BY entity_id, id DESC
LIMIT sqlc.arg(max_rows);
