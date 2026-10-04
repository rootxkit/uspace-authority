-- WP-18: the occurrences schema (migration 00020_occurrences), worked by
-- the authority_occurrences role through internal/occurrences only.
-- Nothing here reads or names a table outside the schema: the audit
-- events row of each write is recorded through internal/audit on the
-- same transaction.

-- name: Now :one
-- The database clock of the transaction: received_at, the skew check and
-- every state change read the same instant.
SELECT now()::timestamptz AS now;

-- name: InsertReport :one
-- received_at is the database clock; a second delivery of the same
-- (reporter_org, report_ref) inserts nothing and returns no row.
INSERT INTO occurrences.occurrence_reports (occurrence_id, reporter_org, report_ref, channel, origin, reporter_person_enc,
    reporter_key_id, occurred_at, became_aware_at, reported_at, report_deadline_s, category, aircraft, manned, intent_refs,
    min_separation, narrative, evidence_urls, content_hash)
VALUES (sqlc.arg(occurrence_id), sqlc.arg(reporter_org), sqlc.arg(report_ref), sqlc.arg(channel), sqlc.arg(origin),
    sqlc.narg(reporter_person_enc), sqlc.narg(reporter_key_id), sqlc.arg(occurred_at), sqlc.arg(became_aware_at),
    sqlc.narg(reported_at), sqlc.arg(report_deadline_s), sqlc.arg(category), sqlc.arg(aircraft), sqlc.arg(manned),
    sqlc.arg(intent_refs)::text[], sqlc.narg(min_separation), sqlc.arg(narrative), sqlc.arg(evidence_urls)::text[],
    sqlc.arg(content_hash))
ON CONFLICT (reporter_org, report_ref) DO NOTHING
RETURNING *;

-- name: ReportByKey :one
SELECT * FROM occurrences.occurrence_reports
WHERE reporter_org = sqlc.arg(reporter_org) AND report_ref = sqlc.arg(report_ref);

-- name: GetReport :one
SELECT * FROM occurrences.occurrence_reports WHERE occurrence_id = sqlc.arg(occurrence_id);

-- name: GetReportForUpdate :one
SELECT * FROM occurrences.occurrence_reports WHERE occurrence_id = sqlc.arg(occurrence_id) FOR UPDATE;

-- name: ListReports :many
-- One page, newest received first, keyed by (received_at, occurrence_id)
-- after the cursor.
SELECT * FROM occurrences.occurrence_reports
WHERE (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(category)::text IS NULL OR category = sqlc.narg(category)::text)
  AND (sqlc.narg(channel)::text IS NULL OR channel = sqlc.narg(channel)::text)
  AND (sqlc.narg(received_from)::timestamptz IS NULL OR received_at >= sqlc.narg(received_from)::timestamptz)
  AND (sqlc.narg(received_to)::timestamptz IS NULL OR received_at < sqlc.narg(received_to)::timestamptz)
  AND (sqlc.narg(cursor_received)::timestamptz IS NULL
       OR (received_at, occurrence_id) < (sqlc.narg(cursor_received)::timestamptz, sqlc.narg(cursor_id)::text))
ORDER BY received_at DESC, occurrence_id DESC
LIMIT sqlc.arg(lim);

-- name: ClassifyReport :one
-- A received report becomes classified; a classified or analysed one
-- keeps its state with the new class.
UPDATE occurrences.occurrence_reports
SET risk_classification = sqlc.arg(risk_classification), classified_at = now(), classified_by = sqlc.arg(actor),
    state = CASE WHEN state = 'received' THEN 'classified' ELSE state END,
    updated_at = now(), updated_by = sqlc.arg(actor)
WHERE occurrence_id = sqlc.arg(occurrence_id)
RETURNING *;

-- name: UpdateAnalysis :one
-- closed_at is the database clock when the state becomes closed.
UPDATE occurrences.occurrence_reports
SET analysis = sqlc.arg(analysis), follow_up = sqlc.arg(follow_up), state = sqlc.arg(state),
    closed_at = CASE WHEN sqlc.arg(state) = 'closed' THEN now() ELSE NULL END,
    updated_at = now(), updated_by = sqlc.arg(actor)
WHERE occurrence_id = sqlc.arg(occurrence_id)
RETURNING *;

-- name: ReportsReceived :many
-- The reports of an export window, oldest first.
SELECT * FROM occurrences.occurrence_reports
WHERE received_at >= sqlc.arg(received_from) AND received_at < sqlc.arg(received_to)
ORDER BY received_at, occurrence_id
LIMIT sqlc.arg(lim);

-- name: InsertExport :one
-- created_at is the transaction's database clock (Now), the instant the
-- sealed document names.
INSERT INTO occurrences.deidentified_exports (export_id, created_at, created_by, format, content_hash, size_bytes, record_count,
    window_from, window_to)
VALUES (sqlc.arg(export_id), sqlc.arg(created_at), sqlc.arg(created_by), sqlc.arg(format), sqlc.arg(content_hash), sqlc.arg(size_bytes),
    sqlc.arg(record_count), sqlc.arg(window_from), sqlc.arg(window_to))
RETURNING *;
