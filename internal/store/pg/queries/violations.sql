-- WP-12: violations (migration 00015_violations). Written by api's
-- consumer of alrt.v1 and its review endpoint (internal/violations).

-- name: GetViolationForUpdate :one
SELECT violation_id, kind, severity, alert_key, track_id, serial, operator_reg, registry_uas_id, zone_id, zone_version,
       zone_type, detector_state, opened_at, closed_at, clear_reason, last_captured_at, policy_version, peak_name,
       peak_value, detail, clearing_detail, terrain_source, in_uspace, evidence_trust, evidence_refs, evidence_track_ids,
       evidence_excerpt, excerpt_samples, excerpt_truncated, cell5, status, reviewed_by, reviewed_at, review_note,
       incident_requested, last_message_at, created_at
FROM violations WHERE violation_id = sqlc.arg(violation_id)
FOR UPDATE;

-- name: GetViolation :one
SELECT violation_id, kind, severity, alert_key, track_id, serial, operator_reg, registry_uas_id, zone_id, zone_version,
       zone_type, detector_state, opened_at, closed_at, clear_reason, last_captured_at, policy_version, peak_name,
       peak_value, detail, clearing_detail, terrain_source, in_uspace, evidence_trust, evidence_refs, evidence_track_ids,
       evidence_excerpt, excerpt_samples, excerpt_truncated, cell5, status, reviewed_by, reviewed_at, review_note,
       incident_requested, last_message_at, created_at
FROM violations WHERE violation_id = sqlc.arg(violation_id);

-- name: InsertViolation :exec
-- first_position is the first sample's position, for the bbox filter;
-- NULL without a sample.
INSERT INTO violations (violation_id, kind, severity, alert_key, track_id, serial, operator_reg, registry_uas_id,
    zone_id, zone_version, zone_type, detector_state, opened_at, closed_at, clear_reason, last_captured_at,
    policy_version, peak_name, peak_value, detail, clearing_detail, terrain_source, in_uspace, evidence_trust,
    evidence_refs, evidence_track_ids, evidence_excerpt, excerpt_samples, excerpt_truncated, first_position, cell5,
    last_message_at)
VALUES (sqlc.arg(violation_id), sqlc.arg(kind), sqlc.arg(severity), sqlc.arg(alert_key), sqlc.arg(track_id),
    sqlc.narg(serial), sqlc.narg(operator_reg), sqlc.narg(registry_uas_id), sqlc.narg(zone_id), sqlc.narg(zone_version),
    sqlc.narg(zone_type), sqlc.arg(detector_state), sqlc.arg(opened_at), sqlc.narg(closed_at), sqlc.narg(clear_reason),
    sqlc.arg(last_captured_at), sqlc.arg(policy_version), sqlc.narg(peak_name), sqlc.narg(peak_value), sqlc.arg(detail),
    sqlc.narg(clearing_detail), sqlc.narg(terrain_source), sqlc.arg(in_uspace), sqlc.arg(evidence_trust),
    sqlc.arg(evidence_refs), sqlc.arg(evidence_track_ids)::text[], sqlc.arg(evidence_excerpt), sqlc.arg(excerpt_samples),
    sqlc.arg(excerpt_truncated),
    CASE WHEN sqlc.narg(first_lon_deg)::double precision IS NULL THEN NULL
         ELSE ST_SetSRID(ST_MakePoint(sqlc.narg(first_lon_deg)::double precision, sqlc.narg(first_lat_deg)::double precision), 4326) END,
    sqlc.arg(cell5), now());

-- name: UpdateViolation :exec
-- A republication or a severity change (detector_state updated) or the
-- clear (cleared, with closed_at and clear_reason); last_message_at is
-- the database's clock.
UPDATE violations
SET severity = sqlc.arg(severity), detector_state = sqlc.arg(detector_state), closed_at = sqlc.narg(closed_at),
    clear_reason = sqlc.narg(clear_reason), last_captured_at = sqlc.arg(last_captured_at),
    policy_version = sqlc.arg(policy_version), peak_name = sqlc.narg(peak_name), peak_value = sqlc.narg(peak_value),
    detail = sqlc.arg(detail), clearing_detail = sqlc.narg(clearing_detail), in_uspace = sqlc.arg(in_uspace),
    evidence_excerpt = sqlc.arg(evidence_excerpt), excerpt_samples = sqlc.arg(excerpt_samples),
    excerpt_truncated = sqlc.arg(excerpt_truncated), last_message_at = now()
WHERE violation_id = sqlc.arg(violation_id);

-- name: CloseSilentViolations :many
-- Every open violation no message has touched for older_than_s seconds
-- of the database's clock is closed detector_silent (bounded by lim).
UPDATE violations
SET detector_state = 'cleared', closed_at = now(), clear_reason = 'detector_silent', last_message_at = now()
WHERE violation_id IN (
    SELECT v.violation_id FROM violations v
    WHERE v.closed_at IS NULL AND v.last_message_at < now() - make_interval(secs => sqlc.arg(older_than_s)::double precision)
    ORDER BY v.last_message_at
    LIMIT sqlc.arg(lim)
    FOR UPDATE SKIP LOCKED)
RETURNING violation_id, kind, track_id, closed_at;

-- name: ReviewViolation :exec
UPDATE violations
SET status = sqlc.arg(status), reviewed_by = sqlc.arg(reviewed_by), reviewed_at = now(), review_note = sqlc.narg(review_note),
    incident_requested = incident_requested OR sqlc.arg(incident_requested)
WHERE violation_id = sqlc.arg(violation_id);

-- name: ListViolations :many
-- One page, newest first, keyed by (opened_at, violation_id) after the
-- cursor; the bbox is on the first position (PostGIS, SRID 4326).
SELECT violation_id, kind, severity, track_id, serial, operator_reg, zone_id, zone_type, detector_state, opened_at,
       closed_at, clear_reason, last_captured_at, policy_version, peak_name, peak_value, in_uspace, evidence_trust,
       excerpt_samples, cell5, status, reviewed_at
FROM violations
WHERE (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
  AND (sqlc.narg(kind)::text IS NULL OR kind = sqlc.narg(kind)::text)
  AND (sqlc.narg(from_ts)::timestamptz IS NULL OR opened_at >= sqlc.narg(from_ts)::timestamptz)
  AND (sqlc.narg(to_ts)::timestamptz IS NULL OR opened_at < sqlc.narg(to_ts)::timestamptz)
  AND (sqlc.narg(min_lon)::double precision IS NULL OR ST_Intersects(first_position,
       ST_MakeEnvelope(sqlc.narg(min_lon)::double precision, sqlc.narg(min_lat)::double precision,
                       sqlc.narg(max_lon)::double precision, sqlc.narg(max_lat)::double precision, 4326)))
  AND (sqlc.narg(cursor_opened)::timestamptz IS NULL
       OR (opened_at, violation_id) < (sqlc.narg(cursor_opened)::timestamptz, sqlc.narg(cursor_id)::text))
ORDER BY opened_at DESC, violation_id DESC
LIMIT sqlc.arg(lim);
