-- WP-17: incidents and evidence packs (migration 00017_incidents),
-- written by api (internal/incidents). Every write is in a transaction
-- with its events row.

-- name: InsertIncident :one
INSERT INTO incidents (incident_id, kind, occurred_at, opened_from, source_violation_id, notice_ref, intent_refs, narrative,
    severity, opened_by)
VALUES (sqlc.arg(incident_id), sqlc.arg(kind), sqlc.arg(occurred_at), sqlc.arg(opened_from), sqlc.narg(source_violation_id),
    sqlc.narg(notice_ref), sqlc.arg(intent_refs)::text[], sqlc.arg(narrative), sqlc.arg(severity), sqlc.arg(opened_by))
RETURNING created_at;

-- name: GetIncident :one
SELECT incident_id, kind, occurred_at, opened_from, source_violation_id, notice_ref, intent_refs, narrative, severity, status,
       assignee, closed_at, opened_by, created_at, updated_at
FROM incidents WHERE incident_id = sqlc.arg(incident_id);

-- name: GetIncidentForUpdate :one
SELECT incident_id, kind, occurred_at, opened_from, source_violation_id, notice_ref, intent_refs, narrative, severity, status,
       assignee, closed_at, opened_by, created_at, updated_at
FROM incidents WHERE incident_id = sqlc.arg(incident_id)
FOR UPDATE;

-- name: IncidentForViolation :one
SELECT incident_id FROM incidents WHERE source_violation_id = sqlc.arg(violation_id);

-- name: UpdateIncident :one
-- closed_at is the database's clock when the status becomes closed and
-- is cleared when a closed incident is reopened.
UPDATE incidents
SET narrative = sqlc.arg(narrative), severity = sqlc.arg(severity), status = sqlc.arg(status), assignee = sqlc.narg(assignee),
    intent_refs = sqlc.arg(intent_refs)::text[],
    closed_at = CASE WHEN sqlc.arg(status) = 'closed' THEN coalesce(closed_at, now()) ELSE NULL END,
    updated_at = now()
WHERE incident_id = sqlc.arg(incident_id)
RETURNING updated_at;

-- name: ListIncidents :many
-- One page, newest first, keyed by (created_at, incident_id) after the
-- cursor.
SELECT incident_id, kind, occurred_at, opened_from, source_violation_id, severity, status, assignee, closed_at, created_at,
       updated_at
FROM incidents
WHERE (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
  AND (sqlc.narg(kind)::text IS NULL OR kind = sqlc.narg(kind)::text)
  AND (sqlc.narg(violation_id)::text IS NULL OR source_violation_id = sqlc.narg(violation_id)::text)
  AND (sqlc.narg(cursor_created)::timestamptz IS NULL
       OR (created_at, incident_id) < (sqlc.narg(cursor_created)::timestamptz, sqlc.narg(cursor_id)::text))
ORDER BY created_at DESC, incident_id DESC
LIMIT sqlc.arg(lim);

-- name: InsertIncidentAircraft :exec
INSERT INTO incident_aircraft (incident_id, serial, operator_reg, registry_uas_id, track_ids, identification, added_by)
VALUES (sqlc.arg(incident_id), sqlc.narg(serial), sqlc.narg(operator_reg), sqlc.narg(registry_uas_id),
    sqlc.arg(track_ids)::text[], sqlc.arg(identification), sqlc.arg(added_by));

-- name: ListIncidentAircraft :many
SELECT id, serial, operator_reg, registry_uas_id, track_ids, identification, added_by, added_at
FROM incident_aircraft WHERE incident_id = sqlc.arg(incident_id) ORDER BY id;

-- name: CountIncidentAircraft :one
SELECT count(*)::integer FROM incident_aircraft WHERE incident_id = sqlc.arg(incident_id);

-- name: InsertIncidentNote :one
INSERT INTO incident_notes (incident_id, author, body)
VALUES (sqlc.arg(incident_id), sqlc.arg(author), sqlc.arg(body))
RETURNING id, created_at;

-- name: ListIncidentNotes :many
SELECT id, author, body, created_at FROM incident_notes WHERE incident_id = sqlc.arg(incident_id) ORDER BY id;

-- name: CountIncidentNotes :one
SELECT count(*)::integer FROM incident_notes WHERE incident_id = sqlc.arg(incident_id);

-- name: InsertEvidencePack :exec
INSERT INTO evidence_packs (pack_id, incident_id, kind, window_from, window_to, content_hash, size_bytes, signature,
    signature_kid, seal_statement, manifest, storage_ref, sealed_key_id, created_by, purpose, case_ref, created_at)
VALUES (sqlc.arg(pack_id), sqlc.arg(incident_id), sqlc.arg(kind), sqlc.arg(window_from), sqlc.arg(window_to),
    sqlc.arg(content_hash), sqlc.arg(size_bytes), sqlc.narg(signature), sqlc.narg(signature_kid), sqlc.arg(seal_statement),
    sqlc.arg(manifest), sqlc.arg(storage_ref), sqlc.narg(sealed_key_id), sqlc.arg(created_by), sqlc.arg(purpose),
    sqlc.narg(case_ref), sqlc.arg(created_at));

-- name: GetEvidencePack :one
SELECT pack_id, incident_id, kind, window_from, window_to, content_hash, size_bytes, signature, signature_kid,
       seal_statement, manifest, storage_ref, sealed_key_id, created_by, purpose, case_ref, created_at
FROM evidence_packs WHERE incident_id = sqlc.arg(incident_id) AND pack_id = sqlc.arg(pack_id);

-- name: ListEvidencePacks :many
SELECT pack_id, kind, window_from, window_to, content_hash, size_bytes, signature_kid, created_by, created_at
FROM evidence_packs WHERE incident_id = sqlc.arg(incident_id) ORDER BY created_at DESC, pack_id DESC LIMIT 200;

-- name: RequestedIncidentsWithoutIncident :many
-- Violations an inspector escalated before WP-17 opened incidents from
-- them (incident_requested, no incident yet), oldest first.
SELECT v.violation_id FROM violations v
WHERE v.status = 'escalated' AND v.incident_requested
  AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.source_violation_id = v.violation_id)
ORDER BY v.reviewed_at NULLS FIRST, v.violation_id
LIMIT sqlc.arg(lim);

-- The evidence pack's relational sources. Each is read on its own
-- (never in one transaction with another), so one unreadable source is
-- reported unavailable in the manifest without hiding the others.

-- name: PackViolations :many
-- The violations of an evidence pack: the incident's own, and every one
-- of its aircraft's tracks or serials opened before the window's end and
-- not closed before its start; bounded by lim (one more than the cap so
-- the caller can refuse rather than thin).
SELECT violation_id, kind, severity, alert_key, track_id, serial, operator_reg, registry_uas_id, zone_id, zone_version,
       zone_type, detector_state, opened_at, closed_at, clear_reason, last_captured_at, policy_version, peak_name,
       peak_value, detail, clearing_detail, terrain_source, in_uspace, evidence_trust, evidence_refs, evidence_track_ids,
       evidence_excerpt, excerpt_samples, excerpt_truncated, cell5, status, reviewed_by, reviewed_at, review_note,
       incident_requested, created_at
FROM violations
WHERE violation_id = sqlc.narg(source_violation_id)::text
   OR ((track_id = ANY (sqlc.arg(track_ids)::text[]) OR evidence_track_ids && sqlc.arg(track_ids)::text[]
        OR serial = ANY (sqlc.arg(serials)::text[]))
       AND opened_at < sqlc.arg(window_to) AND (closed_at IS NULL OR closed_at >= sqlc.arg(window_from)))
ORDER BY opened_at, violation_id
LIMIT sqlc.arg(lim);

-- name: PackZoneVersions :many
-- Every version of the zones an evidence pack names (country/identifier,
-- as violation/v1 carries them), verbatim as authored; the caller keeps
-- the versions it names. Bounded by lim.
SELECT dataset, country, identifier, zone_version, state, type, feature, valid_from, valid_to, published_version,
       published_at, approved_by, approved_at
FROM geo_zones
WHERE country || '/' || identifier = ANY (sqlc.arg(zone_ids)::text[])
ORDER BY country, identifier, zone_version
LIMIT sqlc.arg(lim);

-- name: PackZonesInForce :many
-- The published zone versions in force at any time of the window whose
-- geometry meets the box of the evidence (PostGIS, SRID 4326); bounded
-- by lim.
SELECT dataset, country, identifier, zone_version, state, type, feature, valid_from, valid_to, published_version,
       published_at, approved_by, approved_at
FROM geo_zones
WHERE published_version IS NOT NULL AND valid_from < sqlc.arg(window_to) AND valid_to > sqlc.arg(window_from)
  AND ST_Intersects(coalesce(geom, ST_Buffer(center::geography, radius_m)::geometry),
                    ST_MakeEnvelope(sqlc.arg(min_lon)::double precision, sqlc.arg(min_lat)::double precision,
                                    sqlc.arg(max_lon)::double precision, sqlc.arg(max_lat)::double precision, 4326))
ORDER BY country, identifier, zone_version
LIMIT sqlc.arg(lim);

-- name: PackPolicies :many
-- The policy versions an evidence pack names, every column as stored.
SELECT version, to_jsonb(p) AS policy FROM authority_policy p
WHERE version = ANY (sqlc.arg(versions)::bigint[]) ORDER BY version;

-- name: PackActivePolicy :one
SELECT version, max_gap_s, to_jsonb(p) AS policy FROM authority_policy p WHERE active;

-- name: PackEvents :many
-- The events lines of an evidence pack: every row about the incident,
-- its packs and its violations, oldest first, bounded by lim.
SELECT id, ts, actor_type, actor_id, realm, purpose, entity_type, entity_id, event_type, payload, prev_hash, hash
FROM events
WHERE (entity_type = 'incident' AND entity_id = sqlc.arg(incident_id))
   OR (entity_type = 'violation' AND entity_id = ANY (sqlc.arg(violation_ids)::text[]))
ORDER BY id
LIMIT sqlc.arg(lim);

-- name: PackUSSPList :one
-- The USSP list as the CIS last served it (WP-6): where a USSP's
-- national API (its base_url) is.
SELECT payload, version, fetched_at FROM cis_cache WHERE dataset = 'ussp_list';
