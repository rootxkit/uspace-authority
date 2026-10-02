-- The dynamic restrictions projection read by the detectors (WP-12) and
-- the console, as authority_ts_reader (WP-6).

-- name: ReadRestrictions :many
SELECT identifier, feature, state, starts_at, ends_at, ansp_ref, uspace_airspace_id, cis_version, projected_at
FROM proj_restrictions ORDER BY identifier;

-- name: ReadRestrictionsState :one
-- No row: never projected.
SELECT cis_version, etag, projected_at, extract(epoch FROM now() - projected_at)::double precision AS age_s
FROM proj_restrictions_state WHERE id;
