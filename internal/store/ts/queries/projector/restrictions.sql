-- The dynamic restrictions projection written by api as
-- authority_ts_projector (WP-6, migration 00010_restrictions_projection),
-- always whole, under a transaction-scoped advisory lock, and never with
-- a CIS version older than the one the state row holds.

-- name: LockRestrictionsProjection :exec
SELECT pg_advisory_xact_lock(hashtextextended('cisp/proj_restrictions', 0));

-- name: RestrictionsProjectionVersion :one
-- -1 when the projection was never written.
SELECT coalesce((SELECT cis_version FROM proj_restrictions_state WHERE id), -1)::bigint AS cis_version;

-- name: DeleteAllRestrictions :execrows
DELETE FROM proj_restrictions;

-- name: InsertRestrictions :execrows
INSERT INTO proj_restrictions (identifier, feature, state, starts_at, ends_at, ansp_ref, uspace_airspace_id,
                               cis_version, projected_at)
SELECT r.identifier, r.feature, r.state, r.starts_at, r.ends_at, nullif(r.ansp_ref, ''),
       nullif(r.uspace_airspace_id, ''), sqlc.arg(cis_version)::bigint, sqlc.arg(projected_at)::timestamptz
FROM (SELECT unnest(sqlc.arg(identifiers)::text[]) AS identifier,
             (unnest(sqlc.arg(features)::text[]))::jsonb AS feature,
             unnest(sqlc.arg(states)::text[]) AS state,
             unnest(sqlc.arg(starts)::timestamptz[]) AS starts_at,
             unnest(sqlc.arg(ends)::timestamptz[]) AS ends_at,
             unnest(sqlc.arg(ansp_refs)::text[]) AS ansp_ref,
             unnest(sqlc.arg(airspace_ids)::text[]) AS uspace_airspace_id) AS r;

-- name: UpsertRestrictionsState :exec
INSERT INTO proj_restrictions_state (id, cis_version, etag, projected_at)
VALUES (true, sqlc.arg(cis_version), sqlc.arg(etag), sqlc.arg(projected_at))
ON CONFLICT (id) DO UPDATE SET
    cis_version = EXCLUDED.cis_version, etag = EXCLUDED.etag, projected_at = EXCLUDED.projected_at;
