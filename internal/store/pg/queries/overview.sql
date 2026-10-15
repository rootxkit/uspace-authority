-- The overview's counts (internal/overview, GET /v1/overview/*): figures
-- only, never a row's content, each a bounded or index-backed count
-- (migration 00027_overview_counts).

-- name: OverviewRegistryCounts :many
-- Every operator, UAS and pilot by status, in one statement so the
-- three figures are of one snapshot. Index-only scans of
-- uas_operators_status_idx, uas_status_idx and remote_pilots_status_idx.
SELECT 'operators'::text AS entity, status, count(*)::bigint AS n FROM uas_operators GROUP BY status
UNION ALL
SELECT 'uas'::text, status, count(*)::bigint FROM uas GROUP BY status
UNION ALL
SELECT 'pilots'::text, status, count(*)::bigint FROM remote_pilots GROUP BY status;

-- name: OverviewUSpaceCounts :many
-- The newest version of every U-space airspace by its state: what GET
-- /v1/uspace lists, counted (geo_zones_dataset_identifier_idx).
SELECT state, count(*)::bigint AS n
FROM (
    SELECT DISTINCT ON (identifier) state
    FROM geo_zones
    WHERE dataset = 'uspace_airspace'
    ORDER BY identifier, zone_version DESC
) newest
GROUP BY state;

-- name: OverviewCertificateCounts :many
-- Every USSP and CISP certificate by its derived status.
SELECT status, count(*)::bigint AS n FROM certificates GROUP BY status;

-- name: OverviewAuditEventCount :one
-- The events rows of the window that ends at the database clock, counted
-- up to max_rows (events_ts_idx): a result of max_rows means at least
-- that many.
SELECT count(*)::bigint AS n
FROM (
    SELECT 1
    FROM events
    WHERE ts > now() - make_interval(secs => sqlc.arg(window_s)::double precision) AND ts <= now()
    LIMIT sqlc.arg(max_rows)::bigint
) recent;
