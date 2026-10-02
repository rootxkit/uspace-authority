-- WP-14: the Display Provider's oversight areas (migration 00016_dp_views).

-- name: InsertDPView :one
INSERT INTO dp_views (label, west_deg, south_deg, east_deg, north_deg, created_by)
VALUES (sqlc.arg(label), sqlc.arg(west_deg), sqlc.arg(south_deg), sqlc.arg(east_deg), sqlc.arg(north_deg), sqlc.arg(created_by))
RETURNING id, label, west_deg, south_deg, east_deg, north_deg, created_by, created_at;

-- name: ListDPViews :many
-- Every area, oldest first, at most limit.
SELECT id, label, west_deg, south_deg, east_deg, north_deg, created_by, created_at
FROM dp_views
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: CountDPViews :one
SELECT count(*)::bigint AS n FROM dp_views;
