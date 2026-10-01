-- name: SchemaVersion :one
-- The version the timeseries tree is at (the latest goose row); the
-- reader refuses to start on an older schema than it was built for (D7).
SELECT version_id FROM goose_db_version_timeseries ORDER BY id DESC LIMIT 1;
