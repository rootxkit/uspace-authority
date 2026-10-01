-- name: SchemaVersion :one
-- The version the relational tree is at: goose v3 deletes the row of a
-- rolled-back migration, so the latest row is the current version.
SELECT version_id FROM goose_db_version_relational ORDER BY id DESC LIMIT 1;

-- name: AdvisoryXactLock :exec
-- Blocks until the transaction-scoped advisory lock key is held; it is
-- released at commit or rollback.
SELECT pg_advisory_xact_lock(sqlc.arg(key)::bigint);
