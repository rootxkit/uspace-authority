-- WP-20: the uas.gov.ge import ledger (migration 00022_registry_import).

-- name: InsertRegistryImport :one
INSERT INTO registry_imports (
    id, kind, origin, content_sha256, rules_version, outcome, rows_read, created, updated, unchanged, problems,
    registry_version, actor_id
) VALUES (
    sqlc.arg(id), sqlc.arg(kind), sqlc.arg(origin), sqlc.arg(content_sha256), sqlc.arg(rules_version), sqlc.arg(outcome),
    sqlc.arg(rows_read), sqlc.arg(created), sqlc.arg(updated), sqlc.arg(unchanged), sqlc.arg(problems),
    sqlc.narg(registry_version), sqlc.arg(actor_id)
)
RETURNING at;

-- name: LastRegistryImport :one
-- The newest import of a kind from an origin (the re-import job skips
-- content it ran to an outcome before).
SELECT * FROM registry_imports
WHERE kind = sqlc.arg(kind) AND origin = sqlc.arg(origin)
ORDER BY at DESC, id DESC
LIMIT 1;
