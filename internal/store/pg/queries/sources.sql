-- WP-10: source control (migration 00011_source_controls).

-- name: SourceControlEpoch :one
-- The state's epoch and the last version drawn for a change.
SELECT epoch, version FROM source_control_epoch;

-- name: SetSourceControlVersion :exec
UPDATE source_control_epoch SET version = sqlc.arg(version);

-- name: StartSourceControlEpoch :exec
-- A new epoch (a restored database): followers take its state whatever
-- the version.
UPDATE source_control_epoch SET epoch = sqlc.arg(epoch), version = sqlc.arg(version);

-- name: NextSourceControlVersion :one
SELECT nextval('source_control_version_seq')::bigint AS version;

-- name: SourceControlFor :one
SELECT source_type, instance_id, enabled, reason, actor, changed_at, version, epoch
FROM source_controls
WHERE source_type = sqlc.arg(source_type) AND instance_id IS NOT DISTINCT FROM sqlc.narg(instance_id)::text
FOR UPDATE;

-- name: InsertSourceControl :exec
INSERT INTO source_controls (source_type, instance_id, enabled, reason, actor, changed_at, version, epoch)
VALUES (sqlc.arg(source_type), sqlc.narg(instance_id), sqlc.arg(enabled), sqlc.arg(reason), sqlc.arg(actor),
        sqlc.arg(changed_at), sqlc.arg(version), sqlc.arg(epoch));

-- name: UpdateSourceControl :exec
UPDATE source_controls
SET enabled = sqlc.arg(enabled), reason = sqlc.arg(reason), actor = sqlc.arg(actor), changed_at = sqlc.arg(changed_at),
    version = sqlc.arg(version), epoch = sqlc.arg(epoch)
WHERE source_type = sqlc.arg(source_type) AND instance_id IS NOT DISTINCT FROM sqlc.narg(instance_id)::text;

-- name: ListSourceControls :many
-- Every switch: a type's row before its instances'.
SELECT source_type, instance_id, enabled, reason, actor, changed_at, version, epoch
FROM source_controls
ORDER BY source_type, instance_id NULLS FIRST;
