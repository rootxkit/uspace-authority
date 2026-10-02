-- The registry projection written by api as authority_ts_projector
-- (WP-3, migration 00003_registry_projection). Every write runs under
-- the registry's advisory lock, so a re-projection never reads a state
-- older than a change it could overwrite (G-08). A change's upsert also
-- refuses to replace a row with a newer registry_version; a repair
-- (repair = true) replaces every row with the registry's state, because
-- a change whose relational commit failed after its projection commit
-- left a row newer than anything the registry holds.

-- name: SchemaVersion :one
SELECT version_id FROM goose_db_version_timeseries ORDER BY id DESC LIMIT 1;

-- name: UpsertProjectedOperators :execrows
INSERT INTO proj_registry_operators (operator_id, registration_number_public, status, projected_at, registry_version)
SELECT unnest(sqlc.arg(operator_ids)::text[]), unnest(sqlc.arg(registration_numbers)::text[]),
       unnest(sqlc.arg(statuses)::text[]), sqlc.arg(projected_at)::timestamptz,
       unnest(sqlc.arg(registry_versions)::bigint[])
ON CONFLICT (operator_id) DO UPDATE SET
    registration_number_public = EXCLUDED.registration_number_public,
    status = EXCLUDED.status,
    projected_at = EXCLUDED.projected_at,
    registry_version = EXCLUDED.registry_version
WHERE sqlc.arg(repair)::boolean OR proj_registry_operators.registry_version <= EXCLUDED.registry_version;

-- name: UpsertProjectedUAS :execrows
INSERT INTO proj_registry_uas (uas_id, label, serial, serial_fold, registration_status, operator_id, in_registry,
                               projected_at, registry_version)
SELECT u.uas_id, u.label, u.serial, u.serial_fold, u.registration_status, NULLIF(u.operator_id, ''), true,
       sqlc.arg(projected_at)::timestamptz, u.registry_version
FROM (SELECT unnest(sqlc.arg(uas_ids)::text[]) AS uas_id, unnest(sqlc.arg(labels)::text[]) AS label,
             unnest(sqlc.arg(serials)::text[]) AS serial, unnest(sqlc.arg(serial_folds)::text[]) AS serial_fold,
             unnest(sqlc.arg(statuses)::text[]) AS registration_status,
             unnest(sqlc.arg(operator_ids)::text[]) AS operator_id,
             unnest(sqlc.arg(registry_versions)::bigint[]) AS registry_version) AS u
ON CONFLICT (uas_id) DO UPDATE SET
    label = EXCLUDED.label,
    serial = EXCLUDED.serial,
    serial_fold = EXCLUDED.serial_fold,
    registration_status = EXCLUDED.registration_status,
    operator_id = EXCLUDED.operator_id,
    in_registry = true,
    projected_at = EXCLUDED.projected_at,
    registry_version = EXCLUDED.registry_version
WHERE sqlc.arg(repair)::boolean OR proj_registry_uas.registry_version <= EXCLUDED.registry_version;

-- name: MarkUASNotInRegistry :execrows
-- Aircraft rows the registry does not hold: kept, never deleted, and
-- marked so identification never reads them as registered.
UPDATE proj_registry_uas SET in_registry = false, projected_at = sqlc.arg(projected_at)
WHERE in_registry AND uas_id NOT IN (SELECT unnest(sqlc.arg(known_ids)::text[]));

-- name: MarkOperatorsNotInRegistry :execrows
-- Operator rows the registry does not hold: kept with a status
-- identification does not recognise (owner_unknown, never in good
-- standing).
UPDATE proj_registry_operators SET status = 'unregistered', projected_at = sqlc.arg(projected_at)
WHERE status <> 'unregistered' AND operator_id NOT IN (SELECT unnest(sqlc.arg(known_ids)::text[]));
