-- WP-7: the Remote ID receiver registry (migration 00010_rid_receivers).
-- geom is derived from lat_deg and lon_deg and never selected here.

-- name: InsertReceiver :one
INSERT INTO rid_receivers (
    id, name, lat_deg, lon_deg, owner, owner_name, key_generation, key_hash, pii_key_id, hmac_secret_enc,
    status, firmware, config, version, created_at, created_by, updated_at, updated_by
) VALUES (
    sqlc.arg(id), sqlc.arg(name), sqlc.arg(lat_deg), sqlc.arg(lon_deg), sqlc.arg(owner), sqlc.narg(owner_name),
    1, sqlc.arg(key_hash), sqlc.arg(pii_key_id), sqlc.arg(hmac_secret_enc),
    'enabled', NULL, sqlc.arg(config), 1, sqlc.arg(created_at), sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING id, name, lat_deg, lon_deg, owner, owner_name, key_generation, key_hash, pii_key_id, hmac_secret_enc,
    prev_key_hash, prev_pii_key_id, prev_hmac_secret_enc, prev_valid_until, status, disabled_by, disabled_reason,
    disabled_at, last_seen_at, last_lat_deg, last_lon_deg, last_alt_hae_m, position_deviation_m,
    position_deviations, firmware, config, version, created_at, created_by, updated_at, updated_by;

-- name: ReceiverByID :one
SELECT id, name, lat_deg, lon_deg, owner, owner_name, key_generation, key_hash, pii_key_id, hmac_secret_enc,
    prev_key_hash, prev_pii_key_id, prev_hmac_secret_enc, prev_valid_until, status, disabled_by, disabled_reason,
    disabled_at, last_seen_at, last_lat_deg, last_lon_deg, last_alt_hae_m, position_deviation_m,
    position_deviations, firmware, config, version, created_at, created_by, updated_at, updated_by
FROM rid_receivers WHERE id = sqlc.arg(id);

-- name: ReceiverForUpdate :one
SELECT id, name, lat_deg, lon_deg, owner, owner_name, key_generation, key_hash, pii_key_id, hmac_secret_enc,
    prev_key_hash, prev_pii_key_id, prev_hmac_secret_enc, prev_valid_until, status, disabled_by, disabled_reason,
    disabled_at, last_seen_at, last_lat_deg, last_lon_deg, last_alt_hae_m, position_deviation_m,
    position_deviations, firmware, config, version, created_at, created_by, updated_at, updated_by
FROM rid_receivers WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListReceivers :many
-- One page in id order after after_id.
SELECT id, name, lat_deg, lon_deg, owner, owner_name, key_generation, key_hash, pii_key_id, hmac_secret_enc,
    prev_key_hash, prev_pii_key_id, prev_hmac_secret_enc, prev_valid_until, status, disabled_by, disabled_reason,
    disabled_at, last_seen_at, last_lat_deg, last_lon_deg, last_alt_hae_m, position_deviation_m,
    position_deviations, firmware, config, version, created_at, created_by, updated_at, updated_by
FROM rid_receivers WHERE id > sqlc.arg(after_id) ORDER BY id LIMIT sqlc.arg(page_size);

-- name: UpdateReceiver :exec
-- Writes the whole mutable row; the service reads it FOR UPDATE first.
UPDATE rid_receivers SET
    name = sqlc.arg(name),
    lat_deg = sqlc.arg(lat_deg),
    lon_deg = sqlc.arg(lon_deg),
    owner = sqlc.arg(owner),
    owner_name = sqlc.narg(owner_name),
    key_generation = sqlc.arg(key_generation),
    key_hash = sqlc.arg(key_hash),
    pii_key_id = sqlc.arg(pii_key_id),
    hmac_secret_enc = sqlc.arg(hmac_secret_enc),
    prev_key_hash = sqlc.narg(prev_key_hash),
    prev_pii_key_id = sqlc.narg(prev_pii_key_id),
    prev_hmac_secret_enc = sqlc.narg(prev_hmac_secret_enc),
    prev_valid_until = sqlc.narg(prev_valid_until),
    status = sqlc.arg(status),
    disabled_by = sqlc.narg(disabled_by),
    disabled_reason = sqlc.narg(disabled_reason),
    disabled_at = sqlc.narg(disabled_at),
    config = sqlc.arg(config),
    version = version + 1,
    updated_at = sqlc.arg(updated_at),
    updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id);

-- name: RecordReceiverHeartbeat :exec
-- A heartbeat: when it arrived (api's clock), where the receiver says it
-- is, its firmware, and the deviation from the pinned position. A
-- heartbeat without a position keeps the last one.
UPDATE rid_receivers SET
    last_seen_at = sqlc.arg(last_seen_at),
    last_lat_deg = COALESCE(sqlc.narg(last_lat_deg)::double precision, last_lat_deg),
    last_lon_deg = COALESCE(sqlc.narg(last_lon_deg)::double precision, last_lon_deg),
    last_alt_hae_m = CASE WHEN sqlc.narg(last_lat_deg)::double precision IS NULL THEN last_alt_hae_m
                          ELSE sqlc.narg(last_alt_hae_m)::double precision END,
    position_deviation_m = COALESCE(sqlc.narg(position_deviation_m)::double precision, position_deviation_m),
    position_deviations = position_deviations + sqlc.arg(deviation_increment)::bigint,
    firmware = COALESCE(sqlc.narg(firmware)::text, firmware)
WHERE id = sqlc.arg(id);

-- name: DeleteReceiver :execrows
DELETE FROM rid_receivers WHERE id = sqlc.arg(id);
