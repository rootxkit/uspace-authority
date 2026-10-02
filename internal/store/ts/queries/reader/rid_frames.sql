-- name: RIDFrames :many
-- WP-7: raw Remote ID frames in [from_ts, to_ts) by ingest time, with
-- optional transmitter and receiver filters, oldest first, one row more
-- than the page so the caller can say the page was cut (B-13: a window is
-- refused or paged, never thinned).
SELECT ingest_ts, frame_id, receiver_id, transmitter, rx_ts, msg_type, payload, payload_sha256, rssi_dbm,
    backlog, receiver_lat_deg, receiver_lon_deg, receiver_alt_hae_m, sent_at_ms, nonce
FROM rid_observations
WHERE ingest_ts >= sqlc.arg(from_ts) AND ingest_ts < sqlc.arg(to_ts)
  AND (sqlc.narg(transmitter)::text IS NULL OR transmitter = sqlc.narg(transmitter))
  AND (sqlc.narg(receiver_id)::text IS NULL OR receiver_id = sqlc.narg(receiver_id))
ORDER BY ingest_ts, frame_id
LIMIT sqlc.arg(row_limit);

-- name: RIDFrameByID :many
-- WP-7: every stored row of one frame id (a frame written twice by a
-- redelivery shows as two rows rather than being hidden).
SELECT ingest_ts, frame_id, receiver_id, transmitter, rx_ts, msg_type, payload, payload_sha256, rssi_dbm,
    backlog, receiver_lat_deg, receiver_lon_deg, receiver_alt_hae_m, sent_at_ms, nonce
FROM rid_observations
WHERE frame_id = sqlc.arg(frame_id)
ORDER BY ingest_ts
LIMIT 16;
