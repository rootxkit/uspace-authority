-- WP-17: the telemetry sources of an evidence pack, read as the reader
-- role (SELECT only). Every query is bounded by row_limit, which the
-- caller sets one above its cap so that a window holding more is
-- refused rather than thinned (B-13).

-- name: EvidenceTrackIDs :many
-- The tracks that carried one of the serials in the window.
SELECT DISTINCT track_id FROM tracks
WHERE captured_at >= sqlc.arg(from_ts) AND captured_at < sqlc.arg(to_ts) AND serial = ANY (sqlc.arg(serials)::text[])
ORDER BY track_id
LIMIT sqlc.arg(row_limit);

-- name: EvidenceTracks :many
-- The fused picture's samples of the tracks in the window, as stored,
-- oldest first. Nothing is interpolated or resampled.
SELECT captured_at, track_id, msg_id, ts, rx_ts, time_source, backlog, source, source_instance, trust, lat_deg, lon_deg,
       alt_wgs84_m, alt_amsl_m, alt_source, alt_pressure_m, height_m, height_ref, speed_ms, track_deg, vspeed_ms,
       accuracy_h_m, accuracy_v_m, status, emergency, airborne, ident_status, ident_reason, ident_mismatch, ident_basis,
       serial, operator_reg, registered_operator_reg, registry_uas_id, flight_id, ussp_id, cell5, identity_receiver
FROM tracks
WHERE captured_at >= sqlc.arg(from_ts) AND captured_at < sqlc.arg(to_ts) AND track_id = ANY (sqlc.arg(track_ids)::text[])
ORDER BY track_id, captured_at, dedupe_key
LIMIT sqlc.arg(row_limit);

-- name: EvidenceTransmitters :many
-- The Remote ID transmitters that broadcast one of the serials in the
-- window (a Location frame carries no serial: the transmitter links it).
SELECT DISTINCT transmitter FROM rid_observations
WHERE ingest_ts >= sqlc.arg(from_ts) AND ingest_ts < sqlc.arg(to_ts) AND serial = ANY (sqlc.arg(serials)::text[])
ORDER BY transmitter
LIMIT sqlc.arg(row_limit);

-- name: EvidenceFrames :many
-- The raw frames of the transmitters in the window with what was
-- decoded from them, oldest first (R-15: the raw frames are the
-- archive).
SELECT ingest_ts, frame_id, receiver_id, transmitter, receiver_ts, msg_type, payload, payload_sha256, rssi_dbm, backlog,
       serial, operator_reg, lat_deg, lon_deg, captured_at, time_source, decode_error
FROM rid_observations
WHERE ingest_ts >= sqlc.arg(from_ts) AND ingest_ts < sqlc.arg(to_ts) AND transmitter = ANY (sqlc.arg(transmitters)::text[])
ORDER BY ingest_ts, frame_id
LIMIT sqlc.arg(row_limit);

-- name: EvidenceWriterGaps :many
-- The recorded holes of the tracks and frames tables in the window
-- (WP-9: every dropped or spilled batch with its cause).
SELECT dedupe_key, table_name, stream, from_seq, to_seq, cause, count, count_unit, at, receiver_id, detail
FROM writer_gaps
WHERE at >= sqlc.arg(from_ts) AND at < sqlc.arg(to_ts) AND table_name IN ('tracks', 'rid_observations')
ORDER BY at, dedupe_key
LIMIT sqlc.arg(row_limit);

-- name: EvidenceUSSPFlights :many
-- The Display Provider's rows of the tracks in the window, while they
-- are still held (24 h retention, F3411).
SELECT rx_ts, ussp_id, uss_base_url, isa_id, flight_id, track_id, state_ts, provider_unknown, flight, details
FROM ussp_flights
WHERE rx_ts >= sqlc.arg(from_ts) AND rx_ts < sqlc.arg(to_ts) AND track_id = ANY (sqlc.arg(track_ids)::text[])
ORDER BY rx_ts, dedupe_key
LIMIT sqlc.arg(row_limit);

-- name: EvidenceOldestUSSPFlight :one
-- The oldest Display Provider row held: before it the cache holds
-- nothing (disposed of within 24 h).
SELECT coalesce(min(rx_ts), now())::timestamptz AS oldest FROM ussp_flights;
