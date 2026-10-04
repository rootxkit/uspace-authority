-- WP-19: the police realm's reads of the authority's picture, as the
-- reader role (SELECT only). Bounded by row_limit, which the caller sets
-- one above its cap so that it can say an answer was truncated.

-- name: PoliceClock :one
-- The telemetry database's clock and the newest sample of the picture
-- within horizon_s of it (how fresh the picture is).
SELECT now()::timestamptz AS db_now, (count(*) > 0)::boolean AS has_newest,
       coalesce(extract(epoch FROM now() - max(captured_at)), 0)::double precision AS newest_age_s
FROM tracks
WHERE captured_at > now() - make_interval(secs => sqlc.arg(horizon_s)::double precision);

-- name: PoliceAircraft :many
-- One row per track seen in the box over [from_ts, to_ts]: when it was
-- first and last seen there, and its newest sample there. The remote
-- pilot position is not a column of tracks.
SELECT s.track_id, s.first_seen::timestamptz AS first_seen, s.last_seen::timestamptz AS last_seen, s.samples,
       t.source, t.trust, t.emergency, t.ident_status, t.ident_reason, t.ident_basis, t.serial, t.operator_reg,
       t.registered_operator_reg, t.registry_uas_id
FROM (
    SELECT a.track_id, min(a.captured_at) AS first_seen, max(a.captured_at) AS last_seen, count(*)::bigint AS samples
    FROM tracks a
    WHERE a.captured_at >= sqlc.arg(from_ts) AND a.captured_at <= sqlc.arg(to_ts)
      AND a.lat_deg >= sqlc.arg(min_lat) AND a.lat_deg <= sqlc.arg(max_lat)
      AND a.lon_deg >= sqlc.arg(min_lon) AND a.lon_deg <= sqlc.arg(max_lon)
    GROUP BY a.track_id
    ORDER BY max(a.captured_at) DESC, a.track_id
    LIMIT sqlc.arg(row_limit)
) s
JOIN LATERAL (
    SELECT b.source, b.trust, b.emergency, b.ident_status, b.ident_reason, b.ident_basis, b.serial, b.operator_reg,
           b.registered_operator_reg, b.registry_uas_id
    FROM tracks b
    WHERE b.track_id = s.track_id AND b.captured_at = s.last_seen
      AND b.lat_deg >= sqlc.arg(min_lat) AND b.lat_deg <= sqlc.arg(max_lat)
      AND b.lon_deg >= sqlc.arg(min_lon) AND b.lon_deg <= sqlc.arg(max_lon)
    ORDER BY b.dedupe_key
    LIMIT 1
) t ON true
ORDER BY s.last_seen DESC, s.track_id;

-- name: PolicePositions :many
-- The newest per_track samples of each track in the box over the
-- window (newest first within a track; the caller reverses them).
SELECT t.track_id, t.captured_at, t.lat_deg, t.lon_deg, t.alt_amsl_m, t.alt_source, t.height_m, t.height_ref, t.speed_ms,
       t.track_deg
FROM unnest(sqlc.arg(track_ids)::text[]) AS k (id)
JOIN LATERAL (
    SELECT c.track_id, c.captured_at, c.lat_deg, c.lon_deg, c.alt_amsl_m, c.alt_source, c.height_m, c.height_ref, c.speed_ms,
           c.track_deg
    FROM tracks c
    WHERE c.track_id = k.id AND c.captured_at >= sqlc.arg(from_ts) AND c.captured_at <= sqlc.arg(to_ts)
      AND c.lat_deg >= sqlc.arg(min_lat) AND c.lat_deg <= sqlc.arg(max_lat)
      AND c.lon_deg >= sqlc.arg(min_lon) AND c.lon_deg <= sqlc.arg(max_lon)
    ORDER BY c.captured_at DESC, c.dedupe_key
    LIMIT sqlc.arg(per_track)
) t ON true
ORDER BY t.track_id, t.captured_at DESC;

-- name: PoliceWriterGaps :one
-- The recorded holes of the tracks table over the window (WP-9).
SELECT count(*)::bigint AS gaps, coalesce(array_agg(DISTINCT cause ORDER BY cause), '{}')::text[] AS causes
FROM writer_gaps
WHERE at >= sqlc.arg(from_ts) AND at <= sqlc.arg(to_ts) AND table_name = 'tracks';
