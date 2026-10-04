-- WP-19: the police realm's record (police_queries, police_exports) and
-- the DPO report's reads. Every time here is the database clock.

-- name: PoliceBudget :one
-- The queries of a user and of an agency within the last window_s
-- seconds of the database clock, and in how many seconds the oldest of
-- each leaves the window (when a spent budget frees again). The caller holds the agency's
-- advisory lock, so two replicas cannot both spend the last query.
SELECT
    count(*) FILTER (WHERE user_id = sqlc.arg(user_id))::bigint AS user_n,
    count(*) FILTER (WHERE agency = sqlc.arg(agency))::bigint AS agency_n,
    coalesce(extract(epoch FROM min(at) FILTER (WHERE user_id = sqlc.arg(user_id))
        + make_interval(secs => sqlc.arg(window_s)::double precision) - now()), 0)::double precision AS user_frees_in_s,
    coalesce(extract(epoch FROM min(at) FILTER (WHERE agency = sqlc.arg(agency))
        + make_interval(secs => sqlc.arg(window_s)::double precision) - now()), 0)::double precision AS agency_frees_in_s
FROM police_queries
WHERE (user_id = sqlc.arg(user_id) OR agency = sqlc.arg(agency))
  AND at > now() - make_interval(secs => sqlc.arg(window_s)::double precision);

-- name: InsertPoliceQuery :one
INSERT INTO police_queries (id, user_id, agency, session_jti, kind, purpose, case_ref, query, result_count, pii, remote_ip)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(agency), sqlc.arg(session_jti), sqlc.arg(kind), sqlc.arg(purpose),
        sqlc.arg(case_ref), sqlc.arg(query), sqlc.arg(result_count), sqlc.arg(pii), sqlc.arg(remote_ip))
RETURNING at;

-- name: InsertPoliceExport :exec
INSERT INTO police_exports (pack_id, incident_id, query_id, agency, user_id)
VALUES (sqlc.arg(pack_id), sqlc.arg(incident_id), sqlc.arg(query_id), sqlc.arg(agency), sqlc.arg(user_id));

-- name: PoliceExportByPack :one
SELECT pack_id, incident_id, query_id, agency, user_id, created_at FROM police_exports WHERE pack_id = sqlc.arg(pack_id);

-- name: PoliceQueriesInRange :many
-- The DPO report: a month's police queries in time order, bounded.
SELECT id, at, user_id, agency, session_jti, kind, purpose, case_ref, query, result_count, pii, remote_ip
FROM police_queries
WHERE at >= sqlc.arg(from_ts) AND at < sqlc.arg(to_ts)
ORDER BY at, id
LIMIT sqlc.arg(row_limit);

-- name: PIIEventsInRange :many
-- The DPO report: a month's events rows of the personal-data read
-- types, in chain order, bounded.
SELECT id, ts, actor_type, actor_id, realm, purpose, entity_type, entity_id, event_type, payload
FROM events
WHERE ts >= sqlc.arg(from_ts) AND ts < sqlc.arg(to_ts) AND event_type = ANY (sqlc.arg(event_types)::text[])
ORDER BY id
LIMIT sqlc.arg(row_limit);
