-- name: ActivePolicy :one
SELECT * FROM authority_policy WHERE active;

-- name: PolicyByVersion :one
SELECT * FROM authority_policy WHERE version = sqlc.arg(version);

-- name: ListPolicies :many
SELECT * FROM authority_policy ORDER BY version DESC LIMIT sqlc.arg(page_size);

-- name: MaxPolicyVersion :one
SELECT COALESCE(max(version), 0)::bigint AS version FROM authority_policy;

-- name: InsertPolicy :one
INSERT INTO authority_policy (
    version, height_limit_agl_m, pressure_uncertainty_m,
    zone_conditional_severity, mismatch_severity, identification_severity,
    spoof_distance_m, identity_ttl_s, max_gap_s, identify_within_s,
    broadcast_tolerance_s, max_latency_s, live_max_age_s, clear_after_s,
    stale_after_s, dp_view_diagonal_km, dp_poll_hz, cis_stale_bound_s,
    height_limit_in_uspace, registration_number_pattern, note, created_at, created_by
) VALUES (
    sqlc.arg(version), sqlc.arg(height_limit_agl_m), sqlc.arg(pressure_uncertainty_m),
    sqlc.arg(zone_conditional_severity), sqlc.arg(mismatch_severity), sqlc.arg(identification_severity),
    sqlc.arg(spoof_distance_m), sqlc.arg(identity_ttl_s), sqlc.arg(max_gap_s), sqlc.arg(identify_within_s),
    sqlc.arg(broadcast_tolerance_s), sqlc.arg(max_latency_s), sqlc.arg(live_max_age_s), sqlc.arg(clear_after_s),
    sqlc.arg(stale_after_s), sqlc.arg(dp_view_diagonal_km), sqlc.arg(dp_poll_hz), sqlc.arg(cis_stale_bound_s),
    sqlc.arg(height_limit_in_uspace), sqlc.arg(registration_number_pattern), sqlc.arg(note), sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: DeactivatePolicies :exec
UPDATE authority_policy SET active = false WHERE active;

-- name: ActivatePolicy :one
UPDATE authority_policy
SET active = true, activated_at = sqlc.arg(activated_at), activated_by = sqlc.arg(activated_by)
WHERE version = sqlc.arg(version)
RETURNING *;
