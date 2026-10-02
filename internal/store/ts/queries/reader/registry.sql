-- name: ProjectedOperators :many
-- The registry projection's operators (identify.OperatorFacts), read by
-- every resolver into an identify.Snapshot (WP-3, LESSONS G-08).
SELECT operator_id, registration_number_public, status, projected_at, registry_version
FROM proj_registry_operators ORDER BY operator_id;

-- name: ProjectedUAS :many
-- The registry projection's aircraft (identify.UASFacts).
SELECT uas_id, label, serial, serial_fold, registration_status, operator_id, in_registry, projected_at, registry_version
FROM proj_registry_uas ORDER BY uas_id;
