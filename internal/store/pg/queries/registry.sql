-- WP-3: the registry of operators, UAS and remote pilots, and the F8
-- change feed (migration 00009_registry).

-- name: NextRegistryVersion :one
-- Numbers one registry change; the projection rows it writes carry it.
SELECT nextval('registry_version_seq')::bigint AS version;

-- name: InsertOperator :one
INSERT INTO uas_operators (
    id, operator_type, registration_number_public, registration_number_key,
    secret_part_salt, secret_part_hash, pii_key_id,
    full_name_enc, legal_name_enc, date_of_birth_enc, legal_identification_number_enc,
    postal_address_enc, contact_email_enc, contact_phone_enc, insurance_policy_number_enc,
    competency_confirmation, authorisations, status, status_reason, valid_from, valid_until,
    source, registry_version, created_at, created_by, updated_at, updated_by
) VALUES (
    sqlc.arg(id), sqlc.arg(operator_type), sqlc.arg(registration_number_public), sqlc.arg(registration_number_key),
    sqlc.narg(secret_part_salt), sqlc.narg(secret_part_hash), sqlc.arg(pii_key_id),
    sqlc.narg(full_name_enc), sqlc.narg(legal_name_enc), sqlc.narg(date_of_birth_enc), sqlc.narg(legal_identification_number_enc),
    sqlc.arg(postal_address_enc), sqlc.arg(contact_email_enc), sqlc.arg(contact_phone_enc), sqlc.narg(insurance_policy_number_enc),
    sqlc.arg(competency_confirmation), sqlc.arg(authorisations), sqlc.arg(status), sqlc.arg(status_reason),
    sqlc.arg(valid_from), sqlc.arg(valid_until), sqlc.arg(source), sqlc.arg(registry_version),
    sqlc.arg(created_at), sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: OperatorByID :one
SELECT * FROM uas_operators WHERE id = sqlc.arg(id);

-- name: OperatorForUpdate :one
SELECT * FROM uas_operators WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: OperatorByKey :one
SELECT * FROM uas_operators WHERE registration_number_key = sqlc.arg(registration_number_key);

-- name: ListOperators :many
-- One page in id order after after_id; key and status filter when given.
SELECT * FROM uas_operators
WHERE (sqlc.narg(registration_number_key)::text IS NULL OR registration_number_key = sqlc.narg(registration_number_key))
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status))
  AND id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: UpdateOperator :one
UPDATE uas_operators SET
    pii_key_id = sqlc.arg(pii_key_id),
    full_name_enc = sqlc.narg(full_name_enc),
    legal_name_enc = sqlc.narg(legal_name_enc),
    date_of_birth_enc = sqlc.narg(date_of_birth_enc),
    legal_identification_number_enc = sqlc.narg(legal_identification_number_enc),
    postal_address_enc = sqlc.arg(postal_address_enc),
    contact_email_enc = sqlc.arg(contact_email_enc),
    contact_phone_enc = sqlc.arg(contact_phone_enc),
    insurance_policy_number_enc = sqlc.narg(insurance_policy_number_enc),
    competency_confirmation = sqlc.arg(competency_confirmation),
    authorisations = sqlc.arg(authorisations),
    valid_until = sqlc.arg(valid_until),
    registry_version = sqlc.arg(registry_version),
    updated_at = sqlc.arg(updated_at),
    updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetOperatorStatus :one
UPDATE uas_operators SET
    status = sqlc.arg(status), status_reason = sqlc.arg(status_reason),
    registry_version = sqlc.arg(registry_version), updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: ExpiredOperatorIDs :many
-- Registrations whose validity ended and that are not marked so yet.
SELECT id FROM uas_operators
WHERE status IN ('active', 'suspended') AND valid_until <= sqlc.arg(now)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: AllOperatorFacts :many
-- What the projection holds of every operator (identify.OperatorFacts).
SELECT id, registration_number_public, status, registry_version FROM uas_operators ORDER BY id;

-- name: InsertUAS :one
INSERT INTO uas (
    id, operator_id, serial, serial_fold, manufacturer_code, registration_mark, manufacturer, model,
    owner_ref, class_label, mtom_g, rid_capability, status, status_reason, registered_at,
    registry_version, created_by, updated_at, updated_by
) VALUES (
    sqlc.arg(id), sqlc.arg(operator_id), sqlc.arg(serial), sqlc.arg(serial_fold), sqlc.arg(manufacturer_code),
    sqlc.narg(registration_mark), sqlc.arg(manufacturer), sqlc.arg(model), sqlc.narg(owner_ref),
    sqlc.narg(class_label), sqlc.narg(mtom_g), sqlc.arg(rid_capability), sqlc.arg(status), sqlc.arg(status_reason),
    sqlc.arg(registered_at), sqlc.arg(registry_version), sqlc.arg(created_by), sqlc.arg(registered_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: UASByID :one
SELECT * FROM uas WHERE id = sqlc.arg(id);

-- name: UASForUpdate :one
SELECT * FROM uas WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: UASBySerialFold :many
-- Every aircraft whose serial folds to the key (at most one: serial_fold
-- is unique; the caller still refuses more than one, G-05).
SELECT * FROM uas WHERE serial_fold = sqlc.arg(serial_fold) ORDER BY id;

-- name: ListUAS :many
SELECT * FROM uas
WHERE (sqlc.narg(serial_fold)::text IS NULL OR serial_fold = sqlc.narg(serial_fold))
  AND (sqlc.narg(operator_id)::text IS NULL OR operator_id = sqlc.narg(operator_id))
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status))
  AND id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: UpdateUAS :one
UPDATE uas SET
    registration_mark = sqlc.narg(registration_mark),
    manufacturer = sqlc.arg(manufacturer),
    model = sqlc.arg(model),
    owner_ref = sqlc.narg(owner_ref),
    class_label = sqlc.narg(class_label),
    mtom_g = sqlc.narg(mtom_g),
    rid_capability = sqlc.arg(rid_capability),
    registry_version = sqlc.arg(registry_version),
    updated_at = sqlc.arg(updated_at),
    updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetUASStatus :one
UPDATE uas SET
    status = sqlc.arg(status), status_reason = sqlc.arg(status_reason),
    registry_version = sqlc.arg(registry_version), updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: AllUASFacts :many
-- What the projection holds of every aircraft (identify.UASFacts).
SELECT id, serial, serial_fold, COALESCE(registration_mark, model, '')::text AS label,
       status, operator_id, registry_version
FROM uas ORDER BY id;

-- name: InsertPilot :one
INSERT INTO remote_pilots (
    id, operator_id, person_ref_hash, person_ref_last4, pii_key_id, name_enc, status, status_reason,
    registry_version, created_at, created_by, updated_at, updated_by
) VALUES (
    sqlc.arg(id), sqlc.narg(operator_id), sqlc.arg(person_ref_hash), sqlc.arg(person_ref_last4),
    sqlc.arg(pii_key_id), sqlc.arg(name_enc), sqlc.arg(status), sqlc.arg(status_reason),
    sqlc.arg(registry_version), sqlc.arg(created_at), sqlc.arg(created_by), sqlc.arg(created_at), sqlc.arg(created_by)
)
RETURNING *;

-- name: PilotByID :one
SELECT * FROM remote_pilots WHERE id = sqlc.arg(id);

-- name: PilotForUpdate :one
SELECT * FROM remote_pilots WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: PilotByPersonRef :one
SELECT * FROM remote_pilots WHERE person_ref_hash = sqlc.arg(person_ref_hash);

-- name: ListPilots :many
SELECT * FROM remote_pilots
WHERE (sqlc.narg(operator_id)::text IS NULL OR operator_id = sqlc.narg(operator_id))
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status))
  AND id > sqlc.arg(after_id)
ORDER BY id
LIMIT sqlc.arg(page_size);

-- name: UpdatePilot :one
UPDATE remote_pilots SET
    operator_id = sqlc.narg(operator_id),
    pii_key_id = sqlc.arg(pii_key_id),
    name_enc = sqlc.arg(name_enc),
    registry_version = sqlc.arg(registry_version),
    updated_at = sqlc.arg(updated_at),
    updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetPilotStatus :one
UPDATE remote_pilots SET
    status = sqlc.arg(status), status_reason = sqlc.arg(status_reason),
    registry_version = sqlc.arg(registry_version), updated_at = sqlc.arg(updated_at), updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: UpsertCompetency :one
INSERT INTO pilot_competencies (pilot_id, competency, certificate_ref, valid_until, recorded_at, recorded_by)
VALUES (sqlc.arg(pilot_id), sqlc.arg(competency), sqlc.arg(certificate_ref), sqlc.arg(valid_until),
        sqlc.arg(recorded_at), sqlc.arg(recorded_by))
ON CONFLICT (pilot_id, competency) DO UPDATE SET
    certificate_ref = EXCLUDED.certificate_ref, valid_until = EXCLUDED.valid_until,
    recorded_at = EXCLUDED.recorded_at, recorded_by = EXCLUDED.recorded_by
RETURNING *;

-- name: CompetenciesOf :many
SELECT * FROM pilot_competencies WHERE pilot_id = sqlc.arg(pilot_id) ORDER BY competency;

-- name: InsertStatusChange :one
INSERT INTO registry_status_changes (entity_type, entity_id, public_key, status, at)
VALUES (sqlc.arg(entity_type), sqlc.arg(entity_id), sqlc.arg(public_key), sqlc.arg(status), sqlc.arg(at))
RETURNING seq;

-- name: ListStatusChanges :many
SELECT * FROM registry_status_changes WHERE seq > sqlc.arg(since) ORDER BY seq LIMIT sqlc.arg(page_size);

-- name: LastStatusChange :one
SELECT COALESCE(max(seq), 0)::bigint AS seq FROM registry_status_changes;
