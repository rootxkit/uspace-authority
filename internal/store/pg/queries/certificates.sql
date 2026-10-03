-- WP-16: certificates, operating-status notices and the USSP list
-- publication state (migration 00018_certificates). Every time is the
-- database's clock (now()), never the replica's.

-- name: InsertCertificate :one
INSERT INTO certificates (
    id, holder, holder_name, holder_address, holder_email, holder_phone, holder_url, code, client_id,
    base_url, services, conditions, limitations, terms_url, issued_at, valid_until,
    status_reason, status_changed_at, status_changed_by, lapse_unused_after_months, lapse_ceased_after_months,
    row_version, created_at, created_by, updated_at, updated_by
) VALUES (
    sqlc.arg(id), sqlc.arg(holder), sqlc.arg(holder_name), sqlc.arg(holder_address), sqlc.arg(holder_email),
    sqlc.arg(holder_phone), sqlc.arg(holder_url), sqlc.arg(code), sqlc.arg(client_id),
    sqlc.arg(base_url), sqlc.arg(services)::text[], sqlc.arg(conditions), sqlc.arg(limitations)::text[], sqlc.arg(terms_url),
    sqlc.arg(issued_at), sqlc.arg(valid_until),
    '', now(), sqlc.arg(created_by), sqlc.arg(lapse_unused_after_months), sqlc.arg(lapse_ceased_after_months),
    nextval('certificates_version_seq'), now(), sqlc.arg(created_by), now(), sqlc.arg(created_by)
)
RETURNING *;

-- name: CertificateByID :one
SELECT * FROM certificates WHERE id = sqlc.arg(id);

-- name: CertificateForUpdate :one
-- The row, locked for the transaction that changes it.
SELECT * FROM certificates WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: CertificateCodeTaken :one
SELECT EXISTS (SELECT 1 FROM certificates WHERE code = sqlc.arg(code)) AS taken;

-- name: ListCertificates :many
-- Newest first, at most max_rows, optionally of one holder kind and
-- status.
SELECT * FROM certificates
WHERE (sqlc.narg(holder)::text IS NULL OR holder = sqlc.narg(holder))
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status))
ORDER BY issued_at DESC, id
LIMIT sqlc.arg(max_rows);

-- name: CountCertificates :one
SELECT count(*)::bigint AS n FROM certificates;

-- name: UpdateCertificateDetails :one
-- The fields an admin may correct (PATCH); the status facts are not
-- among them.
UPDATE certificates SET
    holder_name = sqlc.arg(holder_name), holder_address = sqlc.arg(holder_address),
    holder_email = sqlc.arg(holder_email), holder_phone = sqlc.arg(holder_phone), holder_url = sqlc.arg(holder_url),
    base_url = sqlc.arg(base_url), conditions = sqlc.arg(conditions), limitations = sqlc.arg(limitations)::text[],
    terms_url = sqlc.arg(terms_url), valid_until = sqlc.arg(valid_until),
    row_version = nextval('certificates_version_seq'), updated_at = now(), updated_by = sqlc.arg(updated_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetCertificateState :one
-- One transition: the four status facts and the operations times, with
-- who and why.
UPDATE certificates SET
    operations = sqlc.arg(operations), operations_started_at = sqlc.narg(operations_started_at),
    operations_ceased_at = sqlc.narg(operations_ceased_at), limited = sqlc.arg(limited),
    limitations = sqlc.arg(limitations)::text[], suspended = sqlc.arg(suspended),
    ended = sqlc.narg(ended), ended_at = CASE WHEN sqlc.narg(ended)::text IS NULL THEN NULL ELSE now() END,
    status_reason = sqlc.arg(status_reason), status_changed_at = now(), status_changed_by = sqlc.arg(changed_by),
    row_version = nextval('certificates_version_seq'), updated_at = now(), updated_by = sqlc.arg(changed_by)
WHERE id = sqlc.arg(id)
RETURNING *;

-- name: SetCertificateClientStatus :one
-- The certificate's client follows it (06 §2 T9): suspended with a
-- suspension, revoked when the certificate ends, active on
-- reinstatement. Returns the status before.
WITH b AS (SELECT o.client_id AS id, o.status AS before FROM oauth_clients o WHERE o.client_id = sqlc.arg(client_id) FOR UPDATE)
UPDATE oauth_clients c SET status = sqlc.arg(status), updated_at = now(), updated_by = sqlc.arg(updated_by)
FROM b
WHERE c.client_id = b.id
RETURNING b.before;

-- name: InsertCertificateNotice :one
INSERT INTO certificate_notices (certificate_id, state, at, reference, source, recorded_by)
VALUES (sqlc.arg(certificate_id), sqlc.arg(state), sqlc.arg(at), sqlc.narg(reference), sqlc.arg(source), sqlc.arg(recorded_by))
RETURNING *;

-- name: CertificateNoticeByReference :one
SELECT * FROM certificate_notices WHERE certificate_id = sqlc.arg(certificate_id) AND reference = sqlc.arg(reference);

-- name: ListCertificateNotices :many
SELECT * FROM certificate_notices WHERE certificate_id = sqlc.arg(certificate_id) ORDER BY id DESC LIMIT sqlc.arg(max_rows);

-- name: CertificateRegister :many
-- The public register (Art. 18(a)): every certificate not ended, and an
-- ended one for a year after it ended, newest first.
SELECT id, holder, holder_name, code, services, status, issued_at, valid_until, limitations, ended_at
FROM certificates
WHERE ended IS NULL OR ended_at > now() - interval '1 year'
ORDER BY holder, holder_name, id
LIMIT sqlc.arg(max_rows);

-- name: ListedUSSPCertificates :many
-- What the USSP list carries (02 F1): USSP certificates operating or
-- limited whose holder has started and not ceased operations, within
-- their validity, by code.
SELECT * FROM certificates
WHERE holder = 'ussp' AND status IN ('operating', 'limited') AND operations = 'operating'
  AND issued_at <= now() AND valid_until > now()
ORDER BY code
LIMIT sqlc.arg(max_rows);

-- name: CertificateRegisterVersion :one
-- The version of the register as dp-poller follows it.
SELECT COALESCE(max(row_version), 0)::bigint AS version FROM certificates;

-- name: LapseUnusedCertificates :many
-- Art. 16(2): issued and not used within lapse_unused_after_months of
-- issue. The rule is named in status_reason.
UPDATE certificates SET
    ended = 'lapsed', ended_at = now(), status_reason = sqlc.arg(reason),
    status_changed_at = now(), status_changed_by = sqlc.arg(changed_by),
    row_version = nextval('certificates_version_seq'), updated_at = now(), updated_by = sqlc.arg(changed_by)
WHERE ended IS NULL AND operations = 'not_started'
  AND issued_at + make_interval(months => lapse_unused_after_months) <= now()
RETURNING *;

-- name: LapseCeasedCertificates :many
-- Art. 16(2): operations ceased for lapse_ceased_after_months.
UPDATE certificates SET
    ended = 'lapsed', ended_at = now(), status_reason = sqlc.arg(reason),
    status_changed_at = now(), status_changed_by = sqlc.arg(changed_by),
    row_version = nextval('certificates_version_seq'), updated_at = now(), updated_by = sqlc.arg(changed_by)
WHERE ended IS NULL AND operations = 'ceased'
  AND operations_ceased_at + make_interval(months => lapse_ceased_after_months) <= now()
RETURNING *;

-- name: RevokeCertificateClients :exec
-- The clients of the certificates that ended: revoked.
UPDATE oauth_clients SET status = 'revoked', updated_at = now(), updated_by = sqlc.arg(updated_by)
WHERE client_id = ANY(sqlc.arg(client_ids)::text[]) AND status <> 'revoked';

-- name: WantUSSPList :one
-- A transition changed the USSP list: one more version is wanted.
UPDATE certificate_list_state SET wanted = wanted + 1 WHERE id RETURNING wanted;

-- name: USSPListState :one
SELECT wanted, enqueued, enqueued_at, last_attempt_at, last_error, listed_digest FROM certificate_list_state WHERE id;

-- name: USSPListEnqueued :exec
-- The list built while the counter stood at wanted is in the outbox.
UPDATE certificate_list_state SET enqueued = GREATEST(enqueued, sqlc.arg(wanted)), enqueued_at = now(),
    last_attempt_at = now(), last_error = '', listed_digest = sqlc.arg(listed_digest)
WHERE id;

-- name: USSPListFailed :exec
UPDATE certificate_list_state SET last_attempt_at = now(), last_error = left(sqlc.arg(error), 1000) WHERE id;
