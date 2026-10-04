-- WP-20: the registration applications, the portal's mail outbox, its
-- rate budget and its spent links (migration 00023_registry_portal).

-- name: PortalHits :one
-- Requests counted in bucket for key_hash within the window, by the
-- database clock, and when the oldest of them leaves it.
SELECT count(*)::bigint AS n,
       COALESCE(EXTRACT(EPOCH FROM (min(at) + make_interval(secs => sqlc.arg(window_s)::float8) - now())), 0)::float8 AS frees_in_s
FROM registry_portal_hits
WHERE bucket = sqlc.arg(bucket) AND key_hash = sqlc.arg(key_hash)
  AND at > now() - make_interval(secs => sqlc.arg(window_s)::float8);

-- name: InsertPortalHit :exec
INSERT INTO registry_portal_hits (bucket, key_hash) VALUES (sqlc.arg(bucket), sqlc.arg(key_hash));

-- name: PurgePortalHits :execrows
DELETE FROM registry_portal_hits WHERE at < now() - make_interval(secs => sqlc.arg(older_than_s)::float8);

-- name: InsertApplication :one
INSERT INTO registry_applications (
    id, kind, state, operator_type, lang, pii_key_id, payload_enc, remote_ip_hash, verify_expires_at
) VALUES (
    sqlc.arg(id), 'operator_registration', 'unverified', sqlc.arg(operator_type), sqlc.arg(lang), sqlc.arg(pii_key_id),
    sqlc.arg(payload_enc), sqlc.arg(remote_ip_hash), now() + make_interval(secs => sqlc.arg(verify_ttl_s)::float8)
)
RETURNING *;

-- name: ApplicationByID :one
SELECT * FROM registry_applications WHERE id = sqlc.arg(id);

-- name: ApplicationForUpdate :one
SELECT * FROM registry_applications WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: ListApplications :many
-- One page, oldest submitted first, after (submitted_at, id); state
-- filters when given.
SELECT id, kind, state, operator_type, lang, submitted_at, verified_at, registrar_id, review_started_at, decided_at,
       refusal_reason, issued_number, operator_id, valid_until
FROM registry_applications
WHERE (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state))
  AND (submitted_at, id) > (sqlc.arg(after_at)::timestamptz, sqlc.arg(after_id)::text)
ORDER BY submitted_at, id
LIMIT sqlc.arg(page_size);

-- name: VerifyApplication :one
-- The e-mail link followed in time: unverified -> submitted. No row when
-- the application is not unverified or its link expired (database clock).
UPDATE registry_applications SET state = 'submitted', verified_at = now()
WHERE id = sqlc.arg(id) AND state = 'unverified' AND verify_expires_at > now()
RETURNING *;

-- name: StartApplicationReview :one
UPDATE registry_applications SET state = 'under_review', registrar_id = sqlc.arg(registrar_id), review_started_at = now()
WHERE id = sqlc.arg(id) AND state = 'submitted'
RETURNING *;

-- name: SetApplicationIssuedNumber :one
-- The number chosen for an approval, with its secret part sealed until
-- the approval commits; set once.
UPDATE registry_applications SET issued_number = sqlc.arg(issued_number), secret_enc = sqlc.arg(secret_enc),
    valid_until = sqlc.arg(valid_until)
WHERE id = sqlc.arg(id) AND state = 'under_review' AND issued_number IS NULL
RETURNING *;

-- name: ClearApplicationIssuedNumber :exec
-- A chosen number another registration took meanwhile: chosen again on
-- the next approval.
UPDATE registry_applications SET issued_number = NULL, secret_enc = NULL, valid_until = NULL
WHERE id = sqlc.arg(id) AND state = 'under_review' AND operator_id IS NULL;

-- name: ApproveApplication :one
UPDATE registry_applications SET state = 'approved', operator_id = sqlc.arg(operator_id), decided_at = now(),
    registrar_id = sqlc.arg(registrar_id), secret_enc = NULL
WHERE id = sqlc.arg(id) AND state = 'under_review'
RETURNING *;

-- name: RefuseApplication :one
-- A refusal drops what a half-finished approval chose (the number, its
-- sealed secret part and the validity): a refused application has none,
-- and the secret part is kept only for an approval under review.
UPDATE registry_applications SET state = 'refused', refusal_reason = sqlc.arg(refusal_reason), decided_at = now(),
    registrar_id = sqlc.arg(registrar_id), review_started_at = COALESCE(review_started_at, now()),
    issued_number = NULL, secret_enc = NULL, valid_until = NULL
WHERE id = sqlc.arg(id) AND state IN ('submitted', 'under_review')
RETURNING *;

-- name: PurgeApplications :many
-- Decided applications older than the retention, and unverified ones
-- whose link expired that long ago; their mail rows go with them.
DELETE FROM registry_applications
WHERE id IN (
    SELECT a.id FROM registry_applications a
    WHERE (a.state IN ('approved', 'refused') AND a.decided_at < now() - make_interval(secs => sqlc.arg(retain_s)::float8))
       OR (a.state = 'unverified' AND a.verify_expires_at < now() - make_interval(secs => sqlc.arg(unverified_grace_s)::float8))
    ORDER BY a.id
    LIMIT sqlc.arg(batch)
)
RETURNING id, state;

-- name: InsertPortalMail :one
INSERT INTO registry_portal_mail (kind, application_id, lang, pii_key_id, message_enc)
VALUES (sqlc.arg(kind), sqlc.narg(application_id), sqlc.arg(lang), sqlc.arg(pii_key_id), sqlc.arg(message_enc))
RETURNING id;

-- name: ClaimPortalMail :one
-- Takes the oldest message due now (database clock) and moves its next
-- attempt lease_s ahead in the same statement, which commits on its own:
-- the delivery runs outside any transaction, and another replica skips
-- the message until the lease ends (a crash during the delivery sends it
-- again then). No row when nothing is due.
UPDATE registry_portal_mail SET next_attempt_at = now() + make_interval(secs => sqlc.arg(lease_s)::float8)
WHERE id = (
    SELECT d.id FROM registry_portal_mail d
    WHERE d.sent_at IS NULL AND d.failed_at IS NULL AND d.next_attempt_at <= now()
    ORDER BY d.next_attempt_at, d.id
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- name: PortalMailSent :exec
UPDATE registry_portal_mail SET sent_at = now(), message_enc = NULL, attempts = attempts + 1, last_error = NULL
WHERE id = sqlc.arg(id) AND sent_at IS NULL AND failed_at IS NULL;

-- name: PortalMailRetry :exec
UPDATE registry_portal_mail SET attempts = attempts + 1, last_error = sqlc.arg(last_error),
    next_attempt_at = now() + make_interval(secs => sqlc.arg(retry_in_s)::float8)
WHERE id = sqlc.arg(id) AND sent_at IS NULL AND failed_at IS NULL;

-- name: PortalMailFailed :exec
UPDATE registry_portal_mail SET failed_at = now(), message_enc = NULL, attempts = attempts + 1, last_error = sqlc.arg(last_error)
WHERE id = sqlc.arg(id) AND sent_at IS NULL AND failed_at IS NULL;

-- name: PurgePortalMail :execrows
-- Delivered or failed messages without an application, older than the
-- retention (their content is gone already).
DELETE FROM registry_portal_mail
WHERE application_id IS NULL AND (sent_at IS NOT NULL OR failed_at IS NOT NULL)
  AND created_at < now() - make_interval(secs => sqlc.arg(retain_s)::float8);

-- name: PortalMailBacklog :one
SELECT count(*)::bigint AS pending,
       COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at))), 0)::float8 AS oldest_s
FROM registry_portal_mail WHERE sent_at IS NULL AND failed_at IS NULL;

-- name: SpendPortalLink :one
-- Spends an operator link once: a second use, or a use after its expiry
-- (database clock), inserts nothing and answers spent = false.
WITH ins AS (
    INSERT INTO registry_portal_links_used (link_id, expires_at)
    SELECT sqlc.arg(link_id), sqlc.arg(expires_at)::timestamptz
    WHERE sqlc.arg(expires_at)::timestamptz > now()
    ON CONFLICT (link_id) DO NOTHING
    RETURNING link_id
)
SELECT EXISTS (SELECT 1 FROM ins) AS spent;

-- name: PurgePortalLinks :execrows
DELETE FROM registry_portal_links_used WHERE expires_at < now() - make_interval(secs => sqlc.arg(grace_s)::float8);
