-- WP-6: the F1 publication outbox (00013_publications, 00014_cisp), the
-- F3 subscriber cache and the delivery-id replay guard (00014_cisp).
-- internal/cisp is the only user.

-- name: LockOutbox :exec
-- Serialises the writes of one dataset's outbox inside a transaction
-- (numbering a publication, superseding the pending one).
SELECT pg_advisory_xact_lock(hashtextextended('cisp/outbox/' || sqlc.arg(dataset)::text, 0));

-- name: NextPublicationVersion :one
-- The next version of a dataset its owner does not number (the USSP
-- list); zones and U-space airspaces carry their zones version.
SELECT (coalesce(max(version), 0) + 1)::bigint AS version FROM publications WHERE dataset = sqlc.arg(dataset);

-- name: SupersedePendingOutbox :many
-- One pending snapshot per dataset (E-10): a new one supersedes it. A
-- row in flight (sent) is not superseded: it runs to its answer first.
UPDATE publications SET state = 'superseded', state_changed_at = now()
WHERE dataset = sqlc.arg(dataset) AND state = 'pending'
RETURNING id, version, resolves_conflict;

-- name: InsertOutboxRow :one
INSERT INTO publications (dataset, version, payload, payload_hash, feature_count, content_type, signature,
                          signature_kid, signed_at, created_by, resolves_conflict)
VALUES (sqlc.arg(dataset), sqlc.arg(version), sqlc.arg(payload), sqlc.arg(payload_hash), sqlc.arg(feature_count),
        sqlc.arg(content_type), sqlc.narg(signature), sqlc.narg(signature_kid), sqlc.narg(signed_at),
        sqlc.arg(created_by), sqlc.arg(resolves_conflict))
RETURNING id, dataset, version, payload_hash, feature_count, signature, state, created_at;

-- name: DuePublications :many
-- The first unfinished row of every dataset (the outbox is delivered in
-- order per dataset), with its payload. A row behind a conflict waits
-- for an operator (audit A-S2): it is due only when it resolves the
-- conflict itself, or a row after the conflict was acknowledged or
-- resolved it.
SELECT DISTINCT ON (p.dataset) p.id, p.dataset, p.version, p.payload, p.payload_hash, p.feature_count, p.content_type,
       p.state, p.attempts, p.next_retry_at, p.created_at
FROM publications p
WHERE p.state IN ('pending', 'sent')
  AND (p.resolves_conflict OR NOT EXISTS (
        SELECT 1 FROM publications c
        WHERE c.dataset = p.dataset AND c.id < p.id AND c.state = 'conflict'
          AND NOT EXISTS (
                SELECT 1 FROM publications a
                WHERE a.dataset = p.dataset AND a.id > c.id AND a.id < p.id
                  AND (a.state = 'acknowledged' OR a.resolves_conflict))))
ORDER BY p.dataset, p.id;

-- name: IfMatchVersion :one
-- The version the CISP holds as far as this outbox knows: that of the
-- newest earlier row of the dataset the CISP acknowledged, or whose 412
-- showed the CISP's version (an operator's publication after a
-- conflict is sent against the version the conflict showed).
SELECT coalesce(cisp_version, conflict_version)::bigint AS version
FROM publications
WHERE dataset = sqlc.arg(dataset) AND id < sqlc.arg(before)
  AND (cisp_version IS NOT NULL OR conflict_version IS NOT NULL)
ORDER BY id DESC LIMIT 1;

-- name: MarkPublicationSending :execrows
UPDATE publications
SET state = 'sent', attempts = attempts + 1, last_attempt_at = now(), signature = sqlc.arg(signature),
    signature_kid = sqlc.arg(signature_kid), signed_at = sqlc.arg(signed_at), state_changed_at = now()
WHERE id = sqlc.arg(id) AND state IN ('pending', 'sent');

-- name: MarkPublicationAcknowledged :execrows
UPDATE publications
SET state = 'acknowledged', cisp_version = sqlc.arg(cisp_version), acknowledged_at = now(),
    last_status = sqlc.arg(last_status), last_error = NULL, next_retry_at = NULL, state_changed_at = now()
WHERE id = sqlc.arg(id) AND state = 'sent';

-- name: MarkPublicationRetry :execrows
UPDATE publications
SET state = 'pending', next_retry_at = sqlc.arg(next_retry_at), last_status = sqlc.narg(last_status),
    last_error = sqlc.arg(last_error), state_changed_at = now()
WHERE id = sqlc.arg(id) AND state = 'sent';

-- name: MarkPublicationFailed :execrows
UPDATE publications
SET state = 'failed', next_retry_at = NULL, last_status = sqlc.narg(last_status), last_error = sqlc.arg(last_error),
    state_changed_at = now()
WHERE id = sqlc.arg(id) AND state IN ('pending', 'sent');

-- name: MarkPublicationConflict :execrows
UPDATE publications
SET state = 'conflict', next_retry_at = NULL, conflict_version = sqlc.narg(conflict_version),
    last_status = sqlc.arg(last_status), last_error = sqlc.arg(last_error), state_changed_at = now()
WHERE id = sqlc.arg(id) AND state = 'sent';

-- name: ListPublications :many
-- The outbox for the console, newest first, without payloads; the age
-- is on the database clock.
SELECT id, dataset, version, payload_hash, feature_count, content_type, signature_kid, signed_at, state, attempts,
       next_retry_at, cisp_version, conflict_version, last_attempt_at, last_status, last_error, acknowledged_at,
       created_at, created_by, state_changed_at,
       extract(epoch FROM now() - created_at)::double precision AS age_s
FROM publications
WHERE (sqlc.narg(dataset)::text IS NULL OR dataset = sqlc.narg(dataset)::text)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: UpsertCISCache :execrows
-- Stores a verified version; an older one never replaces a newer one
-- (two api replicas pulling at once).
INSERT INTO cis_cache (dataset, version, etag, cis_updated_at, fetched_at, checked_at, feature_count, publisher_kid, payload)
VALUES (sqlc.arg(dataset), sqlc.arg(version), sqlc.arg(etag), sqlc.narg(cis_updated_at), now(), now(),
        sqlc.arg(feature_count), sqlc.narg(publisher_kid), sqlc.arg(payload))
ON CONFLICT (dataset) DO UPDATE SET
    version = EXCLUDED.version, etag = EXCLUDED.etag, cis_updated_at = EXCLUDED.cis_updated_at,
    fetched_at = EXCLUDED.fetched_at, checked_at = EXCLUDED.checked_at, feature_count = EXCLUDED.feature_count,
    publisher_kid = EXCLUDED.publisher_kid, payload = EXCLUDED.payload
WHERE cis_cache.version <= EXCLUDED.version;

-- name: TouchCISCache :execrows
-- The CISP confirmed the version held (a 304, or the same ETag).
UPDATE cis_cache SET checked_at = now() WHERE dataset = sqlc.arg(dataset) AND version = sqlc.arg(version);

-- name: LoadCISCache :many
-- Every cached dataset with its age on the database clock.
SELECT dataset, version, etag, cis_updated_at, fetched_at, checked_at, feature_count, publisher_kid, payload,
       extract(epoch FROM now() - checked_at)::double precision AS age_s
FROM cis_cache ORDER BY dataset;

-- name: RememberDeliveryJTI :one
-- Records a verified delivery id for ttl_s seconds. inserted is 1 for a
-- fresh id; 0 with seen for a replay; 0 without seen when max_live ids
-- of this issuer were already live (nothing written). The bound is per
-- issuer, so one issuer's flood never refuses another's deliveries.
WITH live AS (
    SELECT count(*) AS n FROM cis_delivery_jtis WHERE issuer = sqlc.arg(issuer)::text AND expires_at > now()
), ins AS (
    INSERT INTO cis_delivery_jtis (issuer, jti, expires_at)
    SELECT sqlc.arg(issuer)::text, sqlc.arg(jti)::text, now() + make_interval(secs => sqlc.arg(ttl_s)::double precision)
    FROM live WHERE live.n < sqlc.arg(max_live)::bigint
    ON CONFLICT (issuer, jti) DO NOTHING
    RETURNING 1
)
SELECT (SELECT count(*) FROM ins)::bigint AS inserted,
       EXISTS (SELECT 1 FROM cis_delivery_jtis d WHERE d.issuer = sqlc.arg(issuer)::text AND d.jti = sqlc.arg(jti)::text) AS seen;

-- name: SweepDeliveryJTIs :execrows
DELETE FROM cis_delivery_jtis WHERE expires_at <= now();
