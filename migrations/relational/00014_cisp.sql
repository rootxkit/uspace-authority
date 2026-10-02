-- WP-6: the CISP client (spec 02 F1, F3; docs/PLAN.md §4.1).
--
-- publications, created minimal by WP-5 (00013), gains what its sender
-- needs: the signing key and instant of the detached JWS (re-signed at
-- every attempt, because the CISP holds iat to five minutes), the
-- media type of the payload, when the state last changed (the
-- console's "not yet published" age), the last attempt's status and
-- error, the CISP's current version seen on a 412 (the If-Match of the
-- operator's next publication after a conflict) and when the CISP
-- acknowledged it. States: pending (waiting to be sent, or to be sent
-- again at next_retry_at), sent (a PUT in flight), acknowledged,
-- failed (given up, with the reason), conflict (the CISP holds another
-- version: an operator decides), superseded (replaced by a newer
-- pending snapshot of the dataset before it was sent).
--
-- cis_cache is the subscriber's state (F3): per dataset the newest
-- version whose publisher's signature verified, its ETag, when its
-- content was fetched and when the CISP last confirmed it (the age of
-- cis_age_s), and the payload as served.
--
-- cis_delivery_jtis is the replay guard of POST /v1/cis/notifications:
-- the delivery ids (jti) of verified notifications per issuer until
-- they expire, bounded by the receiver (E-10).

-- +goose Up
ALTER TABLE publications
    ADD COLUMN content_type     text        NOT NULL DEFAULT 'application/geo+json'
        CHECK (content_type IN ('application/geo+json', 'application/json')),
    ADD COLUMN signature_kid    text,
    ADD COLUMN signed_at        timestamptz,
    ADD COLUMN state_changed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN last_attempt_at  timestamptz,
    ADD COLUMN last_status      integer,
    ADD COLUMN last_error       text CHECK (octet_length(last_error) <= 2000),
    ADD COLUMN conflict_version bigint CHECK (conflict_version >= 0),
    ADD COLUMN acknowledged_at  timestamptz;

CREATE INDEX publications_due_idx ON publications (dataset, id) WHERE state IN ('pending', 'sent');

GRANT UPDATE (signature_kid, signed_at, state_changed_at, last_attempt_at, last_status, last_error,
              conflict_version, acknowledged_at) ON publications TO authority_app;

CREATE TABLE cis_cache (
    dataset        text        PRIMARY KEY CHECK (dataset IN ('zones', 'uspace_airspace', 'ussp_list', 'restrictions')),
    version        bigint      NOT NULL CHECK (version >= 0),
    etag           text        NOT NULL,
    cis_updated_at timestamptz,
    fetched_at     timestamptz NOT NULL,
    checked_at     timestamptz NOT NULL,
    feature_count  integer     NOT NULL CHECK (feature_count >= 0),
    publisher_kid  text,
    payload        jsonb       NOT NULL
);

GRANT SELECT, INSERT, UPDATE ON cis_cache TO authority_app;

CREATE TABLE cis_delivery_jtis (
    issuer      text        NOT NULL,
    jti         text        NOT NULL CHECK (octet_length(jti) BETWEEN 1 AND 256),
    received_at timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (issuer, jti)
);

CREATE INDEX cis_delivery_jtis_expires_idx ON cis_delivery_jtis (expires_at);

GRANT SELECT, INSERT, DELETE ON cis_delivery_jtis TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS cis_delivery_jtis;
DROP TABLE IF EXISTS cis_cache;
DROP INDEX IF EXISTS publications_due_idx;
ALTER TABLE publications
    DROP COLUMN IF EXISTS acknowledged_at,
    DROP COLUMN IF EXISTS conflict_version,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS last_status,
    DROP COLUMN IF EXISTS last_attempt_at,
    DROP COLUMN IF EXISTS state_changed_at,
    DROP COLUMN IF EXISTS signed_at,
    DROP COLUMN IF EXISTS signature_kid,
    DROP COLUMN IF EXISTS content_type;
