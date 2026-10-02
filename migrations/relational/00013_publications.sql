-- WP-5: the F1 publication outbox, in the minimal shape docs/PLAN.md
-- §4.1 gives it (dataset, version, payload_hash, signature, state,
-- attempts, next_retry_at, cisp_version). WP-6 owns the table and its
-- sender: it signs the payload (a detached JWS) and delivers it to the
-- CISP. Until it does, POST /v1/zones/publish and /v1/uspace/publish
-- write their row here with state 'pending' and signature NULL; nothing
-- reads a pending row yet, so no unsigned payload ever leaves.
--
-- payload is the exact bytes of the published ED-318 FeatureCollection
-- (the signature is over bytes, not over a JSON value), at most 4 MiB:
-- what uspace-core ed318.Parse at the CISP accepts by default. A new
-- pending row of a dataset supersedes the older pending one (E-10: one
-- pending snapshot per dataset).

-- +goose Up
CREATE TABLE publications (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dataset       text        NOT NULL CHECK (dataset IN ('zones', 'uspace_airspace', 'ussp_list')),
    version       bigint      NOT NULL,
    payload       bytea       NOT NULL CHECK (octet_length(payload) <= 4194304),
    payload_hash  text        NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    feature_count integer     NOT NULL CHECK (feature_count >= 0),
    signature     text,
    state         text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sent', 'acknowledged', 'failed', 'conflict', 'superseded')),
    attempts      integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_retry_at timestamptz,
    cisp_version  bigint,
    created_at    timestamptz NOT NULL DEFAULT now(),
    created_by    text        NOT NULL,
    UNIQUE (dataset, version)
);

CREATE INDEX publications_pending_idx ON publications (dataset, id) WHERE state = 'pending';

GRANT SELECT, INSERT ON publications TO authority_app;
GRANT UPDATE (signature, state, attempts, next_retry_at, cisp_version) ON publications TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS publications;
