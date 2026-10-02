-- WP-7: the Remote ID receiver registry (spec 02 F9, 03 §1 rid_receivers,
-- 06 §2 T2, docs/PLAN.md §4.1, LESSONS R-06, B-10, B-11, B-14).
--
-- A receiver authenticates every request with two separate secrets: a
-- bearer key that names it (stored only as an argon2id hash, key_hash)
-- and an HMAC-SHA256 secret over the exact body bytes (hmac_secret_enc,
-- 32 random bytes sealed with the PII key under pii_key_id and bound to
-- the row and generation, internal/pii). Both are generated here and
-- shown once, at creation and at each rotation. A rotation keeps the
-- previous generation (prev_*) until prev_valid_until, so a receiver can
-- be re-flashed without a gap; only one previous generation is kept.
--
-- geom is the pinned position the heartbeat's reported position is
-- compared with (T2); lat_deg and lon_deg are the values as given and
-- geom is derived from them (SRID 4326), so the two cannot disagree.
-- A deviation beyond the receiver's tolerance is counted in
-- position_deviations and its size kept in position_deviation_m.
--
-- status is the registry's switch of one receiver (enabled/disabled),
-- with who and why (B-11: disabled is not silent). The source-control
-- switches of WP-10 (source_controls, direct_rid by type and instance)
-- are separate and also refuse an observation with 503 (B-10).
--
-- Every change is an events row written in the same transaction
-- (internal/receivers); rows are deleted only by the audited delete.

-- +goose Up
CREATE TABLE rid_receivers (
    id                   text             PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    name                 text             NOT NULL CHECK (name <> '' AND length(name) <= 200),
    lat_deg              double precision NOT NULL CHECK (lat_deg BETWEEN -90 AND 90),
    lon_deg              double precision NOT NULL CHECK (lon_deg BETWEEN -180 AND 180),
    geom                 geometry(Point, 4326) GENERATED ALWAYS AS (ST_SetSRID(ST_MakePoint(lon_deg, lat_deg), 4326)) STORED,
    owner                text             NOT NULL CHECK (owner IN ('authority', 'third_party')),
    owner_name           text             CHECK (owner_name IS NULL OR length(owner_name) <= 200),
    key_generation       integer          NOT NULL CHECK (key_generation >= 1),
    key_hash             text             NOT NULL CHECK (key_hash LIKE '$argon2id$%'),
    pii_key_id           text             NOT NULL,
    hmac_secret_enc      bytea            NOT NULL,
    prev_key_hash        text             CHECK (prev_key_hash IS NULL OR prev_key_hash LIKE '$argon2id$%'),
    prev_pii_key_id      text,
    prev_hmac_secret_enc bytea,
    prev_valid_until     timestamptz,
    status               text             NOT NULL CHECK (status IN ('enabled', 'disabled')),
    disabled_by          text,
    disabled_reason      text,
    disabled_at          timestamptz,
    last_seen_at         timestamptz,
    last_lat_deg         double precision,
    last_lon_deg         double precision,
    last_alt_hae_m       double precision,
    position_deviation_m double precision,
    position_deviations  bigint           NOT NULL DEFAULT 0 CHECK (position_deviations >= 0),
    firmware             text             CHECK (firmware IS NULL OR length(firmware) <= 100),
    config               jsonb            NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config) = 'object'),
    version              bigint           NOT NULL DEFAULT 1,
    created_at           timestamptz      NOT NULL,
    created_by           text             NOT NULL,
    updated_at           timestamptz      NOT NULL,
    updated_by           text             NOT NULL,
    CONSTRAINT rid_receivers_disabled_says_who CHECK (
        (status = 'enabled' AND disabled_by IS NULL AND disabled_at IS NULL)
        OR (status = 'disabled' AND disabled_by IS NOT NULL AND disabled_at IS NOT NULL)
    ),
    CONSTRAINT rid_receivers_previous_whole CHECK (
        (prev_key_hash IS NULL AND prev_pii_key_id IS NULL AND prev_hmac_secret_enc IS NULL AND prev_valid_until IS NULL)
        OR (prev_key_hash IS NOT NULL AND prev_pii_key_id IS NOT NULL AND prev_hmac_secret_enc IS NOT NULL
            AND prev_valid_until IS NOT NULL)
    ),
    CONSTRAINT rid_receivers_last_position_whole CHECK ((last_lat_deg IS NULL) = (last_lon_deg IS NULL))
);

CREATE INDEX rid_receivers_geom_idx ON rid_receivers USING gist (geom);

GRANT SELECT, INSERT, DELETE ON rid_receivers TO authority_app;
-- id and created_* never change; a receiver moved to another
-- slug is a new receiver.
GRANT UPDATE (name, lat_deg, lon_deg, owner, owner_name, key_generation, key_hash, pii_key_id, hmac_secret_enc,
              prev_key_hash, prev_pii_key_id, prev_hmac_secret_enc, prev_valid_until, status, disabled_by,
              disabled_reason, disabled_at, last_seen_at, last_lat_deg, last_lon_deg, last_alt_hae_m,
              position_deviation_m, position_deviations, firmware, config, version, updated_at, updated_by)
    ON rid_receivers TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS rid_receivers;
