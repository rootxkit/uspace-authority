-- WP-3: the registry of UAS operators, UAS and remote pilots (spec 03 §1,
-- 2019/947 Art. 14(2)-(3), docs/PLAN.md §4.1), the F8 change feed and
-- the registration-number format of authority_policy (G-07, INV-03).
--
-- Registration numbers and serials are validated by uspace-core regnum
-- and serial before they reach these tables; the CHECKs here only
-- refuse what no validation could have let through (a hyphen in a
-- registered number, a serial with surrounding space).
--
-- uas_operators holds the Art. 14(2) field set. registration_number_key
-- is the compare key (regnum.CompareKey: the public part with its ASCII
-- letters upper-cased, G-04, G-12) and is unique, so two spellings of one
-- number cannot both be registered. The EU secret part is never stored in
-- clear: secret_part_hash is an HMAC-SHA-256 under the registry hash key
-- of a per-row salt and the three characters (spec 06 §5). Every personal
-- column (*_enc) is AES-256-GCM sealed under the PII key named by
-- pii_key_id, bound to its row and column (internal/pii, D9).
--
-- uas keeps the serial as given (G-05) and its ASCII fold (serial.FoldKey,
-- G-12). The brief's uniqueness is (manufacturer_code, serial), the code
-- being the first four characters of a CTA-2063-A serial and the serial
-- itself otherwise; serial_fold is unique as well, because a second
-- aircraft whose serial differs only by case would make every folded
-- lookup of either ambiguous (identify.MatchAmbiguous): the registry
-- refuses it instead of registering an aircraft nobody can identify.
--
-- remote_pilots keeps a pilot's national id as a keyed hash plus its last
-- four characters (spec 06 §5) and the name sealed; pilot_competencies
-- holds one row per competency (A1_A3, A2, STS_01, STS_02, national_*).
--
-- Rows are never deleted (no DELETE grant): a registration ends as
-- revoked or expired. Every status change also lands in
-- registry_status_changes, the F8 change feed of ids and statuses only.
-- registry_version_seq numbers every change; the projection rows in the
-- telemetry database carry the version of the change that wrote them.

-- +goose Up
ALTER TABLE authority_policy
    ADD COLUMN registration_number_pattern text NOT NULL DEFAULT '^[A-Z]{3}[A-Za-z0-9]{8,16}$',
    ADD CONSTRAINT authority_policy_registration_pattern CHECK (
        registration_number_pattern <> '' AND length(registration_number_pattern) <= 256
    );

CREATE SEQUENCE registry_version_seq AS bigint MINVALUE 1;

CREATE TABLE uas_operators (
    id                              text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    operator_type                   text        NOT NULL CHECK (operator_type IN ('natural', 'legal')),
    registration_number_public      text        NOT NULL
        CHECK (registration_number_public <> '' AND strpos(registration_number_public, '-') = 0
               AND registration_number_public = btrim(registration_number_public)),
    registration_number_key         text        NOT NULL UNIQUE,
    secret_part_salt                bytea,
    secret_part_hash                text        CHECK (secret_part_hash ~ '^[0-9a-f]{64}$'),
    pii_key_id                      text        NOT NULL,
    full_name_enc                   bytea,
    legal_name_enc                  bytea,
    date_of_birth_enc               bytea,
    legal_identification_number_enc bytea,
    postal_address_enc              bytea       NOT NULL,
    contact_email_enc               bytea       NOT NULL,
    contact_phone_enc               bytea       NOT NULL,
    insurance_policy_number_enc     bytea,
    competency_confirmation         boolean     NOT NULL DEFAULT false,
    authorisations                  jsonb       NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(authorisations) = 'array'),
    status                          text        NOT NULL CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    status_reason                   text        NOT NULL DEFAULT '',
    valid_from                      timestamptz NOT NULL,
    valid_until                     timestamptz NOT NULL,
    source                          text        NOT NULL CHECK (source IN ('portal', 'uas_gov_ge_import', 'manual')),
    registry_version                bigint      NOT NULL,
    created_at                      timestamptz NOT NULL,
    created_by                      text        NOT NULL,
    updated_at                      timestamptz NOT NULL,
    updated_by                      text        NOT NULL,
    CONSTRAINT uas_operators_validity CHECK (valid_until > valid_from),
    CONSTRAINT uas_operators_secret CHECK ((secret_part_salt IS NULL) = (secret_part_hash IS NULL)),
    CONSTRAINT uas_operators_natural CHECK (
        operator_type <> 'natural' OR (full_name_enc IS NOT NULL AND date_of_birth_enc IS NOT NULL)
    ),
    CONSTRAINT uas_operators_legal CHECK (
        operator_type <> 'legal' OR (legal_name_enc IS NOT NULL AND legal_identification_number_enc IS NOT NULL)
    )
);

CREATE INDEX uas_operators_status_idx ON uas_operators (status, valid_until);

CREATE TABLE uas (
    id                text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    operator_id       text        NOT NULL REFERENCES uas_operators (id),
    serial            text        NOT NULL CHECK (serial <> '' AND serial = btrim(serial)),
    serial_fold       text        NOT NULL UNIQUE,
    manufacturer_code text        NOT NULL,
    registration_mark text,
    manufacturer      text        NOT NULL DEFAULT '',
    model             text        NOT NULL DEFAULT '',
    owner_ref         text,
    class_label       text        CHECK (class_label IN ('C0', 'C1', 'C2', 'C3', 'C4', 'C5', 'C6')),
    mtom_g            integer     CHECK (mtom_g > 0),
    rid_capability    text        NOT NULL CHECK (rid_capability IN ('direct', 'network', 'both', 'none')),
    status            text        NOT NULL CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    status_reason     text        NOT NULL DEFAULT '',
    registered_at     timestamptz NOT NULL,
    registry_version  bigint      NOT NULL,
    created_by        text        NOT NULL,
    updated_at        timestamptz NOT NULL,
    updated_by        text        NOT NULL,
    CONSTRAINT uas_manufacturer_serial UNIQUE (manufacturer_code, serial)
);

CREATE INDEX uas_operator_idx ON uas (operator_id);

CREATE TABLE remote_pilots (
    id               text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    operator_id      text        REFERENCES uas_operators (id),
    person_ref_hash  text        NOT NULL UNIQUE CHECK (person_ref_hash ~ '^[0-9a-f]{64}$'),
    person_ref_last4 text        NOT NULL CHECK (char_length(person_ref_last4) BETWEEN 1 AND 4),
    pii_key_id       text        NOT NULL,
    name_enc         bytea       NOT NULL,
    status           text        NOT NULL CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    status_reason    text        NOT NULL DEFAULT '',
    registry_version bigint      NOT NULL,
    created_at       timestamptz NOT NULL,
    created_by       text        NOT NULL,
    updated_at       timestamptz NOT NULL,
    updated_by       text        NOT NULL
);

CREATE TABLE pilot_competencies (
    pilot_id        text        NOT NULL REFERENCES remote_pilots (id),
    competency      text        NOT NULL
        CHECK (competency IN ('A1_A3', 'A2', 'STS_01', 'STS_02') OR competency ~ '^national_[a-z0-9_]{1,32}$'),
    certificate_ref text        NOT NULL CHECK (certificate_ref <> ''),
    valid_until     timestamptz NOT NULL,
    recorded_at     timestamptz NOT NULL,
    recorded_by     text        NOT NULL,
    PRIMARY KEY (pilot_id, competency)
);

CREATE TABLE registry_status_changes (
    seq         bigserial   PRIMARY KEY,
    entity_type text        NOT NULL CHECK (entity_type IN ('operator', 'uas', 'pilot')),
    entity_id   text        NOT NULL,
    public_key  text        NOT NULL,
    status      text        NOT NULL CHECK (status IN ('active', 'suspended', 'revoked', 'expired')),
    at          timestamptz NOT NULL
);

GRANT USAGE ON SEQUENCE registry_version_seq TO authority_app;
GRANT USAGE ON SEQUENCE registry_status_changes_seq_seq TO authority_app;
GRANT SELECT, INSERT ON uas_operators, uas, remote_pilots, pilot_competencies, registry_status_changes TO authority_app;
-- The identity of an entry (id, number, serial, national id hash, type)
-- never changes; a correction is a revocation and a new registration.
GRANT UPDATE (pii_key_id, full_name_enc, legal_name_enc, date_of_birth_enc, legal_identification_number_enc,
              postal_address_enc, contact_email_enc, contact_phone_enc, insurance_policy_number_enc,
              competency_confirmation, authorisations, status, status_reason, valid_until,
              registry_version, updated_at, updated_by) ON uas_operators TO authority_app;
GRANT UPDATE (registration_mark, manufacturer, model, owner_ref, class_label, mtom_g, rid_capability,
              status, status_reason, registry_version, updated_at, updated_by) ON uas TO authority_app;
GRANT UPDATE (operator_id, pii_key_id, name_enc, status, status_reason, registry_version, updated_at, updated_by)
    ON remote_pilots TO authority_app;
GRANT UPDATE (certificate_ref, valid_until, recorded_at, recorded_by) ON pilot_competencies TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS registry_status_changes;
DROP TABLE IF EXISTS pilot_competencies;
DROP TABLE IF EXISTS remote_pilots;
DROP TABLE IF EXISTS uas;
DROP TABLE IF EXISTS uas_operators;
DROP SEQUENCE IF EXISTS registry_version_seq;
ALTER TABLE authority_policy
    DROP CONSTRAINT IF EXISTS authority_policy_registration_pattern,
    DROP COLUMN IF EXISTS registration_number_pattern;
