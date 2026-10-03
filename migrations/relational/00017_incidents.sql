-- WP-17: incidents and evidence packs (spec 01 A10; 03 §1 incidents,
-- evidence_packs; 05 §4 incidents kept indefinitely, hash-sealed; 06 §2
-- T6, T7; 06 §5; docs/PLAN.md §4.1).
--
-- incidents is the authority's own case file. It is opened from a
-- violation an inspector escalated (source_violation_id, one incident
-- per violation), from the authority's own observation, or from an ANSP
-- or USSP notice; never from an occurrence report (376/2014 Art. 15-16:
-- no column here names one and the occurrences schema of WP-18 grants
-- this role nothing). Every change is an events row written in the
-- transaction that makes it.
--
-- incident_aircraft holds what identified an aircraft at the time:
-- the serial, the operator registration number's PUBLIC part only (the
-- EU secret part is never stored; spec 06 §5), the track ids and the
-- identification as it was judged. incident_notes is append-only.
--
-- evidence_packs is immutable (03 §1): one row per sealed archive, with
-- the SHA-256 of the archive (content_hash), the detached JWS of the
-- seal statement by the publication key (signature, signature_kid; null
-- when no publication key is configured, and the manifest says so), the
-- manifest (no personal data: a legal pack's personal data is inside the
-- archive only, and the archive of a legal pack is sealed at rest with
-- the PII key), where the archive is stored, who built it and why. The
-- hash is also in the evidence_pack_built events row (T7). A trigger
-- refuses UPDATE and DELETE on both append-only tables.

-- +goose Up
CREATE TABLE incidents (
    incident_id         text        PRIMARY KEY CHECK (incident_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    kind                text        NOT NULL CHECK (kind IN ('airprox', 'nonconformance', 'lost_link', 'emergency',
                                                             'violation_escalated', 'other')),
    occurred_at         timestamptz NOT NULL,
    opened_from         text        NOT NULL CHECK (opened_from IN ('violation', 'own_observation', 'ansp_notice', 'ussp_notice')),
    source_violation_id text        UNIQUE REFERENCES violations (violation_id),
    notice_ref          text        CHECK (length(notice_ref) <= 200),
    intent_refs         text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(intent_refs) <= 32),
    narrative           text        NOT NULL DEFAULT '' CHECK (length(narrative) <= 20000),
    severity            text        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    status              text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'assigned', 'closed')),
    assignee            text        CHECK (assignee <> '' AND length(assignee) <= 128),
    closed_at           timestamptz,
    opened_by           text        NOT NULL CHECK (opened_by <> ''),
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    CHECK ((opened_from = 'violation') = (source_violation_id IS NOT NULL)),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK (status <> 'assigned' OR assignee IS NOT NULL)
);

CREATE INDEX incidents_created ON incidents (created_at DESC, incident_id DESC);
CREATE INDEX incidents_status ON incidents (status, created_at DESC);

CREATE TABLE incident_aircraft (
    id              bigserial   PRIMARY KEY,
    incident_id     text        NOT NULL REFERENCES incidents (incident_id),
    serial          text        CHECK (serial <> '' AND length(serial) <= 64),
    operator_reg    text        CHECK (operator_reg <> '' AND length(operator_reg) <= 64),
    registry_uas_id text        CHECK (length(registry_uas_id) <= 64),
    track_ids       text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(track_ids) <= 16),
    identification  jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(identification) = 'object'),
    added_by        text        NOT NULL CHECK (added_by <> ''),
    added_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (serial IS NOT NULL OR operator_reg IS NOT NULL OR cardinality(track_ids) > 0)
);

CREATE INDEX incident_aircraft_incident ON incident_aircraft (incident_id, id);

CREATE TABLE incident_notes (
    id          bigserial   PRIMARY KEY,
    incident_id text        NOT NULL REFERENCES incidents (incident_id),
    author      text        NOT NULL CHECK (author <> ''),
    body        text        NOT NULL CHECK (body <> '' AND length(body) <= 4000),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX incident_notes_incident ON incident_notes (incident_id, id);

CREATE TABLE evidence_packs (
    pack_id         text        PRIMARY KEY CHECK (pack_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    incident_id     text        NOT NULL REFERENCES incidents (incident_id),
    kind            text        NOT NULL CHECK (kind IN ('oversight', 'legal')),
    window_from     timestamptz NOT NULL,
    window_to       timestamptz NOT NULL,
    content_hash    text        NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes      bigint      NOT NULL CHECK (size_bytes > 0),
    signature       text        CHECK (length(signature) <= 8192),
    signature_kid   text        CHECK (length(signature_kid) <= 128),
    seal_statement  jsonb       NOT NULL CHECK (jsonb_typeof(seal_statement) = 'object'),
    manifest        jsonb       NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    storage_ref     text        NOT NULL CHECK (storage_ref <> '' AND length(storage_ref) <= 1024),
    sealed_key_id   text        CHECK (length(sealed_key_id) <= 32),
    created_by      text        NOT NULL CHECK (created_by <> ''),
    purpose         text        NOT NULL CHECK (purpose <> '' AND length(purpose) <= 200),
    case_ref        text        CHECK (case_ref <> '' AND length(case_ref) <= 200),
    created_at      timestamptz NOT NULL,
    CHECK (window_to > window_from),
    CHECK ((signature IS NULL) = (signature_kid IS NULL)),
    -- A legal pack carries personal data: a case reference and an
    -- archive sealed at rest are mandatory.
    CHECK (kind <> 'legal' OR (case_ref IS NOT NULL AND sealed_key_id IS NOT NULL))
);

CREATE INDEX evidence_packs_incident ON evidence_packs (incident_id, created_at DESC);

-- +goose StatementBegin
CREATE FUNCTION incidents_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % refused', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER incident_notes_append_only
    BEFORE UPDATE OR DELETE ON incident_notes
    FOR EACH ROW EXECUTE FUNCTION incidents_refuse_change();

CREATE TRIGGER evidence_packs_immutable
    BEFORE UPDATE OR DELETE ON evidence_packs
    FOR EACH ROW EXECUTE FUNCTION incidents_refuse_change();

GRANT SELECT, INSERT, UPDATE ON incidents TO authority_app;
GRANT SELECT, INSERT ON incident_aircraft, incident_notes, evidence_packs TO authority_app;
GRANT USAGE ON SEQUENCE incident_aircraft_id_seq, incident_notes_id_seq TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS evidence_packs;
DROP TABLE IF EXISTS incident_notes;
DROP TABLE IF EXISTS incident_aircraft;
DROP TABLE IF EXISTS incidents;
DROP FUNCTION IF EXISTS incidents_refuse_change();
