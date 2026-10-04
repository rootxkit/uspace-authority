-- WP-18: occurrence reports under Reg. (EU) 376/2014 (spec 01 A8, 03 §1
-- occurrence_reports, 05 §4, 06 §2 T6, 06 §5, 09 §1.7; docs/PLAN.md
-- §4.1 and D9).
--
-- The reports live in their own schema, occurrences, worked by their
-- own role, authority_occurrences, which api uses through a second pool
-- in internal/occurrences only. The application role authority_app has
-- no grant on the schema and the occurrences role has none on the
-- authority's enforcement tables: 376 Art. 15-16 keep a report from
-- ever becoming evidence against its reporter, so no foreign key, view,
-- function or query crosses between this schema and the rest
-- (internal/occurrences' segregation test reads pg_depend to prove it).
-- The only objects outside the schema this role touches are the audit
-- log (events, append-only) and the goose version table, so a report's
-- intake, every reporter-identity read and every export commit with
-- their events row.
--
-- occurrence_reports holds one report per (reporter_org, report_ref):
-- reporter_org is the sender's token subject (a USSP's or the ANSP's
-- client id) or operator:<registration public part> for an operator's
-- report (2019/947 Art. 19(2)); report_ref is the sender's own
-- reference, the idempotency key with reporter_org. The reporter's
-- person reference arrives in clear over TLS (M13) and is stored only
-- sealed (AES-256-GCM) under OCCURRENCE_KEY, a key separate from the PII
-- key, bound to the row's id (reporter_person_enc, reporter_key_id).
-- received_at is the database clock at intake; within_72h is computed
-- from it, became_aware_at and the deadline in force at intake
-- (report_deadline_s, OCCURRENCES_REPORT_DEADLINE_S, 376 Art. 4(7)-(8))
-- and can never be edited. A late report is stored and flagged, never
-- refused. aircraft keeps each operator registration's public part only.
--
-- deidentified_exports records every de-identified export (376 Art.
-- 7(4), 16(3)): its format, the SHA-256 of the exact bytes produced and
-- how many records it holds. Both tables refuse DELETE (no grant), and
-- the exports refuse UPDATE too.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authority_occurrences') THEN
    CREATE ROLE authority_occurrences NOLOGIN;
  END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
  NULL; -- created concurrently by another database's migration
END
$$;
-- +goose StatementEnd

CREATE SCHEMA occurrences;
REVOKE ALL ON SCHEMA occurrences FROM PUBLIC;

CREATE TABLE occurrences.occurrence_reports (
    occurrence_id       text        PRIMARY KEY CHECK (occurrence_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    reporter_org        text        NOT NULL CHECK (reporter_org <> '' AND length(reporter_org) <= 160),
    report_ref          text        NOT NULL CHECK (report_ref <> '' AND length(report_ref) <= 128),
    channel             text        NOT NULL CHECK (channel IN ('mandatory', 'voluntary')),
    origin              text        NOT NULL CHECK (origin IN ('client', 'operator')),
    reporter_person_enc bytea,
    reporter_key_id     text        CHECK (reporter_key_id <> '' AND length(reporter_key_id) <= 32),
    occurred_at         timestamptz NOT NULL,
    became_aware_at     timestamptz NOT NULL,
    reported_at         timestamptz,
    received_at         timestamptz NOT NULL DEFAULT now(),
    report_deadline_s   integer     NOT NULL CHECK (report_deadline_s > 0),
    within_72h          boolean     GENERATED ALWAYS AS
                            ((received_at - became_aware_at) <= make_interval(secs => report_deadline_s)) STORED,
    category            text        NOT NULL CHECK (category IN ('airprox', 'nonconformance_in_prohibited',
                                                                 'lost_link_in_uspace', 'emergency', 'other')),
    aircraft            jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(aircraft) = 'array' AND jsonb_array_length(aircraft) <= 50),
    manned              jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(manned) = 'array' AND jsonb_array_length(manned) <= 50),
    intent_refs         text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(intent_refs) <= 50),
    min_separation      jsonb       CHECK (jsonb_typeof(min_separation) = 'object'),
    narrative           text        NOT NULL DEFAULT '' CHECK (length(narrative) <= 20000),
    evidence_urls       text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(evidence_urls) <= 20),
    content_hash        text        NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    risk_classification text        CHECK (risk_classification <> '' AND length(risk_classification) <= 64),
    classified_at       timestamptz,
    classified_by       text,
    analysis            text        NOT NULL DEFAULT '' CHECK (length(analysis) <= 20000),
    follow_up           text        NOT NULL DEFAULT '' CHECK (length(follow_up) <= 20000),
    state               text        NOT NULL DEFAULT 'received' CHECK (state IN ('received', 'classified', 'analysed', 'closed')),
    closed_at           timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    updated_by          text,
    UNIQUE (reporter_org, report_ref),
    CHECK ((reporter_person_enc IS NULL) = (reporter_key_id IS NULL)),
    CHECK (became_aware_at >= occurred_at),
    CHECK ((risk_classification IS NULL) = (classified_at IS NULL)),
    CHECK (state = 'received' OR risk_classification IS NOT NULL),
    CHECK ((state = 'closed') = (closed_at IS NOT NULL)),
    CHECK (origin <> 'operator' OR (channel = 'mandatory' AND reporter_org LIKE 'operator:%'))
);

CREATE INDEX occurrence_reports_received ON occurrences.occurrence_reports (received_at DESC, occurrence_id DESC);
CREATE INDEX occurrence_reports_state ON occurrences.occurrence_reports (state, received_at DESC);

CREATE TABLE occurrences.deidentified_exports (
    export_id    text        PRIMARY KEY CHECK (export_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   text        NOT NULL CHECK (created_by <> ''),
    format       text        NOT NULL CHECK (format <> '' AND length(format) <= 64),
    content_hash text        NOT NULL CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    size_bytes   bigint      NOT NULL CHECK (size_bytes > 0),
    record_count integer     NOT NULL CHECK (record_count >= 0),
    window_from  timestamptz NOT NULL,
    window_to    timestamptz NOT NULL,
    CHECK (window_to > window_from)
);

CREATE INDEX deidentified_exports_created ON occurrences.deidentified_exports (created_at DESC);

GRANT USAGE ON SCHEMA occurrences TO authority_occurrences;
GRANT SELECT, INSERT ON occurrences.occurrence_reports TO authority_occurrences;
GRANT UPDATE (risk_classification, classified_at, classified_by, analysis, follow_up, state, closed_at, updated_at, updated_by)
    ON occurrences.occurrence_reports TO authority_occurrences;
GRANT SELECT, INSERT ON occurrences.deidentified_exports TO authority_occurrences;

-- The audit log and the schema check, as authority_app has them.
GRANT SELECT ON goose_db_version_relational TO authority_occurrences;
GRANT SELECT, INSERT ON events TO authority_occurrences;
GRANT USAGE ON SEQUENCE events_id_seq TO authority_occurrences;
GRANT EXECUTE ON FUNCTION events_ensure_partition(timestamptz) TO authority_occurrences;

-- +goose Down
DROP SCHEMA IF EXISTS occurrences CASCADE;
REVOKE ALL ON FUNCTION events_ensure_partition(timestamptz) FROM authority_occurrences;
REVOKE ALL ON SEQUENCE events_id_seq FROM authority_occurrences;
REVOKE ALL ON events FROM authority_occurrences;
REVOKE ALL ON goose_db_version_relational FROM authority_occurrences;
