-- WP-20: the uas.gov.ge import (docs/PLAN.md §5 registry rows, Q-A11;
-- spec 03 §1 uas_operators.source, 08 Q4; LESSONS G-11).
--
-- source_ref is the id the source gives an entry: the uas.gov.ge
-- record id of an imported operator or aircraft (the import is
-- idempotent on it), the application id of a registration the portal
-- approved (a retried approval finds the operator it made). It is
-- unique per source and never changes (no UPDATE grant), like the rest
-- of an entry's identity. uas gains the source column uas_operators
-- has had since 00009, so an imported aircraft says where it came from.
--
-- registry_imports records every import that ran to an outcome (dry
-- runs are events rows only): what was read (kind, origin, the SHA-256
-- of the exact bytes, the rules file's version), what came of it
-- (applied or refused) and the counts. The periodic re-import reads the
-- newest fetched row of a kind so content it applied or refused before
-- is not run again (a refusal is permanent until the source changes),
-- also after a restart. Append-only.
--

-- +goose Up
ALTER TABLE uas_operators
    ADD COLUMN source_ref text CHECK (source_ref <> '' AND length(source_ref) <= 128);
CREATE UNIQUE INDEX uas_operators_source_ref ON uas_operators (source, source_ref) WHERE source_ref IS NOT NULL;

ALTER TABLE uas
    ADD COLUMN source     text NOT NULL DEFAULT 'manual' CHECK (source IN ('portal', 'uas_gov_ge_import', 'manual')),
    ADD COLUMN source_ref text CHECK (source_ref <> '' AND length(source_ref) <= 128);
CREATE UNIQUE INDEX uas_source_ref ON uas (source, source_ref) WHERE source_ref IS NOT NULL;

CREATE TABLE registry_imports (
    id               text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    at               timestamptz NOT NULL DEFAULT now(),
    kind             text        NOT NULL CHECK (kind IN ('operators', 'uas')),
    origin           text        NOT NULL CHECK (origin IN ('upload', 'fetch')),
    content_sha256   text        NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    rules_version    text        NOT NULL CHECK (rules_version <> '' AND length(rules_version) <= 64),
    outcome          text        NOT NULL CHECK (outcome IN ('applied', 'refused')),
    rows_read        integer     NOT NULL CHECK (rows_read >= 0),
    created          integer     NOT NULL CHECK (created >= 0),
    updated          integer     NOT NULL CHECK (updated >= 0),
    unchanged        integer     NOT NULL CHECK (unchanged >= 0),
    problems         integer     NOT NULL CHECK (problems >= 0),
    registry_version bigint,
    actor_id         text        NOT NULL CHECK (actor_id <> '')
);
CREATE INDEX registry_imports_kind_origin_at ON registry_imports (kind, origin, at DESC);

-- +goose StatementBegin
CREATE FUNCTION registry_imports_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'registry_imports is append-only: % refused', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER registry_imports_append_only BEFORE UPDATE OR DELETE ON registry_imports
    FOR EACH ROW EXECUTE FUNCTION registry_imports_refuse_change();

GRANT SELECT, INSERT ON registry_imports TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS registry_imports;
DROP FUNCTION IF EXISTS registry_imports_refuse_change();
DROP INDEX IF EXISTS uas_source_ref;
ALTER TABLE uas DROP COLUMN IF EXISTS source_ref, DROP COLUMN IF EXISTS source;
DROP INDEX IF EXISTS uas_operators_source_ref;
ALTER TABLE uas_operators DROP COLUMN IF EXISTS source_ref;
