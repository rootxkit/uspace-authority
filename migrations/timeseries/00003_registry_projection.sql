-- WP-3: the registry projection that identification reads (LESSONS G-08,
-- docs/PLAN.md D2 and §4.2). Hot-path processes never open the
-- relational database; they read these two tables, whose columns are
-- exactly what uspace-core identify.NewSnapshot takes (OperatorFacts and
-- UASFacts) plus projected_at and registry_version.
--
-- api writes them as authority_ts_projector: inside the registry change,
-- before the relational commit (a failed projection write rolls the
-- change back), and in full at startup and every 300 s under an advisory
-- lock. An upsert never replaces a row with an older registry_version.
-- Nothing deletes a row: an aircraft the registry does not hold is kept
-- with in_registry = false, and an operator the registry does not hold
-- keeps its row with the status 'unregistered', which identification
-- does not recognise and so never reads as in good standing.
--
-- authority_ts_projector may SELECT, INSERT and UPDATE these two tables
-- and nothing else. The writer role's default INSERT grant (00002_roles)
-- is revoked here: tsdb-writer writes hypertables only.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authority_ts_projector') THEN
    CREATE ROLE authority_ts_projector NOLOGIN;
  END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
  NULL; -- created concurrently by another database's migration
END
$$;
-- +goose StatementEnd

CREATE TABLE proj_registry_operators (
    operator_id                text        PRIMARY KEY,
    registration_number_public text        NOT NULL,
    status                     text        NOT NULL,
    projected_at               timestamptz NOT NULL,
    registry_version           bigint      NOT NULL
);

CREATE TABLE proj_registry_uas (
    uas_id              text        PRIMARY KEY,
    label               text        NOT NULL DEFAULT '',
    serial              text        NOT NULL,
    serial_fold         text        NOT NULL,
    registration_status text        NOT NULL,
    operator_id         text,
    in_registry         boolean     NOT NULL,
    projected_at        timestamptz NOT NULL,
    registry_version    bigint      NOT NULL
);

CREATE INDEX proj_registry_uas_serial_fold_idx ON proj_registry_uas (serial_fold);

REVOKE INSERT ON proj_registry_operators, proj_registry_uas FROM authority_ts_writer;
GRANT USAGE ON SCHEMA public TO authority_ts_projector;
GRANT SELECT ON goose_db_version_timeseries TO authority_ts_projector;
GRANT SELECT, INSERT, UPDATE ON proj_registry_operators, proj_registry_uas TO authority_ts_projector;
GRANT SELECT ON proj_registry_operators, proj_registry_uas TO authority_ts_reader;

-- +goose Down
DROP TABLE IF EXISTS proj_registry_uas;
DROP TABLE IF EXISTS proj_registry_operators;
REVOKE ALL ON goose_db_version_timeseries FROM authority_ts_projector;
REVOKE USAGE ON SCHEMA public FROM authority_ts_projector;
