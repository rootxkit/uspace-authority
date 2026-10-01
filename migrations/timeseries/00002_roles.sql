-- WP-1: the two telemetry roles (docs/PLAN.md §2, §3; spec 06 §2 T7).
--
--   authority_ts_reader  SELECT only: the role of the hot-path processes
--                        (rid-ingest, dp-poller, detect, picture-ws) and
--                        of api's record reads.
--   authority_ts_writer  SELECT and INSERT: tsdb-writer, the only writer
--                        of the hypertables. No UPDATE or DELETE.
--
-- Both are created NOLOGIN when missing (a deployment may provision them
-- beforehand); login users are granted membership by the deployment and
-- each process sets its role on connect (internal/store). Default
-- privileges give every table a later migration of this tree creates
-- the same grants, so a new hypertable never needs a grant to be
-- remembered. Roles are cluster-wide: the Down revokes, never drops.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authority_ts_reader') THEN
    CREATE ROLE authority_ts_reader NOLOGIN;
  END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
  NULL; -- created concurrently by another database's migration
END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authority_ts_writer') THEN
    CREATE ROLE authority_ts_writer NOLOGIN;
  END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
  NULL;
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA public TO authority_ts_reader, authority_ts_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO authority_ts_reader, authority_ts_writer;
GRANT INSERT ON ALL TABLES IN SCHEMA public TO authority_ts_writer;
REVOKE INSERT ON goose_db_version_timeseries FROM authority_ts_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO authority_ts_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT ON TABLES TO authority_ts_writer;

-- +goose Down
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT, INSERT ON TABLES FROM authority_ts_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM authority_ts_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authority_ts_reader, authority_ts_writer;
REVOKE USAGE ON SCHEMA public FROM authority_ts_reader, authority_ts_writer;
