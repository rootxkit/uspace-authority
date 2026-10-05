-- uspace-authority bootstrap (deploy/compose.yaml): POSTGRES_DB creates
-- the relational database `authority` (PostGIS); this creates the
-- telemetry database `authority_ts` (TimescaleDB) beside it in the one
-- timescaledb-ha container (M37). They stay separate databases with
-- separate migration trees and version tables. Extensions and roles are
-- created by the migrations (`uspace-authority migrate`); the processes
-- log in as the superuser and SET ROLE (PG_ROLE, TS_*_ROLE).
CREATE DATABASE authority_ts;
