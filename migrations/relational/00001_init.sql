-- Relational tree (PostgreSQL 16 + PostGIS 3.4), written by api only.
-- Version table: goose_db_version_relational. Never merged with the
-- timeseries tree (CLAUDE.md rule 10); tables arrive with WP-1 onwards.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS postgis;

-- +goose Down
DROP EXTENSION IF EXISTS postgis;
