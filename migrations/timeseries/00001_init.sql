-- Telemetry tree (TimescaleDB): hypertables written by tsdb-writer,
-- projection tables written by api. Version table:
-- goose_db_version_timeseries. Never merged with the relational tree
-- (CLAUDE.md rule 10); tables arrive with WP-1 onwards.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- +goose Down
DROP EXTENSION IF EXISTS timescaledb;
