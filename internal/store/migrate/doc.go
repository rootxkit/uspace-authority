// Package migrate holds the goose runners of the two migration trees
// (migrations/relational for PostgreSQL + PostGIS, migrations/timeseries
// for TimescaleDB). Each tree has its own database, its own version
// table (goose_db_version_relational, goose_db_version_timeseries) and
// its own advisory lock; the trees are never merged (CLAUDE.md rule 10).
// Only the migrate subcommand applies them (D7). WP-1 adds the tables.
package migrate
