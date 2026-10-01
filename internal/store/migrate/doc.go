// Package migrate holds the goose runners of the two migration trees
// (migrations/relational for PostgreSQL + PostGIS, migrations/timeseries
// for TimescaleDB). Each tree has its own database, its own version
// table (goose_db_version_relational, goose_db_version_timeseries) and
// its own advisory lock; the trees are never merged (CLAUDE.md rule 10).
// Only the migrate subcommand applies them (D7): Up, under the tree's
// session advisory lock. Status lists each migration and whether it is
// applied; Latest is the newest version embedded, which a long-running
// process compares with the database's at start (store.RequireVersion)
// and refuses to run below. WP-1 adds the relational events and
// authority_policy tables and the telemetry roles.
package migrate
