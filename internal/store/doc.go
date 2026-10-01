// Package store holds what both databases share: the pgx pool setup
// (maximum connections, statement timeout, application_name per
// process, the role the process works as) and the error helpers its
// callers use without importing pgx (plan §3: only internal/store opens
// a database).
//
// Built by WP-1:
//
//   - store.OpenPool: a pgxpool from PoolOptions. Every connection sets
//     application_name ("uspace-authority-<process>") and
//     statement_timeout as runtime parameters, then SET ROLE to the
//     process's role when one is given, so a login user that holds
//     several roles works with the least it needs.
//   - store/pg: the relational database (api only). The sqlc query set
//     internal/store/pg/queries -> internal/store/pg/gen, DB.WithTx
//     (one transaction, the generated queries bound to it), DB.AdvisoryLock
//     (a session-level try-lock every periodic job takes so one api
//     replica runs a job at a time) and the schema version check of D7.
//     The application role is authority_app (migration 00002): SELECT
//     and INSERT on events, SELECT and INSERT plus UPDATE of the
//     activation columns on authority_policy.
//   - store/ts: the telemetry database with two query sets, writer
//     (tsdb-writer only, role authority_ts_writer: SELECT and INSERT) and
//     reader (hot-path processes and api's record reads, role
//     authority_ts_reader: SELECT only). Default privileges give every
//     table a later timeseries migration creates the same grants; an
//     integration test proves an INSERT as the reader fails and the same
//     INSERT as the writer succeeds.
//   - store/migrate: the embedded goose trees, Up under an advisory
//     lock, Status, Latest, and the layout test that no file of one
//     tree names a table of the other.
//   - store/storetest: test-only scratch databases (created from
//     template0, migrated, dropped afterwards) for the integration
//     tests, imported by _test.go files only.
package store
