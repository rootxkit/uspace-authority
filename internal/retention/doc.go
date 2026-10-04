// Package retention is what this system keeps and for how long (WP-27;
// spec 05 §4, 06 §2 T7, 06 §5, 02 F7, 08 Q8; plan Q-A15, Q-A18). It runs
// in api only; docs/runbooks/retention.md is the procedure.
//
// Periods are configuration (config.Retention), the spec's Q8 defaults
// pending GCAA, said with pending_gcaa on the status line, in
// GET /v1/retention/status, in every manifest and every deletion's
// events row. The database enforces the regulatory floor whatever they
// say.
//
// Service.Run is the daily retention job, each step bounded per run and
// run even when another failed:
//
//   - ArchiveTelemetry: each chunk of rid_observations, tracks and
//     manned_tracks past the online window is exported by one COPY (no
//     transaction held by api) to the archive store, read back and
//     checked (size, SHA-256, rows), recorded archived in the telemetry
//     ledger archive_chunks with its events row, then dropped through
//     authority_archive_drop_chunk unless held. The remote pilot position
//     is removed from archived System frames (archive.RedactOperator)
//     unless an incident references the aircraft around the chunk. A
//     step committed in the telemetry database is recorded in the
//     relational audit log after that commit and caught up after a
//     restart, once (recordOnce).
//   - ExpireArchive: archived objects and USSP bundles past the archive
//     period are deleted unless held.
//   - DeleteViolations: closed violations past their period, in batches
//     of BatchRows, each one transaction with its events row naming
//     every id, through authority_retention_delete_violations.
//   - DropAuditMonths: the oldest months of events past their period,
//     one per transaction, through authority_retention_drop_events_month,
//     which records the chain's anchor (audit_dropped_months).
//
// What holds a record: an active legal hold (Holds, /v1/retention/holds),
// a violation an incident was opened from, an open incident's aircraft
// around when it occurred. Every deletion checks them inside its own
// transaction after taking legal_holds in SHARE mode (the hold gate), so
// a hold placed meanwhile waits and is seen by the next batch; past
// MaxHolds active holds everything is held (fail closed).
//
// Scheduler runs the jobs (retention, audit_verify, evidence_verify,
// ussp_records) when job_runs says they are due on the database clock,
// each under its own session advisory lock, and records every run with
// its outcome and summary; a restart neither skips a due run nor
// repeats a finished one.
package retention
