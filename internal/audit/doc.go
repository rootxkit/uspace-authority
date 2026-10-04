// Package audit is the append-only audit log, the relational table
// events (spec 03 §1, 06 §2 T7 and §5, docs/PLAN.md §4.1). Every PII
// read, switch, publication, token issuance and refusal, export and
// review of this system is one row, written in the same transaction as
// the act it records.
//
// Built by WP-1:
//
//   - The table (migration 00002_events): partitioned by month on ts,
//     SELECT and INSERT only for the application role authority_app, a
//     trigger refusing UPDATE and DELETE for every role, indexes on
//     (entity_type, entity_id, ts) and (actor_id, ts).
//   - Writer.Record(ctx, q, Event) validates the event (actor type,
//     actor id, entity type, an event type of the Catalogue, and a
//     purpose on every type tagged PIIView), then inside the caller's
//     transaction q: takes the month's advisory lock, creates the month
//     partition when missing, reads the previous hash, and inserts the
//     row with hash = sha256(prev_hash || canonical JSON of the row
//     without hash). The chain is linear within a month because every
//     writer of that month holds its lock; the first row of a month
//     also takes the previous month's lock and links to the last row
//     written before it (GenesisHash when there is none).
//   - The canonical JSON is the row's fields in a fixed order, ts in UTC
//     with microseconds, and the payload as PostgreSQL stores it (jsonb
//     normalised, then keys sorted), so Record hashes exactly what
//     Verify reads back.
//   - Writer.Verify(ctx, month) recomputes the month's chain in id order
//     and reports the rows it checked, the last hash, and the first
//     broken row (prev_hash mismatch or hash mismatch) or none. The
//     integration test tampers with a row as a superuser and reads both
//     answers (E-01, E-02).
//   - WP-27: GET /v1/audit/verify and the monthly job (ChainVerifier)
//     verify months and record each verification as an
//     audit_chain_verified row in the chain itself; a broken month is
//     counted, logged and named on the status line, also after a
//     restart (Load). Once the oldest months are dropped after their
//     retention, the oldest kept month's first row links to the anchor
//     in audit_dropped_months (Result.AnchoredTo).
//   - Writer.Query pages the log newest first with optional filters for
//     GET /v1/audit/events; Handler serves that route, behind the role
//     placeholder of internal/apiserver, and records the read itself as
//     an audit_events_viewed event.
package audit
