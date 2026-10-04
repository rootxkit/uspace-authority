// Package police is the police realm (WP-19; spec 01 A9, 02 F10, 06 §2
// T6, 06 §5, Q-A14): purpose-logged queries and legal exports for the
// accounts of police and other agencies, and the monthly report of
// every personal-data view and export for the data protection officer.
// It runs in api only. docs/runbooks/police-realm.md is the procedure.
//
// Accounts (internal/authz, migration 00021): an account of the police
// realm holds police.query alone (WP-2 table B, "inside a session") and
// never a console role; it names its agency and the CIDRs it may sign in
// and query from. Sign-in is WP-2's (password, then TOTP): a password
// or a TOTP step from an address off the list is refused with the answer
// of a wrong password and recorded (address_not_allowed). Every police
// request checks the address again against the account's row as it is
// now (Service.caller), so a list changed after sign-in applies at once;
// an admin's change also ends the account's sessions.
//
// Every query (QueryAircraft, QueryOperator, QuerySerial, Export,
// Download) carries a purpose from POLICE_PURPOSES and a case reference
// and is one police_queries row and one police_query events row in one
// transaction (PG.Record), committed before any personal data is
// opened. The row holds who, the agency, the session, why, what was
// asked (a registration number's public part only), how many results
// and whether personal data was released. Budgets per user and per
// agency (POLICE_USER_QUERIES, POLICE_AGENCY_QUERIES per
// POLICE_RATE_WINDOW_S) count these rows on the database clock under
// the agency's advisory lock, so neither a restart nor a second api
// replica forgets or doubles one; a spent budget is 429 with
// Retry-After and a police_query_refused row.
//
// What an answer holds (G-10): aircraft in a box now (the picture's
// tracks last seen within POLICE_LIVE_WINDOW_S of the telemetry
// database's clock) or at an instant (within POLICE_AT_WINDOW_S of it,
// no older than POLICE_HISTORY_MAX_AGE_S), with serial, registration
// public part, identification status, trust, times and positions, never
// the remote pilot position; with how fresh the picture is and the
// recorded writer gaps of the window, so an empty answer from a stale
// picture does not read as an empty sky. Registry status, validity and
// fleet for an operator number or a serial (uspace-core's matching
// through the registry). The operator's identity (name, legal name,
// address, e-mail, phone; never the date of birth, the identification
// number or the insurance policy) only for a purpose of
// POLICE_PII_PURPOSES, read through registry.OperatorPersonalData, whose
// registry_pii_viewed row carries the police query, the case and the
// agency (audit.WithAnnotations). Every list is bounded and says when it
// was truncated (E-10).
//
// Exports: a legal evidence pack through WP-17's builder (hash sealed,
// signed, sealed at rest) for an incident, or for the aircraft the
// picture held in a box over a window, for which an incident
// opened_from police_request is opened first (at most
// incidents.MaxAircraft aircraft; more is refused, never thinned). Only
// a personal-data purpose exports. police_exports links the pack to the
// agency, and only that agency downloads it; every download is a
// police_queries row and WP-17's evidence_pack_downloaded row.
//
// Never any occurrence report (376/2014 Art. 15(2), 16): this package
// does not import internal/occurrences (internal/layout's test), its
// queries name no occurrences table, and the application role it works
// as has no grant on the occurrences schema (an integration test proves
// the refusal).
//
// The DPO report (DPOReport, GET /v1/audit/dpo-report for admin and
// auditor): a UTC month's police_queries rows and every events row of
// the catalogue's personal-data read types (police_query aside, whose
// rows are the first list), each with its actor, purpose, entity and,
// for a police read, its case reference and agency; bounded by
// DPO_REPORT_MAX_ROWS with truncated; the read is a dpo_report_viewed
// row in the same transaction.
package police
