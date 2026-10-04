// Package occurrences is the authority's intake and handling of
// occurrence reports under Reg. (EU) 376/2014 (WP-18; spec 01 A8, 02 F7
// and F11, 03 §1 occurrence_reports, 04 §3.3 occurrence/v1, 05 §4, 06 §2
// T6, 06 §5, 09 §1.7). It runs in api only. docs/runbooks/occurrences.md
// is the procedure.
//
// Segregation (376 Art. 15-16, CLAUDE.md rule 6): the reports live in
// the PostgreSQL schema occurrences, worked by the role
// authority_occurrences through a pool of their own (store, which only
// this package imports). api's application role has no grant on the
// schema, the occurrences role has none on violations or incidents, no
// foreign key, view, function or query crosses between them, and
// internal/violations and internal/incidents never import this package;
// the tests prove each from the code, the migration and the live
// catalogue (pg_depend). A report never becomes a violation: violations
// rest on the authority's own evidence.
//
// Intake (Service.Intake, POST /v1/occurrences, scope
// occurrences.write): the body is occurrence/v1 (schemas/occurrence/
// v1.json, owned here, M14), the shape the ANSP's outbox posts
// (uspace-ansp internal/coord OccurrenceMessage). Normalise checks every
// member and bound (E-10) and cuts every operator registration to its
// public part (G-04: the secret part is never stored). The token's sub
// is recorded as reporter_org; an operator's report (2019/947 Art.
// 19(2), OperatorOrigin, posted through WP-20's portal) is
// operator:<public part> on the mandatory channel. The intake is
// idempotent on (reporter_org, report_ref): the same content again
// answers the first receipt, other content under the same reference is
// 409. received_at is the database clock and within_72h is computed by
// the database from it, became_aware_at and the deadline in force at
// intake (OCCURRENCES_REPORT_DEADLINE_S); a late report is stored and
// flagged, never refused. The reporter's person reference arrives in
// clear over TLS (M13) and is sealed at rest (AES-256-GCM, bound to the
// row's id) under OCCURRENCE_KEY_FILE, a key separate from the PII key;
// without it a report carrying one is refused 503 and nothing is stored
// in clear.
//
// Handling (incident officers, the independent persons of Art. 6(3)):
// reports are read without their reporter by incident officers and
// inspectors; the reporter (organisation, reference, person) is its own
// operation for incident officers only, each read an
// occurrence_reporter_viewed events row with the purpose, committed
// before the identity is returned; an attempt that cannot open the
// sealed reference is refused and committed as an
// occurrence_reporter_unopened row with the purpose. Classify records the safety risk
// class from the configured scheme (Art. 7(2)); UpdateAnalysis records
// the analysis and follow-up and moves a report received -> classified
// -> analysed -> closed. Every change is one events row naming what
// changed, never the text or the reporter.
//
// Export (Art. 7(4), 16(3)): Service.Export writes the de-identified
// record set of a window through an Exporter, pluggable by format; this
// build's is FormatECCAIRSDraft (the demo default of plan Q-A12; E5X is
// the owner's question). No reporter, no names, no addresses: aircraft
// by serial and registration public part; the narrative as the reporter
// wrote it, which the officer redacts before filing. The exact bytes
// are sealed by their SHA-256, recorded in deidentified_exports and in
// the occurrence_export_created events row. A window over the bound is
// refused, never thinned.
package occurrences
