// Package registry is the authority's registry of UAS operators, UAS
// and remote pilots (2019/947 Art. 14, spec 01 A1 and A6, 03 §1), the
// registry projection every identification rests on (LESSONS G-08,
// docs/PLAN.md D2), and the F8 status-only lookups for USSPs (spec 02
// F8). Safety-relevant: a wrong projection row makes an aircraft look
// registered.
//
// Built by WP-3:
//
//   - Entities (migration 00009_registry). Operators carry the Art. 14(2)
//     field set; the registration number is validated by uspace-core
//     regnum under the active policy's registration_number_pattern
//     (G-07) and keyed by regnum.CompareKey (G-04, G-12), so a second
//     spelling of a number is a duplicate; a hyphen is refused (only the
//     public part is registered). The secret part, when issued, is an
//     HMAC-SHA-256 under the registry hash key of a per-row salt and the
//     three characters; a pilot's national id is an HMAC of the trimmed
//     id plus its last four characters (spec 06 §5). Every personal
//     column is AES-256-GCM sealed with the PII key (internal/pii, D9),
//     bound to its table, row and column. UAS keep the serial as given,
//     trimmed (G-05), with serial.FoldKey beside it;
//     the class decides whether the serial must be CTA-2063-A
//     (serial.ValidateForClass, G-06); (manufacturer_code, serial) and
//     the fold key are unique, so an exact duplicate and a spelling that
//     differs only by case are refused (the latter would make every
//     folded lookup ambiguous). Pilots carry competencies (A1_A3, A2,
//     STS_01, STS_02, national_*) with a certificate and an end date.
//   - One status graph for every entity (CheckTransition): active and
//     suspended move between each other; either may be revoked (final)
//     or expire (the expiry job only, from valid_until); an expired
//     registration is renewed once its valid_until is in the future.
//     Every transition is an events row and a registry_status_changes
//     row (the F8 change feed of ids and statuses).
//   - The projection (proj_registry_operators, proj_registry_uas in the
//     telemetry database, written as authority_ts_projector). Every
//     change runs in one relational transaction holding the advisory
//     lock LockProjection and numbered by registry_version_seq; before
//     the relational commit the change's rows are written and committed
//     in the telemetry database; a failed projection write rolls the
//     change back and answers 503 projection_unavailable naming the
//     cause (SC-17 step 3). If the relational commit then fails, the
//     projection is ahead: the failure is counted and a full
//     re-projection is requested at once. After the commit the version
//     is published (registry.v1.changed and KV registry_version once
//     the bus lands, WP-10; NopPublisher until then).
//   - Reproject, at api startup and every REGISTRY_REPROJECT_S (300 s),
//     under a job lock and LockProjection held from the relational read
//     to the projection commit, writes the registry's state over every
//     row, so a change made meanwhile waits and is never overwritten
//     (SC-17 steps 4 and 5). A row the registry does not hold is kept
//     and marked: aircraft in_registry = false, operators 'unregistered'
//     (which identify never reads as in good standing); nothing is
//     deleted. An expired registration is projected as 'expired', which
//     identify also fails safe on (unknown_operator).
//   - ProjectionReader (for the hot-path processes): loads the tables in
//     one read-only transaction into exactly what identify.NewSnapshot
//     takes, refreshes every DefaultRefresh (5 s) and on Notify, keeps
//     the snapshot it holds when a read fails (SC-17 step 6), and puts
//     projection_age_s, rows and registry_version on the status line.
//     Before its first good read Lookup is nil, which identify answers
//     registry_unavailable.
//   - Validate (F8): per entity valid / suspended / revoked / unknown,
//     the end of validity, the class label and MTOM band of a UAS and
//     the competencies of a pilot; never a name, address, phone or
//     e-mail (a test greps every response schema of the contract).
//     Serials match through identify.Snapshot (exact, else a unique
//     fold); operator numbers on regnum.CompareKey. A batch holds at
//     most MaxBatch (100) entities. Every call is one registry_validated
//     event with the client and the purpose; without it no answer
//     leaves. An expired registration answers revoked with its
//     valid_until.
//   - Personal data is read only through OperatorPersonalData and
//     PilotPersonalData, for the registrar and inspector roles
//     (apiserver.PIIRoles), with a purpose recorded as
//     registry_pii_viewed before anything is opened.
//
// Later work packages: the uas.gov.ge import, the public check and the
// portal applications (WP-20); the bus push and KV (WP-10); the
// resolvers that read the projection (WP-8, WP-14).
package registry
