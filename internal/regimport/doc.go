// Package regimport imports the registry of uas.gov.ge into the
// authority's (WP-20; spec 03 §1 uas_operators.source, 08 Q4; plan
// Q-A11; LESSONS G-11). It runs in api only. docs/runbooks/
// registry-import.md is the procedure and the rules-file format.
//
// The export's format is not known yet (spec Q4: no export has been
// seen; the data-sharing agreement with GCAA is pending), so nothing
// here assumes one. A rules file (REGISTRY_IMPORT_RULES_FILE,
// configuration agreed with GCAA, never committed with real data) says
// which column holds which registry field, how the export's values map
// onto the registry's (operator type, status, class, Remote ID
// capability, yes/no), which date formats and UTC offset its dates use,
// the unit of its masses, the registration-number pattern its numbers
// follow and whether they carry the EU secret part. LoadRules checks it
// whole at start and names every field at fault; api does not start on
// a bad one.
//
// An import (Service.Run, POST /v1/registry/import, registrar) reads
// one export of one kind (operators first, then uas) as CSV or a JSON
// array of flat objects (ReadRecords; bounded by
// REGISTRY_IMPORT_MAX_BYTES and REGISTRY_IMPORT_MAX_ROWS, E-10), maps
// every record under the rules (MapOperators, MapUAS) and hands the
// records to internal/registry's ImportOperators or ImportUAS: one
// transaction, all or nothing, idempotent on the record's source id
// (source = uas_gov_ge_import, source_ref = the id), every value
// checked by the registry's own rules (regnum, serial, the Art. 14(2)
// set). Every problem is reported by record and field
// (records[<n>].<field>, the column named in the reason); with any, the
// import is refused whole (422) and nothing is written but its events
// row. A dry run runs the same checks in a transaction that is rolled
// back and answers the report. Every import that ran to an outcome is a
// registry_imports row (the ledger) beside its events row.
//
// The periodic re-import (Job, REGISTRY_IMPORT_URL with {kind},
// https only, every REGISTRY_IMPORT_EVERY_S) runs only when the agreed
// URL is configured (G-11: nothing is scraped, no redirect followed),
// under a job lock so one replica runs it, and skips content the ledger
// shows it ran to an outcome under the same rules: an applied export
// would change nothing, and a refused one stays refused until the
// source changes it. A failed fetch is counted and waits for the next
// period; there is no retry loop.
package regimport
