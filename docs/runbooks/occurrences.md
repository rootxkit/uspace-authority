# Occurrence reports (Reg. (EU) 376/2014)

The authority's intake and independent handling of occurrence reports
(spec 01 A8, 02 F7 and F11, 03 §1 `occurrence_reports`, 04 §3.3
`occurrence/v1`, 06 §2 T6, 06 §5, 09 §1.7; WP-18). `api` serves them
under `/v1/occurrences*`. A report is a safety record for people: it
never becomes a violation, it is never joined to an incident, and it is
never used against the reporter or the persons named in it (376 Art.
15-16). Nothing here alerts anyone or acts on an aircraft.

## Segregation

| What | How it is held | Proved by |
|---|---|---|
| Own schema and role | The reports live in the PostgreSQL schema `occurrences`, worked by the role `authority_occurrences` (`PG_OCCURRENCES_ROLE`) through a second pool of `api` used only by `internal/occurrences`. | `internal/layout` `TestOnlyOccurrencesImportsItsStore` |
| The rest of `api` cannot read them | `authority_app` (`PG_ROLE`) has no grant on the schema. | `TestIntegrationNoPathJoinsAnOccurrenceToAViolation` (permission denied as `authority_app`, read as `authority_occurrences`) |
| They cannot read enforcement | `authority_occurrences` has no grant on `violations`, `incidents`, `incident_aircraft`, `evidence_packs` or the registry. The only objects outside the schema it touches are `events` (insert, read) and the goose version table. | same test |
| No link | No foreign key, view, function, trigger or default between `occurrences.*` and any other schema; no `violation_id` or `incident_id` column in the occurrences schema; no `occurrence_id` column in the incidents tables. An incident's narrative may quote an occurrence id an officer types; nothing links it. | the same test reads `pg_depend` and `information_schema.columns`, and finds a planted view and foreign key (E-01); `TestNoLinkColumnInEitherMigration` |
| No code path | `internal/violations`, `internal/incidents`, `internal/violation` and `internal/detectsvc` never import `internal/occurrences`; no query or code line of `internal/occurrences` names a violation, an incident or an evidence pack, and `internal/incidents` names no occurrence. | `TestEnforcementNeverDependsOnOccurrences`, `TestNoPathFromOccurrencesToEnforcement`, `TestNoPathToOccurrenceReports` |

The login user of `PG_URL` must be a member of `authority_occurrences`
(migration `00020_occurrences` creates the role NOLOGIN when it does not
exist; the development stack logs in as the superuser, which is).

## Intake channels

| Channel | Who | How | `reporter_org` |
|---|---|---|---|
| USSP | a certified USSP (376 Art. 4(8); 2021/664 Art. 15(1)(d)) | `POST /v1/occurrences` with an ecosystem token of scope `occurrences.write` (every USSP client gets it with its certificate, WP-16) | the token's `sub`, e.g. `ussp-ab12-01` |
| ANSP | the ANSP's staff reports, queued by its outbox (uspace-ansp `internal/coord`, `internal/deliver`) | the same, client `ansp-01` | `ansp-01` |
| Operator | a UAS operator (2019/947 Art. 19(2)) | the operator portal (WP-20) or a signed public form, later; the service already records it (`OperatorOrigin`) | `operator:<registration public part>`, always the **mandatory** channel |

The body is `occurrence/v1` (`schemas/occurrence/v1.json`, owned here;
`api/openapi.yaml` `OccurrenceReport` is the same shape, a test holds
the two together). What the intake does:

- **Idempotent** on (`reporter_org`, `report_ref`): the same report again
  answers 200 with the id given first (`replayed: true`) and writes
  nothing; another report under a held reference is 409
  `report_ref_conflict` (a sender's reference names one report). The
  replay check is the SHA-256 of the report as normalised; the reporter's
  person reference is not hashed (only whether one was sent), so the
  first delivery's reference is the one kept.
- **Late reports are accepted.** `received_at` is the database clock;
  `within_72h` is computed by the database from it, `became_aware_at`
  and the deadline in force at intake (`OCCURRENCES_REPORT_DEADLINE_S`,
  default 259200 = 72 h, 376 Art. 4(7)-(8)) and can never be edited.
  Exactly at the deadline is within. A late report is stored with
  `within_72h: false` and counted (`occurrences_received_late`), never
  refused.
- **Refused, with the member named:** a `became_aware_at` before
  `occurred_at`, or ahead of the database clock by more than
  `OCCURRENCES_CLOCK_SKEW_S` (300 s); a member past its bound (50
  aircraft, manned aircraft or intent references; 20 evidence URLs;
  20000 bytes of narrative; 128 bytes of a person reference; a body over
  256 KiB is 413); a control character in a text (PostgreSQL holds no
  NUL). Members this version does not know are ignored.
- **The reporter's person reference** (`reporter.person_ref`, an opaque
  reference in the sender's system, never a name) arrives in clear over
  TLS (M13) and is sealed at rest (AES-256-GCM, bound to the row's id)
  under `OCCURRENCE_KEY_FILE`, a key **separate from the PII key** (a
  key file equal to it stops the start). Without the key, a report
  carrying a reference is refused 503 `occurrence_key_unavailable`
  (the sender retries) and nothing is stored in clear; a report without
  one is received.
- **Registration numbers:** each aircraft's `operator_reg` is cut to its
  public part (uspace-core `regnum` under the active policy's pattern);
  a secret part sent is dropped and never stored.
- `reporter.org` is informational: a value other than the token's `sub`
  is ignored and counted (`occurrences_reporter_org_ignored`).
- One `occurrence_received` events row per new report, with the sending
  client as actor and no reporter identity or text in its payload.

## The officer workflow

Incident officers are the independent persons of 376 Art. 6(3); they see
reports and their reporters. Inspectors read reports **without** the
reporter and cannot read it (403), nor change a report.

| Step | Operation | Role | Audit |
|---|---|---|---|
| Read | `GET /v1/occurrences` (filters `state`, `category`, `channel`, `from`/`to` on `received_at`, cursor), `GET /v1/occurrences/{id}` | `incident_officer`, `inspector` | none; the answers hold no reporter organisation, reference or person (`has_reporter_person` only) |
| Reporter | `GET /v1/occurrences/{id}/reporter?purpose=...` | `incident_officer` only | `occurrence_reporter_viewed` with the purpose (a PII read), committed before the identity is returned; `Cache-Control: no-store` |
| Classify | `POST /v1/occurrences/{id}/classify` `{risk_classification}` | `incident_officer` | `occurrence_classified` (from, to) |
| Analyse | `PATCH /v1/occurrences/{id}/analysis` `{analysis, follow_up, state}` | `incident_officer` | `occurrence_analysis_updated` naming what changed, never the text |
| Export | `POST /v1/occurrences/export` `{from, to, format}` | `incident_officer` | `occurrence_export_created` with the hash |

States: `received` -> `classified` (by the first classification; a
report can be reclassified until closed) -> `analysed` (needs a
classification and an analysis) -> `closed` (from analysed). A closed
report is not changed (409 `occurrence_closed`); a report is classified
before it is analysed (409 `occurrence_not_classified`) and analysed
before it is closed (409 `occurrence_not_analysed`).

The risk classification scheme (376 Art. 7(2)) is configuration,
`OCCURRENCES_RISK_CLASSES`. Its default is the ECCAIRS occurrence class
list (`accident`, `serious_incident`, `incident`,
`occurrence_without_safety_effect`, `not_determined`), which has **not**
been checked against the ECCAIRS taxonomy (read from memory of the
taxonomy's labels, not from a source; Q-A12). The common European risk
classification scheme of Art. 7(5) is not implemented; changing the list
is a configuration change, and the classes already recorded keep their
value.

## The de-identified export

`POST /v1/occurrences/export` writes the reports **received** in
[`from`, `to`) in one format and answers `content` (the exact document),
`content_hash` (`sha256:` of the UTF-8 bytes of `content`), `size_bytes`
and `record_count`. The hash, size, format and count are recorded in
`occurrences.deidentified_exports` (no update, no delete) and in the
`occurrence_export_created` events row. To verify a filed copy, hash its
bytes and compare. A window holding more than
`OCCURRENCES_EXPORT_MAX_RECORDS` (5000) reports is refused
(`export_too_large`), never thinned: narrow the window.

Formats are pluggable (`internal/occurrences` `Exporter`); this build has
one, `eccairs-compatible-draft` (`OCCURRENCES_EXPORT_FORMAT`).

### What the export contains

No reporter organisation, report reference, reporter person, name or
address (376 Art. 16(3)). Left out as well: flight ids, authorisation
numbers and intent references (each leads back to an operator's account
at a USSP), evidence URLs, and the officers' analysis and follow-up
(working notes). Aircraft are given by serial and the registration
number's public part.

**The narrative is exported as the reporter wrote it.** It is free text
and may name people; every record says
`narrative_redaction: "not_redacted: ..."`. The officer reviews it and
redacts names before the record is filed (the console warns, WP-23). The
tests plant a name in every reporter and free-text field and find it in
the export only inside the narrative.

### Export field mapping

The layout is a draft. The ECCAIRS attribute column names what each
field is intended to map to; **none of it has been checked against the
ECCAIRS/ADREP taxonomy** (no copy of the taxonomy was available), so the
column is a plan, not a mapping.

| Export field | Source | ECCAIRS attribute (unverified) |
|---|---|---|
| `occurrence_id` | `occurrence_reports.occurrence_id` | the national file number |
| `reporting_channel` | `channel` (`mandatory`, `voluntary`) | report source / reporting form type |
| `reporter_category` | `origin`: `organisation` (USSP, ANSP) or `uas_operator` | reporter's category (organisation type only) |
| `occurrence_category` | `category` (376 Art. 4(1)) | occurrence category |
| `utc_date_time` | `occurred_at` | UTC date and UTC time |
| `became_aware_at` | `became_aware_at` | (none known; kept for the 72 h obligation) |
| `received_at` | `received_at` | date the report was received by the authority |
| `reported_within_deadline` | `within_72h` | (none known) |
| `risk_classification` | `risk_classification` (configured scheme) | occurrence class / risk classification |
| `state` | `state` | report status |
| `aircraft[].serial_number` | `aircraft[].serial` | aircraft serial number |
| `aircraft[].operator_registration` | `aircraft[].operator_reg` (public part) | operator / aircraft registration |
| `manned_aircraft[].icao24_address` | `manned[].icao24` | aircraft address (ICAO 24-bit) |
| `manned_aircraft[].callsign` | `manned[].callsign` | call sign |
| `minimum_separation.horizontal_m`, `.vertical_m`, `.at` | `min_separation` | horizontal and vertical separation (airprox) |
| `narrative` | `narrative`, as reported | narrative (reporter's language) |

### The open question (Q-A12, owner only)

Whether 376/2014 (with 2015/1018 for the UAS classes) or an equivalent
is in force in Georgia, whether ECCAIRS/ADREP **E5X** is the target
format, and whether GCAA is the single national intake (spec 08 Q9,
plan §14 Q-A12) are the owner's decisions. Until they are made the demo
default stands: the de-identified JSON above, tagged
`format: eccairs-compatible-draft`. An E5X writer is a later work
package that adds an `Exporter` and a format name; nothing else changes.

## Configuration

| Variable | Default | What |
|---|---|---|
| `OCCURRENCE_KEY_FILE` | unset | the occurrence key (one line of base64, `openssl rand -base64 32`); unset: references refused 503 |
| `OCCURRENCE_KEY_ID` | `occ-1` | stored beside every sealed reference |
| `PG_OCCURRENCES_ROLE` | `authority_occurrences` | the role of the occurrences pool |
| `PG_OCCURRENCES_MAX_CONNS` | 4 | the pool's size |
| `OCCURRENCES_REPORT_DEADLINE_S` | 259200 | the reporting deadline (72 h) |
| `OCCURRENCES_CLOCK_SKEW_S` | 300 | how far `became_aware_at` may be ahead of the database clock |
| `OCCURRENCES_RISK_CLASSES` | the ECCAIRS occurrence classes | the classification scheme |
| `OCCURRENCES_EXPORT_FORMAT` | `eccairs-compatible-draft` | the default export format |
| `OCCURRENCES_EXPORT_MAX_RECORDS` | 5000 | reports one export holds at most |
| `OCCURRENCES_WRITE_TIMEOUT_S` | 10 | bound on one transaction |

At start `api` logs `occurrences ready` (role, whether the key is held,
the deadline, the scheme, the formats), and at error level when the key
is missing. `/readyz` checks the occurrences pool (`occurrences`).

## Counters (status line and `/metrics`, group `occurrences`)

`occurrences_received`, `occurrences_received_late`,
`occurrences_replayed`, `occurrences_report_ref_conflict`,
`occurrences_refused_invalid`, `occurrences_refused_key_unavailable`,
`occurrences_reporter_org_ignored`,
`occurrences_operator_channel_mandatory`, `occurrences_reporter_viewed`,
`occurrences_reporter_does_not_open`, `occurrences_classified`,
`occurrences_analysis_updated`, `occurrences_exports`,
`occurrences_export_too_large`.

## Known limits

- The sender is the actor of the `occurrence_received` events row, so
  the audit log names the reporting organisation (a USSP's or the ANSP's
  client). For operator reports (WP-20) the portal's actor will be the
  operator's account; how the audit log protects that identity is
  WP-20's to decide with the DPO.
- Retention: reports are kept indefinitely (spec 05 §4); purging personal
  details per a DPO rule is a national choice not implemented here.
