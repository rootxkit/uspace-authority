# Importing the registry of uas.gov.ge

How the authority's registry takes the operators and aircraft GCAA
already registered on uas.gov.ge (WP-20; spec 03 §1
`uas_operators.source`, 08 Q4; `docs/PLAN.md` Q-A11; LESSONS G-11).
`api` serves `POST /v1/registry/import` to registrars and, when the
agreed URL is configured, re-imports on a period. Nothing here scrapes
a website, follows a redirect or reads uas.gov.ge without an
agreement.

**Pending GCAA.** Whether the authority becomes the registry of record
or mirrors uas.gov.ge, what export exists, its format, its cadence and
the data-sharing agreement are open (spec Q4). No export has been seen.
This build reads any CSV or flat JSON export through a rules file and
ships the spec's defaults (below); the defaults are not policy answers.

## The agreement needed with GCAA

Before the first import, agree in writing:

1. **The legal basis** for the authority to hold the Art. 14(2) data of
   every registered operator (Law of Georgia on Personal Data
   Protection; the DPO's DPIA, spec 06 §5).
2. **The access method** (G-11): a file handed over, or an export URL
   with its credential (`REGISTRY_IMPORT_URL`, `REGISTRY_IMPORT_TOKEN_FILE`).
   https only; the job follows no redirect.
3. **The export's contents**: one file of operators and one of aircraft,
   each record with a stable id that never changes or is reused (the
   import is idempotent on it), and the columns of the field set below.
4. **The value lists**: how the export writes operator types, statuses
   (and which of them means revoked), classes and Remote ID capability.
5. **The registration-number format** (spec Q5): the export's pattern,
   whether numbers carry the EU secret part, and whether it matches the
   policy's `registration_number_pattern` (G-07).
6. **Dates and units**: the date formats, the UTC offset of dates
   without one (Georgia is +04:00), masses in grams or kilograms.
7. **The cadence** (`REGISTRY_IMPORT_EVERY_S`, one day by default) and
   who at GCAA answers for a refused export.

The rules file records points 3 to 6. It is configuration, kept with the
deployment's secrets, never committed with real data; the repository
holds only the synthetic file of the tests
(`internal/regimport/testdata/rules.json`, `GEOTEST*` numbers, `TEST*`
serials).

## The rules file

`REGISTRY_IMPORT_RULES_FILE` names one JSON object (at most 1 MiB).
`api` checks it whole at start and does not start on a bad one, naming
every field at fault (`rules.<path>`). Without it, an import is refused
`503 import_not_configured`. An abridged example (the `"..."` members
stand for the rest; the complete synthetic file is
`internal/regimport/testdata/rules.json`):

```json
{
  "rules_version": "gcaa-2026-10",
  "format": "csv",
  "csv": {"delimiter": ";"},
  "registration_number_pattern": "GEO[A-Za-z0-9]{12}",
  "secret_suffix": true,
  "date_formats": ["DD.MM.YYYY", "YYYY-MM-DD", "RFC3339"],
  "utc_offset": "+04:00",
  "mtom_unit": "kg",
  "operators": {
    "columns": {"source_id": "Record ID", "registration_number": "Reg No", "operator_type": "Type", "...": "..."},
    "values": {
      "operator_type": {"Physical person": "natural", "Legal person": "legal"},
      "status": {"Active": "active", "Suspended": "suspended", "Cancelled": "revoked"}
    },
    "defaults": {"status": "active"}
  },
  "uas": {
    "columns": {"source_id": "Record ID", "serial": "Serial", "operator_registration_number": "Operator", "...": "..."},
    "values": {"rid_capability": {"broadcast": "direct", "no": "none"}},
    "defaults": {"rid_capability": "none"}
  }
}
```

| Member | Meaning |
|---|---|
| `rules_version` | 1 to 64 of `[A-Za-z0-9._-]`; named in every import's events row and ledger row. Content run under one version is run again under another. |
| `format` | `csv` or `json`: the format of the fetched export. An upload says its own by `Content-Type` (`text/csv` or `application/json`). |
| `csv.delimiter` | one character; `,` by default. The first row is the header; a byte-order mark is tolerated; every row has the header's columns. |
| `registration_number_pattern` | the export's own shape, checked before the registry's (the policy's pattern, G-07); empty checks only the policy's. Anchored. |
| `secret_suffix` | `true` splits `<public>-<3 letters or digits>` into the number and its secret part. The secret part is stored only as the registry's keyed hash; a hyphen is never registered (G-04). A `secret_part` column does the same. |
| `date_formats` | tried in order: tokens `YYYY MM DD hh mm ss`, `T` and punctuation, or `RFC3339`. A date without a time is the start of that day at `utc_offset`, and for `valid_until` the start of the next (valid through that day). |
| `utc_offset` | `+HH:MM` or `-HH:MM`, required. |
| `mtom_unit` | `g` (default) or `kg`; masses become whole grams. |
| `<kind>.columns` | registry field to the export's column. |
| `<kind>.values` | per field, the export's value to the registry's, compared trimmed and with ASCII letters folded (G-12). A value the map does not name is a problem; nothing is guessed. |
| `<kind>.defaults` | the registry's value of a field whose column is absent or empty. Not for ids (`source_id`, numbers, serials). |

Operator fields: `source_id`, `registration_number`, `secret_part`,
`operator_type` (`natural`, `legal`), `full_name`, `legal_name`,
`date_of_birth`, `legal_identification_number`, `postal_address`,
`contact_email`, `contact_phone`, `insurance_policy_number`,
`competency_confirmation` (`true`, `false`), `valid_from`,
`valid_until`, `status` (`active`, `suspended`, `revoked`). Required:
`source_id`, `registration_number`, `operator_type`, `valid_until`,
`status`, and what the registry requires of the type (Art. 14(2)).

Aircraft fields: `source_id`, `serial`, `operator_registration_number`
(the owner, registered already), `class_label` (`C0`..`C6` or empty),
`mtom`, `manufacturer`, `model`, `registration_mark`, `owner_ref`,
`rid_capability` (`direct`, `network`, `both`, `none`), `status`.
Required: `source_id`, `serial`, `operator_registration_number`,
`rid_capability`, `status`. The class decides whether the serial must be
CTA-2063-A (G-06).

## What an import does

- **One file, one kind, operators first.** An aircraft names an operator
  registered already (by any source).
- **All or nothing.** One transaction under the projection lock, one
  registry version. With any problem nothing is written and the answer
  is `422 import_refused` listing every problem by record and field,
  `records[<n>].<field>` (n = 1 is the first record after the header),
  the column named in the reason, at most 100 with `truncated`.
- **Idempotent on the record's id.** A record imported before
  (`source = uas_gov_ge_import`, `source_ref` = its id) is updated where
  it differs (the report names the fields, never the values) and moved
  to its status; one that matches is left alone (`unchanged`). The same
  file twice changes nothing the second time.
- **Identity never changes.** A record whose number, operator type,
  start of validity, secret part, serial or owner changed is a problem:
  revoke it and register again. A number already registered by hand or
  through the portal is a problem, never taken over. A revoked record
  listed as anything else is a problem (revoked is final).
- **Expiry is the registry's.** A registration past its `valid_until`
  is expired by the registry's job; an export that still lists it
  active leaves it expired, and renews it once its `valid_until` moves.
- **A record the file does not list is not touched.** An export may be
  partial; revoking what it leaves out would be a guess.
- **Projection.** A tightening change (suspend, revoke, an edit) is
  projected before the commit and a failed write rolls the import back
  (`503 projection_unavailable`); a loosening one (a new record, a
  status becoming active) after it, repaired if it fails (G-08).
- **Bounds** (E-10): `REGISTRY_IMPORT_MAX_BYTES` (8 MiB, 413 beyond),
  `REGISTRY_IMPORT_MAX_ROWS` (2000 records, 400 beyond), 4096 bytes a
  value, 256 columns, and `REGISTRY_IMPORT_WRITE_TIMEOUT_S` (25 s, inside
  the listener's 30 s write timeout) on the transaction: an import past
  it is rolled back and answered `503 import_timeout`, never committed
  after its caller was cut off. When the bound falls during the COMMIT
  itself the database may have committed or not: the answer is
  `503 import_outcome_unknown`, nothing reaches the ledger, and a
  `registry_imported` event with the content's SHA-256 says whether it
  was written (running it again changes nothing if it was). A first import of 5000 records took
  about 18 s on the development stack (a re-import of them, unchanged,
  about 2 s). The import holds the registry's projection lock while it
  runs, so other registry changes wait for it; split a larger export.
- **Audit.** Every import is an events row with its counts, the SHA-256
  of the bytes read and the rules version: `registry_imported`,
  `registry_import_refused` or `registry_import_dry_run`; each entity it
  writes has its own row (`operator_registered`, `operator_updated`,
  `registry_status_changed`, ...). Every import run to an outcome is a
  `registry_imports` row (append-only).

## The dry-run procedure

1. Put the agreed rules file in place and restart `api`; the start line
   `registry portal` says `import_rules: true`.
2. Dry-run the operators:

   ```
   POST /v1/registry/import?kind=operators&dry_run=true
   Content-Type: text/csv

   <the export>
   ```

   The answer is the report: `records`, `created`, `updated`,
   `unchanged`, every problem, and per record what would be done.
   **Read it** (E-02): a report of zero records means the header did not
   match the rules, not an empty registry.
3. Fix the export with GCAA, or the rules file, until the dry run lists
   no problem. Nothing is written by a dry run but its events row.
4. Import the operators (the same request without `dry_run`), then
   dry-run and import the aircraft (`kind=uas`).
5. Check a few numbers through `GET /v1/registry/check?number=` and the
   registry's own reads.

## The periodic re-import

With `REGISTRY_IMPORT_URL` set (`{kind}` replaced by `operators` and
`uas`), `api` fetches both exports every `REGISTRY_IMPORT_EVERY_S`
under a job lock (one replica runs it) and imports them as an upload
would, as `registry_import_job`. Content the ledger shows was run to an
outcome before under the same rules is not run again: an applied export
would change nothing, and a refused one stays refused until GCAA
changes it (a refusal is permanent, never retried in a loop). A failed
fetch (unreachable, not 200, larger than the bound, a redirect) is
counted (`registry_import_fetch_failed`), logged and waits for the next
period.

## Configuration

| Variable | Default | |
|---|---|---|
| `REGISTRY_IMPORT_RULES_FILE` | unset | the rules file; unset: imports 503 |
| `REGISTRY_IMPORT_URL` | unset | the agreed export URL with `{kind}`; https (http to loopback only) |
| `REGISTRY_IMPORT_TOKEN_FILE` | unset | its bearer token, if agreed |
| `REGISTRY_IMPORT_EVERY_S` | `86400` | the re-import period (pending GCAA) |
| `REGISTRY_IMPORT_TIMEOUT_S` | `60` | one fetch |
| `REGISTRY_IMPORT_MAX_BYTES` | `8388608` | one export |
| `REGISTRY_IMPORT_MAX_ROWS` | `2000` | records of one export (at most 50000; pending GCAA) |
| `REGISTRY_IMPORT_WRITE_TIMEOUT_S` | `25` | one import's transaction (at most 25) |

Counters: `registry_import_applied`, `registry_import_refused`,
`registry_import_dry_run` (registry); `registry_import_not_configured`,
`registry_import_unreadable`, `registry_import_ledger_failed`,
`registry_import_fetched`, `registry_import_fetch_failed`,
`registry_import_fetch_unchanged`, `registry_import_fetch_skipped`,
`registry_import_timeout`, `registry_import_commit_unknown`.
