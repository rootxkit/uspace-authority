# WP-3: registry

Branch `feat/WP-3-registry`. Milestone A-M1. Owns `internal/registry`,
the migrations for `uas_operators`, `uas`, `remote_pilots`,
`pilot_competencies`, `registry_status_changes`, the telemetry-database
projection tables `proj_registry_uas` and `proj_registry_operators`, and
the routes `/v1/registry/*` except `import`, `check` and `applications`
(WP-20). Depends on WP-1 (and WP-2 for roles; until WP-2 merges, routes
sit behind the `requireRole` placeholder). Consumers: WP-8, WP-14
(identification), WP-19, WP-20, WP-22.

Safety-relevant: the projection is what every identification rests on.
Reviewed adversarially.

## Read first

1. `docs/PLAN.md` §1.2 D2, D9, §4.1, §4.2, §5 registry rows, §14 Q-A10,
   Q-A11.
2. Spec `01` A1, A6, A12; `02 F8`; `03 §1` `uas_operators`, `uas`,
   `remote_pilots`, `03 §6` identifiers; `06 §5` (secret part hashed,
   national id hashed, status-only answers); `09 §1.3` 947 Art. 14 rows.
3. `uspace-core/regnum` (`NewValidator`, `PublicPart`, `CompareKey`),
   `serial` (`ValidateCTA2063A`, `ValidateForClass`, `Normalize`,
   `FoldKey`), `identify` (`OperatorFacts`, `UASFacts`, `Snapshot`,
   `Lookup`, `Match`) — the projection's columns are exactly what
   `identify.NewSnapshot` takes.
4. LESSONS G-01 (what statuses mean), G-04, G-05, G-06, G-07, G-08
   (projection), G-11, G-12, E-01, E-10; scenario SC-17.
5. Reference only: utm `api/uas_registry.py`, `api/uas_routes.py`,
   `gateway/registry_projection.py`,
   `infra/migrations/relational/versions/0005_uas_registry.py`,
   `infra/migrations/telemetry/versions/0009_uas_identity_projection.py`,
   `0010_projection_unregistered.py`.

## What to build

### Entities and lifecycle

- Operators: the 947 Art. 14(2) field set (`03 §1`), `operator_type`
  natural/legal, `registration_number_public` validated by
  `regnum.Validator` with the pattern from `authority_policy`
  (`registration_number_pattern`), `secret_part_hash` (salted SHA-256
  of the three-character secret when the authority issues one; never
  the clear value), PII columns (`full_name`/`legal_name`,
  `date_of_birth`, `legal_identification_number`, `postal_address`,
  `contact_email`, `contact_phone`, `insurance_policy_number`) encrypted
  with the PII key (AES-256-GCM, `key_id` column), `authorisations`
  JSONB (operational authorisations, LUCs, declarations), `status`
  active/suspended/revoked/expired with `status_reason`,
  `valid_from/until`, `source` portal/uas_gov_ge_import/manual.
- UAS: `serial` kept as given (G-05), `serial_fold` = `serial.FoldKey`
  (ASCII only, G-12), unique `(manufacturer_code, serial)` where the
  manufacturer code is the first four characters of a CTA serial and
  `serial` otherwise; `ValidateForClass(serial, class_label)` (G-06);
  `registration_mark`, `manufacturer`, `model`, `owner_ref`,
  `class_label`, `mtom_g`, `rid_capability`, `status`.
- Remote pilots: `person_ref_hash` (salted) and `person_ref_last4`
  (`06 §5`), `name` encrypted, `operator_id` nullable, competencies
  rows (`A1_A3`, `A2`, `STS_01`, `STS_02`, `national_*`) with
  `certificate_ref` and `valid_until`.
- Status transitions through one function with the allowed graph
  (active → suspended → active; → revoked terminal; expiry by job from
  `valid_until`), every transition an `events` row and a
  `registry_status_changes` row.

### Projection (G-08)

- `proj_registry_operators(operator_id, registration_number_public,
  status, projected_at, registry_version)` and `proj_registry_uas(uas_id,
  label, serial, serial_fold, registration_status, operator_id,
  in_registry, projected_at, registry_version)` in the telemetry
  database.
- Write path: inside the relational transaction, before commit, the
  service writes the affected rows to the projection (second
  connection); if that write fails the relational transaction is rolled
  back and the API returns 503 with the reason (SC-17 step 3).
  `registry_version` is a sequence incremented per change.
- Full re-projection at `api` startup and every 300 s under
  `pg_advisory_lock('registry_projection')`, held from the relational
  read to the projection write (SC-17 steps 4–5); rows with no registry
  entry are marked `in_registry = false`, never deleted silently
  (`0010_projection_unregistered` behaviour).
- Push: after commit, publish `registry.v1.changed` with
  `registry_version` (through the bus interface of WP-10; no-op until
  it merges) and set KV `registry_version`.
- `registry.ProjectionReader` (used by hot-path processes): loads the
  tables into an `identify.Snapshot`, refreshes every 5 s and on push,
  keeps the last snapshot on a failed read (SC-17 step 6), exposes
  `projection_age_s`, `rows`, counters.

### F8 validate and changes

- `GET /v1/registry/validate?operator=&serial=&pilot=` and the batch
  `POST`: per entity `valid` / `suspended` / `revoked` / `unknown`,
  `valid_until`, `class_label` and `mtom_band` for a UAS, competency
  set for a pilot. **No names, addresses, phones or emails**: the
  response type has no such field, and a test greps the OpenAPI response
  schema for the PII property names and fails if any appears. Scope
  `registry.validate`; `purpose` query parameter required ∈
  `authorisation` / `identification`; every call an `events` row with
  the caller's `sub` (one client per USSP).
- `GET /v1/registry/changes?since=<seq>` from `registry_status_changes`,
  ids and statuses only, paged, `ETag`.
- Registrar CRUD routes per plan §5 with role checks; reads of PII
  fields require `purpose` and are audited as `pii_view`.

## Tests

- Unit: every validation refusal beside its acceptance (bad pattern,
  hyphen in a registration number, wrong class serial, duplicate
  serial, ambiguous fold); status graph.
- Vectors: `serials_and_registration.json` and
  `identification_status.json` through `RunOwned("authority")` where the
  cases exercise registry rows → `UASFacts`/`OperatorFacts` mapping
  (the registry fixtures become projection rows; the judgement is
  core's).
- Integration: projection written with the change, rolled back when the
  projection write fails (inject a constraint), repaired by the 300 s job
  after a row is deleted by hand, lock ordering with a concurrent change;
  `ProjectionReader` keeps its snapshot through a dropped connection
  (E-02); validate answers for each status; the change feed pages.
- E-10: batch validate bounded (≤ 100 entities).

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] A-M1 registry items demonstrated in the integration test: an
  operator with every Art. 14(2) field, a pilot and two UAS registered,
  one suspended, looked up by number and serial; validate returns
  status only; every change audited.
- [ ] SC-17 steps 2–6 pass as a timed integration test (change visible
  to a reader within 5 s + transaction time).
- [ ] CHANGELOG line; `internal/registry/doc.go`.

## Commits

`feat(registry): operators, UAS and remote pilots with the Art. 14 field set [WP-3 A-M1]`,
`feat(registry): project registry facts into the telemetry database with the change [WP-3 A-M1]`,
`feat(registry): status-only validity lookups and the change feed for USSPs [WP-3 A-M1]`,
`test(registry): a registry change reaches a reader within the refresh (SC-17) [WP-3 A-M1]`.
