# WP-5: zones and U-space airspace authoring

Branch `feat/WP-5-zones`. Milestone A-M1. Owns `internal/zonesvc`, the
migrations for `geo_zones` and `uspace_airspaces`, the projection table
`proj_zones`, and the routes `/v1/zones/*` and `/v1/uspace/*` (the
publish endpoints enqueue through WP-6's outbox; until it merges they
write the `publications` row through an interface). Depends on WP-1.
Consumers: WP-6, WP-12, WP-13, WP-22, WP-26.

## Read first

1. `docs/PLAN.md` §1.2 D2, §4.1, §4.2, §5 zone rows.
2. Spec `01` A2, A3; `02 F1` (the ED-318 feature shape and the Art. 3(4)
   block in `extendedProperties`); `03 §1` `geo_zones`,
   `uspace_airspaces`; `04 §3.4`; `09 §1.6`; `08` Q2, Q6, Q17.
3. `uspace-core/ed318` (`Parse`, `Export`, `FromED269`, `ToED269`,
   `ToZones`, `Applies`, `Daylight`, the UNVERIFIED notes in its
   `doc.go`), `ed269` (`Parse`, `Problems`, `Limits`), `zones`
   (`Zone`, `NewIndex`), `geodesy` (`ValidRing`).
4. LESSONS Z-01..Z-07, Z-11, Z-12, Z-13, T-09, INV-03; scenarios SC-12,
   SC-13.
5. Reference only: utm `api/zones.py`, `api/zone_routes.py`,
   `airspace/ed269.py`, `tools/gov_ge_zones.py`,
   `infra/migrations/relational/versions/0007_geo_awareness.py`.

## What to build

- `geo_zones`: one row per zone version; the ED-318 `UASZone`
  properties as columns for querying (`identifier`, `country`, `name`,
  `type`, `variant`, `reason[]`, `restriction_conditions`, `region`,
  `regulation_exemption`, `message`) plus `feature` JSONB holding the
  exact ED-318 feature as exported by core (the master copy; columns
  are derived from it in the same transaction and a test proves
  `Export(Parse(feature))` equals it by value), `geom` (polygon) or
  `center`+`radius_m` (circle, judged by centre and radius, Z-11; the
  polygon drawn for a circle is for display only and lives in a
  separate column), `lower_m`/`lower_ref`/`upper_m`/`upper_ref` with
  the original unit kept in `ed318_extra`, `limited_applicability`
  JSONB, `zone_authority` JSONB, `data_source`, `extended_properties`,
  `zone_version`, `valid_from`, `valid_to` (period of validity is
  mandatory, 947 Art. 15(3): a zone without one is refused), `state`
  draft/approved/published/superseded, `published_version`,
  `created_by`, `approved_by`.
- `uspace_airspaces`: `03 §1` columns; the Art. 3(4) block
  (`uas_requirements`, `service_performance` with `nid_update_hz`,
  `ti_update_hz`, `cis_latency_s`, `operational_conditions`,
  `airspace_constraints` including any height ceiling),
  `services_required[]` (NID, GEO, FA, TI always; WX, CM optional),
  `adjacent_ids[]`, `in_controlled_airspace`, `ats_provider_id`,
  `cisp_id`, `designated_from/to`, `designation_ref`,
  `risk_assessment_ref`, `aip_ref`. Exported as `USPACE` zones with the
  block in `extendedProperties` in the shape of the CISP's
  `cis/uspace_requirements/v1` (the CISP owns that schema, M7); the
  export is validated in CI against the pinned copy of the CISP's
  schema that WP-6's `api/clients/cisp.yaml` + `SOURCE` mechanism
  carries, never against a local reading of `02 F1`.
- Authoring API (plan §5): create a draft version, replace (new
  version), approve, publish (creates the `publications` outbox row for
  dataset `zones` or `uspace_airspace` with the full current set),
  history, `GET /v1/zones/export?at=` giving the ED-318
  `FeatureCollection` in force at `at` (collection metadata in core's
  `ed318.Metadata` names, `issued` and `provider` from config, never
  the spec's `creationDateTime`/`updateDateTime`/`originator`, which
  core's `Parse` on the CISP would not carry; M15, spec erratum) and
  `GET /v1/zones/export?applies_at=<RFC 3339>` annotating every
  feature with `extendedProperties.cis_applicability` ∈ `applies` /
  `not_applicable` / `unknown` without filtering (M17; a console shows
  "not applicable now" from one fetch; `at` and `applies_at` together
  are refused), and
  `POST /v1/zones/import` accepting ED-318 or ED-269 (detected by
  wrapper): all or nothing, every problem by JSON path and reason (Z-02),
  an ED-269 import mapped through `ed318.FromED269` with what cannot be
  held refused by name; the `airspace.gov.ge` importer accepts a rules
  file (`Z-13`; format documented, no real data in the repo).
- Validation on every write through `ed318.Parse` of the exported
  feature (never repaired), `geodesy.ValidRing` bounds, applicability
  evaluable (Z-04, Z-07), the `WGS84` vertical reference accepted and
  flagged in the response as this project's extension (Z-05).
- Applicability preview: `GET /v1/zones/{identifier}/applies?at=` using
  `ed318.Applies` with a `Daylight` implementation from `internal/ground`
  (sunrise/sunset from position; until WP-11 merges, a documented stub
  that refuses daylight events with a named problem rather than
  guessing).
- Projection: `proj_zones(identifier, zone_version, feature JSONB,
  valid_from, valid_to, type, bbox, projected_at, zones_version)` in the
  telemetry database holding every published version in force (both
  datasets); written with the publish transaction (same discipline as
  WP-3), re-projected every 300 s under an advisory lock; push
  `zones.v1.changed` and KV `zones_version`. `zonesvc.ProjectionReader`
  loads the rows through `ed318.Parse` → `ed318.ToZones` into a
  `zones.Index`, refreshes on push and every 60 s, keeps the last index
  on failure, exposes `projection_age_s` and the list of zones that need
  terrain or geoid (Z-09; the error-level status line is WP-12's).

## Tests

- Vectors: `ed318_roundtrip.json` and `zones_applicability.json`
  through `RunOwned("authority")` over the service's import → store →
  export path (core judges; this proves the storage round trip changes
  nothing).
- Unit: every refusal beside its acceptance (missing validity, bad ring,
  unevaluable schedule, Z-spelling in ED-269, two volumes, WGS84 flagged
  but accepted); version transitions; circle stored as centre and
  radius.
- Integration: import a Luxembourg-sized synthetic ED-269 file
  (generated in the test, ≤ 1400-vertex zone); publish; projection
  written and read back as a `zones.Index` with the right candidates for
  a point; re-projection repairs a deleted row; `export?at=` returns the
  version in force at two instants around a change; `export?applies_at=`
  returns every feature with the three annotation values exercised
  (E-01: one of each).
- E-10: import bounded by `ed269.DefaultLimits`; a document past the
  byte cap refused with the reason.

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] A-M1 zone item through the API: author → approve → publish → outbox
  row with a signed payload (signature from WP-6; until then the row is
  `pending` with `signature` null and a test marks that explicitly).
- [ ] `docs/runbooks/zones.md`: authoring flow, ED-269 import rules,
  the UNVERIFIED notes inherited from core restated for the console.
- [ ] CHANGELOG line; `internal/zonesvc/doc.go`.

## Commits

`feat(zonesvc): versioned ED-318 geo-zones and U-space designations [WP-5 A-M1]`,
`feat(zonesvc): all-or-nothing ED-318 and ED-269 import with problems by path [WP-5 A-M1]`,
`feat(zonesvc): project published zones into the telemetry database [WP-5 A-M1]`,
`test(zonesvc): ED-318 round trip and applicability vectors through storage [WP-5 A-M1]`.
