# Zones and U-space airspaces (WP-5)

How the authority authors geo-zones and U-space airspace designations,
imports ED-318 and ED-269 files, publishes them towards the CISP and
projects them for the detectors. The code is `internal/zonesvc`; the
contract is `api/openapi.yaml` (`/v1/zones*`, `/v1/uspace*`).

## Authoring flow

| Step | Who | Call | Result |
|---|---|---|---|
| Author | inspector | `POST /v1/zones` `{feature, valid_from, valid_to}` | version 1, `draft` |
| Revise | inspector | `PUT /v1/zones/{identifier}` (same body) | the next version, `draft`; the identifier's unpublished versions become `superseded` |
| Check | anyone with a read role | `GET /v1/zones/{identifier}/applies?at=` | `applies`, `not_applicable` or `unknown` with the reason |
| Approve | admin | `POST /v1/zones/{identifier}/approve` `{zone_version}` | `approved`; only the newest version, only a draft |
| Publish | admin | `POST /v1/zones/publish` | every approved version `published`; older published versions `superseded`; the outbox row; the projection; the announcement |
| History | read roles | `GET /v1/zones/{identifier}/versions` | every version, newest first |
| Export | read roles | `GET /v1/zones/export[?at=|?applies_at=]` | ED-318 `FeatureCollection` |

U-space airspaces follow the same steps under `/v1/uspace` (admin only):
the body carries the USPACE feature, `designated_from`, `designated_to`
and `designation` (services, the Art. 3(4) members, adjacent airspaces,
references); `designate` is the approval. The service writes the Art.
3(4) block into the feature's `extendedProperties.uspace_requirements`
in the CISP's `cis/uspace_requirements/v1` shape; a feature that brings
its own block is refused. A publication whose airspace names an
adjacent airspace that is not in it is refused (409), naming it.

Rules every write follows:

- The feature is an ED-318 UASZone feature that uspace-core
  `ed318.Parse` accepts; it is stored exactly as `ed318.Export` writes
  it and never repaired. Problems come back by JSON path
  (`feature.properties.type`).
- The period of validity is mandatory (2019/947 Art. 15(3)); `valid_to`
  after `valid_from`.
- The zone must be judgeable: every ring closed and at most 5000
  positions, limits finite with their reference, a lower limit below an
  upper one in the same reference, and an applicability the judgement can
  evaluate (a schedule by daylight events needs `startDateTime` and
  `endDateTime`, at most 366 days apart).
- Identifiers are at most 7 characters, unique across zones and U-space
  airspaces, and never `export`, `import` or `publish`.
- `WGS84` as a vertical reference is accepted and listed in the answer's
  `extensions`: it is this project's extension (height above the
  ellipsoid), not a published ED-318 reference.

## What the console shows

- `state` of every version, `published_version` (the zones version of
  its publication), who created, approved and published it, and when.
- `extensions` beside a zone that uses WGS84.
- The publication's outbox row: `pending` with `signature` null until
  WP-6 signs and sends it; its "not yet published" age is WP-6's.
- Applicability: `unknown` is never shown as "applies" or "does not
  apply". A zone scheduled by BMCT, SR, SS or EECT is resolved from its
  position by the ground package's daylight (core's NOAA calculator,
  WP-11); where the sun does not reach the event that day it is
  `unknown` with the reason. Were no daylight source available, the
  preview would answer 503 `daylight_unavailable` and the detectors'
  status line would name the zone in `zones_not_judged`.

## UNVERIFIED notes inherited from uspace-core ed318

The EUROCAE ED-318 text is not available to the project. These readings
are core's and stay unverified until a licensed copy is checked; the
console must not present them as the standard's:

- The names of a zone's vertical limits: the geometry's `layer` object
  with `upper`, `upperReference`, `lower`, `lowerReference` and `uom`, as
  the ED-318 JSON schema and InterUSS `uas_standards` show them.
- An absent `uom` means metres (the schema's statement).
- A circle's radius (a `Point` with an `extent` of `subType` `Circle`) is
  in metres, whatever the layer's `uom` (which governs the vertical
  limits only). A radius above 1000 km is refused.
- A `MultiPolygon` is refused whole in this release, never imported part
  by part.

## Import

`POST /v1/zones/import` takes the file's bytes
(`Content-Type: application/octet-stream`, at most 4 MiB; a UTF-8 byte
order mark is accepted) and `valid_from` / `valid_to` (else the ED-318
collection's `metadata.validFrom` / `validTo`; without either the import
is refused). The format is detected by the wrapper: a top-level `type`
is ED-318; `UASZoneList`, or `features` without `type`, is ED-269. The
import is all or nothing: one draft per zone in one transaction, or a
400 listing every problem by JSON path (`features[3].restriction`), at
most 100 with `truncated: true` beyond. An existing identifier gets its
next version.

ED-269 rules (uspace-core `ed269.Parse` and `ed318.FromED269`):

- Read strictly: unknown fields, wrong types, values outside an
  enumeration, over-length strings, unclosed rings and periods that
  cannot be evaluated are refused.
- `REQ_AUTHORIZATION` with a Z is refused by name: ED-269 spells it
  `REQ_AUTHORISATION`.
- A zone with more than one volume is refused, never half-imported.
- What ED-318 cannot hold is refused by name: a `FOREIGN_TERRITORY`
  reason, a zone without an authority, an authority without a purpose.
- `M` and `FT` become the layer's `m` and `ft`; a `Circle` becomes a
  `Point` with a `Circle` extent, its radius in metres; ED-269 fields
  without an ED-318 member travel in `extendedProperties.ed269`.

### airspace.gov.ge

The site publishes no feed, no limits and no times (LESSONS Z-13). Save
`/Airspace/leaflet/zone/points.js` and the page from a browser, write the
rules with the authority, and post them:

```
POST /v1/zones/import/airspace-gov-ge
{
  "points_js": "<the saved points.js>",
  "page_html": "<the saved page>",
  "valid_from": "2026-10-01T00:00:00Z",
  "valid_to": "2027-10-01T00:00:00Z",
  "rules": {
    "country": "GEO",
    "authority": {"name": "<authority>", "purpose": "AUTHORIZATION"},
    "kinds": {
      "CTR": {"restriction": "REQ_AUTHORISATION", "uom": "M",
              "lower_reference": "AGL", "lower_limit": 0,
              "upper_reference": "AGL", "upper_limit": 120,
              "applicability": [{"permanent": "YES"}],
              "reason": ["AIR_TRAFFIC"]}
    },
    "identifiers": {"UGR01_EPR": "UGR01"}
  }
}
```

- A polygon is `var NAME_points = [[lat, lon], ...];` (the site's order,
  latitude first), closed if the site left it open; a circle's centre is
  `var NAME_point = [lat, lon];` and its radius, in metres, is the
  page's `L.circle(NAME_point, {radius: <m>})`.
- The kind is the last `_` part of the variable name; every kind needs a
  rule, and nothing in a rule has a default (each value decides alerts).
  A kind without a rule, a circle without a radius, or an identifier
  longer than 7 characters (the name without `_`, unless `identifiers`
  gives one) refuses the conversion, naming the zone.
- The result is an ED-269 document imported exactly as above. No real
  data is kept in this repository.

## Projection and readers

`proj_zones` in the telemetry database holds every published version
whose period has not ended. It is rewritten whole with each publication
(before the relational commit; a failure rolls the publication back with
503 `projection_unavailable`) and by the re-projection at startup and
every `ZONES_REPROJECT_S` (300 s), which restores a deleted row and
deletes a row the relational database no longer holds. Readers rebuild
their `zones.Index` on `zones.v1.changed`, every 60 s, and at the instant
a period starts or ends; a failed read keeps the index held. Counters:
`zones_projection_write_failed`, `zones_projection_ahead`,
`zones_reprojected`, `zones_reproject_failed`,
`zones_projection_rows_deleted`, `zones_announce_failed`,
`zones_projection_read_failed`, `zones_not_judged`.

## Known gap

ED-318 has no per-feature period of validity. A publication carries the
versions in force when it is made; a version whose period starts later
reaches the CISP with the next publication. The authority's own export
and projection hold every period.
