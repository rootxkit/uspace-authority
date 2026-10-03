# Incidents and evidence packs

The authority's own case files and the sealed evidence that goes with
them (spec 01 A10, 02 F7 and F10, 03 §1, 05 §4, 06 §2 T6-T7, 06 §5;
WP-17). `api` serves them under `/v1/incidents*` to inspectors and
incident officers. Nothing here alerts anyone or acts on an aircraft:
an incident is a record for people.

## The workflow

1. **Open.** An incident is opened in one of three ways:
   - an inspector escalates a violation (`POST
     /v1/violations/{id}/review` with `decision: escalated`; a note is
     required when the evidence is broadcast only, 06 §2 T1). The
     incident is opened in the same transaction (`kind:
     violation_escalated`, `opened_from: violation`, one incident per
     violation, the review note as its first narrative, the aircraft as
     the violation identified it). An escalation recorded before this
     release (`incident_requested`) is opened by the backfill job within
     `INCIDENTS_BACKFILL_S`;
   - `POST /v1/incidents` with `opened_from: own_observation`;
   - `POST /v1/incidents` with `opened_from: ansp_notice` or
     `ussp_notice` and the notice's `notice_ref`.

   An incident is never opened from an occurrence report (376/2014 Art.
   15-16); occurrences live in their own schema (WP-18) and nothing here
   reads them.
2. **Work the case.** `PATCH /v1/incidents/{id}`: `assignee` and
   `status: assigned`, `note` (append-only; at most 500), `add_aircraft`
   (at most 32), `intent_refs`, `narrative`, `severity`. A closed
   incident can always be reopened (`status: open` or `assigned`).
   Every change is one `incident_updated` events row naming each change
   with its old and new value.
3. **Build a pack.** `POST /v1/incidents/{id}/evidence-packs` with
   `kind`, `from`, `to` and `purpose` (and `case_ref` for a legal pack).
   The answer is the pack's manifest, hash and signature.
4. **Hand it over.** `GET .../evidence-packs/{pack}/download?purpose=...`
   serves the archive; `GET .../verify` re-checks the stored archive.

## An aircraft of an incident

| Field | Meaning |
|---|---|
| `serial` | As broadcast or provided; never verified here. |
| `operator_reg` | The registration number's **public part** only. A secret part sent (`FIN87astrdge12k8-xyz`) is dropped by uspace-core `regnum` under the active policy's pattern and never stored (06 §5). |
| `track_ids` | The tracks of the aircraft (at most 16). |
| `identification` | The identification as judged at the time (`status`, `reason`, `basis`, `evidence_trust`), as recorded. |

## What a pack holds

A ZIP archive with fixed timestamps and entries in name order, so the
same evidence always gives the same bytes:

| File | Section | Basis | What |
|---|---|---|---|
| `manifest.json` | | | The manifest (below), with the SHA-256 of every other file. |
| `incident.json` | `incident` | recorded | The incident, its aircraft and notes. |
| `violations.json` | `violations` | observed | The incident's violation and every violation of its aircraft (track or serial) open in the window, with their evidence excerpts. |
| `tracks/NNNN.json` | `tracks` | observed | One file per track: the samples as stored in `tracks`, cut into `segments`, with the `holes` between them. Nothing is interpolated or resampled. |
| `raw_frames.json` | `raw_frames` | observed | The raw Remote ID frames of the transmitters that broadcast the aircraft's serial in the window (R-15), with what was decoded from them and each payload's SHA-256. |
| `writer_gaps.json` | `writer_gaps` | recorded | Every batch of the tracks or frames table tsdb-writer recorded as dropped or spilled in the window. |
| `ussp_flights.json` | `ussp_flights` | received | The Display Provider's rows of the tracks, while still held (24 h, F3411). |
| `manned_tracks.json` | `manned_tracks` | received | The ANSP's manned traffic (WP-15) placed in the window inside the extent of the evidence's positions padded by `INCIDENTS_MANNED_MARGIN_M` (10 km): what an airprox is weighed against. `alt_pressure_m` is pressure altitude, never AMSL; `alt_wgs84_m` is null when the source gave none. `none` says an ANSP feed outage leaves no row: read `writer_gaps` and the `ansp_feed` status first. |
| `ussp_records/NN.json` | `ussp_records` | received | The USSP's service record of each USSP flight of the pack (`GET {base_url}/v1/records/flights/{id}`, scope `ussp.records`, fetched while the pack is built; 02 F7, Q-A18), verbatim. |
| `zones.json` | `zones` | recorded | The zone versions the violations name and every published version in force in the window over the evidence's extent, each ED-318 feature verbatim as authored. |
| `policies.json` | `policies` | recorded | Every `authority_policy` version the violations were judged with and the one active at build. |
| `events.json` | `events` | recorded | Every audit row of the incident, its packs and its violations, with `prev_hash` and `hash` (T7). The pack's own `evidence_pack_built` row follows them. |
| `personal_data/operators.json` | `personal_data` | recorded | Legal packs only (below). |

The manifest (`evidence-pack/v1`; also in `GET .../evidence-packs/{pack}`)
holds:

- `sections`: per section its `state` (`included`, `none`,
  `unavailable`, `withheld`), the `reason` when not included, its
  `basis` (`observed` by this system, `recorded` by its people or
  processes, `received` from a peer, `inferred`) and its files. **A
  source that could not be read is `unavailable` with the reason; it is
  never silently missing.**
- `segmenting`: the `max_gap_s` and the policy version that cut the
  tracks.
- `tracks`: per track its file, samples, segments and holes.
- `agl_numbers`: every height above ground in the pack with the ground
  dataset and spacing it was taken from (D-05), or `unavailable` when
  detection recorded none.
- `ussp_records`: per USSP flight its state and reason.
- `frame_payloads_withheld`, `redaction`, `inferred` (what the pack
  infers rather than observes, E-04), `files` (path, SHA-256, size).

The manifest never holds personal data, whatever the kind.

## What each hole label means

A track is cut into segments; the interval between two segments (or a
run of samples without a position at either end) is a hole with every
cause known of it:

| Cause | Meaning |
|---|---|
| `silence` | No sample of the track for longer than the active policy's `max_gap_s` (3 s by default). |
| `no recorded cause` | Beside `silence` when nothing recorded explains it: the aircraft may have been out of coverage, landed, switched off, or the broadcast lost. Nothing is assumed. |
| `writer_gap` | tsdb-writer recorded a dropped or spilled batch of the tracks or frames table inside the hole (`recorded` lists each: table, cause, count, stream sequence). Attributed by time: the lost rows may or may not have been this aircraft's. Cuts the track even inside `max_gap_s`. |
| `sample_without_position` | A Location frame of the aircraft's transmitter arrived with an unknown position (R-01). Cuts the track even inside `max_gap_s`. |
| `frame_undecodable` | A frame of the aircraft's transmitter could not be decoded; the raw frame is in `raw_frames.json`. |

A frame is linked to a track through the transmitters that broadcast
the track's serial in the window (a Location frame carries no serial);
a frame of a Message Pack without a decoded position is not counted as
`sample_without_position` (its content is not known here).

## Sealing, storage and verification

- `content_hash` is `sha256:` and the hex SHA-256 of the archive. It is
  in `evidence_packs` (immutable: a trigger refuses `UPDATE` and
  `DELETE`, also for the owner) and in the `evidence_pack_built` events
  row with the purpose (T7).
- The **seal statement** (`evidence-pack-seal/v1`: pack, incident, kind,
  window, hash, size, creation time on the database's clock, author) is
  signed as a detached JWS (RFC 7797, `b64: false`) by the publication
  key (`PUBLICATION_KEY_FILE`), the key whose public half is in this
  issuer's JWKS. The statement is rebuilt from the stored row to verify,
  so a changed row breaks the signature. Without a publication key a
  pack is built unsigned, said at start and counted
  (`evidence_packs_unsigned`).
- Archives are stored under `EVIDENCE_DIR` as `<incident>/<pack>.zip`,
  written once, never overwritten (`0400`). A legal pack's archive is
  sealed at rest with the PII key (AES-256-GCM), so no personal data is
  on disk in the clear.
- **Every download and every verification re-reads the stored archive
  and recomputes the hash before anything else.** A mismatch (or a
  sealed archive that does not open) is refused with 409
  `evidence_tampered` and recorded (`evidence_pack_verified`,
  `hash_matches: false`); `GET .../verify` answers what it found and
  records it. An archive that cannot be read at all (the storage lost
  it or is unmounted, an object above `INCIDENTS_PACK_MAX_BYTES`, the
  PII key missing or another one) is not tampering: verify and download
  answer 503 `evidence_storage_unavailable`, count
  `evidence_packs_unreadable` and record `hash_matches: null`. The verdicts on the signature: `verified`, `invalid` (the
  row or archive changed), `unsigned`, `unverifiable` (signed with a
  publication key this system no longer holds: verify against the JWKS
  published at the time).
- To check a copy outside the system: its SHA-256 must equal
  `content_hash`; the `X-Evidence-Signature` of the download (also
  `signature` in the manifest answer) verifies over the seal statement
  with the publication key of the published JWKS.

The chain of custody is the incident's events: `incident_opened`,
`incident_updated`, `evidence_pack_built` (purpose, hash),
`evidence_pack_downloaded` (purpose, every time),
`evidence_pack_verified` (every check, with its result).

## Oversight and legal packs

| | `oversight` | `legal` |
|---|---|---|
| Who builds and downloads | inspector, incident officer | a personal-data role only (`inspector`; 403 otherwise) |
| `case_ref` | optional | required |
| Operators | registration public part and serial only | plus their personal data from the registry |
| Raw frame payloads | Basic ID, Location, Authentication; System (remote pilot position), Self-ID (free text), Operator ID (the registration as broadcast, which may hold the EU secret part) and Message Pack payloads withheld, kept by SHA-256 | all |
| Display Provider details | withheld (may carry the remote pilot position) | included |
| USSP service records | withheld, kept by SHA-256 (no contract fixes their shape) | included |
| At rest | as built | sealed with the PII key |

**The legal pack procedure.** Only for a stated legal purpose with a
case reference (a court order, a prosecutor's request):

1. An inspector builds it: `POST .../evidence-packs` with `kind:
   legal`, `purpose` (why, in words that will be read by the data
   protection officer) and `case_ref`.
2. The registry is read for each operator of the pack; each read is a
   `registry_pii_viewed` events row with the purpose `evidence pack
   <pack> (case <case_ref>): <purpose>`. An operator the registry does
   not know, or knows twice, is `unavailable` with the reason.
3. The pack is downloaded by an inspector with a purpose (every download
   audited) and handed over with its `content_hash` and signature.
4. A legal pack is never downloaded "to look": build an oversight pack
   for that.

## Limits and configuration

| Variable | Default | Meaning |
|---|---|---|
| `EVIDENCE_DIR` | unset | Where archives are stored. Unset: every pack operation is refused with 503 `evidence_storage_unavailable`, said at start at error level. |
| `INCIDENTS_PACK_MAX_WINDOW_S` | 21600 | Longest window; longer is 400 `window_too_large` (build several packs). |
| `INCIDENTS_PACK_MAX_ROWS` | 200000 | Rows per section; more is 413 `pack_too_large` (narrow the window). Never thinned. |
| `INCIDENTS_PACK_MAX_BYTES` | 268435456 | Largest archive; larger is 413 `pack_too_large`. |
| `INCIDENTS_PACK_MAX_ZONES` | 500 | Zone versions named and in force. |
| `INCIDENTS_PACK_CONCURRENCY` | 2 | Builds at once per replica; past it 503 `pack_busy` (`evidence_packs_busy`). |
| `INCIDENTS_BUILD_TIMEOUT_S` | 120 | Bound on one build, record fetches included. |
| `INCIDENTS_WRITE_TIMEOUT_S` | 10 | Bound on one incident transaction. |
| `INCIDENTS_BACKFILL_S`, `INCIDENTS_BACKFILL_BATCH` | 300, 100 | The job opening incidents of earlier escalations. |
| `RECORDS_CLIENT_ID`, `RECORDS_CLIENT_SECRET_FILE` | `authority-01`, unset | The client asking this issuer for `ussp.records` tokens. Unset: every record is `unavailable` with that reason, said at start. |
| `RECORDS_TIMEOUT_MS`, `RECORDS_MAX_BYTES`, `RECORDS_MAX_PER_PACK` | 5000, 1048576, 16 | One record fetch; past the bounds a record is `unavailable` with the reason. |

A USSP's `base_url` comes from its certificate (WP-16), found by its
code or its client id (the owner of its ISAs), whatever the
certificate's status now: a record of a past flight is still the
USSP's. A USSP without a certificate is `unavailable: the USSP holds no
certificate in the register`.

Counters (`/metrics`, status line `incidents`): `incidents_opened`,
`incidents_opened_from_violation`, `incidents_updated`,
`incidents_backfilled`, `incidents_backfill_failed`,
`incidents_bound_refused`, `evidence_packs_built`,
`evidence_packs_refused`, `evidence_packs_busy`,
`evidence_packs_unsigned`, `evidence_packs_orphaned` (an archive stored
whose row did not commit: the file is an orphan, logged with its
reference), `evidence_packs_downloaded`, `evidence_packs_verified`,
`evidence_packs_tampered`, `evidence_packs_unreadable`,
`evidence_sections_unavailable`.

## Known gaps

- The USSP service-record body has no contract yet (`uspace-ussp` at
  `8c64876` names the `records` tag but no operation). The record is kept
  verbatim as an opaque JSON object with its hash; it is withheld from
  oversight packs because its shape, and so its personal data, is not
  known.
- Storage is a directory (`EVIDENCE_DIR`); the S3-compatible bucket the
  brief names is not implemented (no object-storage dependency in this
  release). Point `EVIDENCE_DIR` at a mounted, backed-up volume.
