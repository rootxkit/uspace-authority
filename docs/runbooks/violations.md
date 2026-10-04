# Violations

The authority's findings of non-compliance from its own evidence (spec
01 A7, 2019/947 Art. 18(k); WP-12). `detect` judges every track with
uspace-core's alert monitor and publishes `violation/v1` on
`alrt.v1.<kind>.<cell5>.<violation_id>`; `api` stores them in
`violations` with an `events` row for every transition; inspectors
review them through `/v1/violations`. The authority never alerts a pilot
and never warns of proximity: conflicts are the USSP's (plan D5).

## The kinds

| Kind | Raised when (uspace-core) | Severity | Clears |
|---|---|---|---|
| `height_120m` | AMSL minus the DEM ground is strictly over the policy's `height_limit_agl_m` (120 m) | warning | resolved once at or under the limit for longer than `clear_after_s` |
| `zone_incursion` | inside a zone or dynamic restriction in force at the sample's `captured_at`, vertically inside its limits | PROHIBITED critical, REQ_AUTHORISATION warning, CONDITIONAL per policy; warning when a limit could not be judged | resolved once outside for longer than `clear_after_s` |
| `unregistered` | an unidentified or unknown-operator aircraft inside a PROHIBITED or REQ_AUTHORISATION zone (G-03) | policy `identification_severity` (critical) | with the zone violation |
| `identification_mismatch` | a registered serial broadcast with another operator's number, or `serial_conflict` (G-02), on the ground too | policy `mismatch_severity` (warning) | resolved once the identification says otherwise for `clear_after_s` |

Not raised: conflicts (CPA, counted `conflict_events_ignored`), presence
in a U-space airspace (a USPACE zone is recorded as `in_uspace: true` on
the aircraft's violations, never a violation itself), anything from a
`backlog` sample (T-04), and `no_authorisation` and `rid_absent`, which
are later detectors (WP-26, plan Q-A6).

## What each field means

| Field | Meaning |
|---|---|
| `violation_id` | One per raise of a condition; stable while it holds. |
| `alert_key` | The monitor's key of the condition (`zone:<country>:<identifier>:<aircraft>`, `height:<aircraft>`, ...). |
| `track_id`, `serial`, `operator_reg` | The aircraft as identified when raised; serial and number are as broadcast or provided, never verified. An operator number (here and in `evidence_excerpt`) is only its public part under the policy's `registration_number_pattern`: a secret part a broadcast carried is cut by detect and never stored (G-04, 06 §5). |
| `zone_id`, `zone_version`, `zone_type` | The zone judged (`country/identifier`), its published version (null for a dynamic restriction). |
| `opened_at`, `closed_at` | When the condition was first shown true and when it cleared, on the placed clock (`captured_at`). |
| `clear_reason` | `resolved` (shown false past the hysteresis), `stale` (not heard for `stale_after_s`), `landed`, `source_disabled` (its source switched off, B-11), `flight_ended`, `reconfigured` (the zone set or policy changed and the aircraft's last sample, judged again as it was received, no longer raised it; an aircraft quiet past `stale_after_s` or no longer held is `stale` instead), `detector_silent` (closed by api: detect stopped republishing it, a restart or a bus outage; not a judgement of the aircraft, and revived as the same violation if detect's next update for it arrives, with `violation_revived` recording the gap). Only `resolved` rests on evidence that the condition ended. |
| `peak` | The number it rested on at its worst: `height_agl_m` for `height_120m` (there is no stored AGL column, D-02). |
| `detail` | The judgement as uspace-core gave it: `vertical_known` (false on a pressure altitude or an unjudged limit), `within_band` (pressure altitude: inside as indicated, or only in the band widened by `pressure_uncertainty_m`), `limit_not_judged` and `not_judged` (`AGL`, `WGS84`: a limit that needs a ground or geoid this system lacks), `height_agl_m`, `alt_hae_m`, `max_height_agl_m`, `identifier`, `restriction`, `status`, `identification_reason`. |
| `terrain_source` | The DEM dataset, spacing and attribution of a height over the ground (D-05). |
| `policy_version` | The `authority_policy` version judged with; 0 means detect had received no policy and judged with the documented defaults (its status line says so). |
| `evidence_trust` | `broadcast` (direct Remote ID: as broadcast and unverified) or `provider` (network Remote ID). |
| `evidence_refs`, `evidence_track_ids` | The track, the receiver or USSP it came through, the zone and version. |
| `evidence_excerpt` | The track samples copied at the raise (the last `DETECT_EXCERPT_WINDOW_S`, 10 s) and appended while it held, up to `VIOLATIONS_EXCERPT_MAX_SAMPLES` (`excerpt_truncated` beyond). The Display Provider cache is disposed of within 24 h; this copy is the record. |
| `excerpt_segmenting` | `GET /v1/violations/{id}` only (WP-23): the excerpt cut by the evidence packs' rule (`docs/runbooks/incidents.md`, B-13) with the active policy's `max_gap_s`: `segments` (indexes into `evidence_excerpt`) and `holes`, each with every cause known of it (`silence`, `no recorded cause`, `writer_gap` with the recorded lines, `sample_without_position`). `writer_gaps_read: false` when the writer gaps could not be read in full: a silence then says `writer_gaps_unread`, never `no recorded cause`. `state: unavailable` with the reason when the policy cannot be read: the console then draws the samples unjoined. The console draws what this says and cuts nothing itself. |
| `status` | The review: `new`, `reviewed`, `dismissed`, `escalated`. |

## Reviewing

As an inspector:

```
GET  /v1/violations?status=new&kind=zone_incursion&from=...&to=...&bbox=44.7,41.6,44.9,41.8
GET  /v1/violations/{id}
POST /v1/violations/{id}/review   {"decision": "reviewed" | "dismissed" | "escalated", "note": "..."}
```

`new` or `reviewed` may become `reviewed`, `dismissed` or `escalated`;
`dismissed` and `escalated` are final (409 `violation_reviewed`).
Broadcast-only evidence is never escalated without a note (06 §2 T1:
400 naming `note`): a broadcast can be spoofed, so say what corroborates
it. Escalation records `incident_requested` and opens the incident in the
same transaction (docs/runbooks/incidents.md).
Every decision is an `events` row with the inspector and the note.

## The audit trail of one violation

```
GET /v1/audit/events?entity_type=violation&entity_id=<violation_id>
```

`violation_raised`, `violation_severity_changed`, `violation_cleared`
(actor `detect`, or `api` for `detector_silent`), `violation_revived`
(a `detector_silent` close undone by a later update: `silent_from`,
`closed_at`, `resumed_at`, `silent_for_s`), `violation_reviewed`,
`violation_dismissed`, `violation_escalated`, `incident_requested`.

## When the status line is at error level

detect writes every status line at error level, and once at start the
line `violations not judged in full` with `not_judged`, while anything in
force is not judged. Each entry says what and why:

| Entry | Meaning | Fix |
|---|---|---|
| `zones projection not loaded` | detect has never read `proj_zones` (the telemetry database unreachable, or a schema version too old) | check `TS_URL` and the database; the projection is re-read every `DETECT_ZONES_REFRESH_S` and on `zones.v1.changed` |
| `restrictions projection not loaded` | as above for `proj_restrictions` | as above |
| `zone not judged: <dataset>/<id>@<version>: ...` | a zone in force that uspace-core cannot build (a daylight event the place cannot resolve, a feature that does not parse) | fix the zone and publish a new version |
| `restriction not judged: ...` | the same for a dynamic restriction | the ANSP's restriction: tell the ANSP |
| `terrain not configured: the height limit over the ground (height_120m) is not evaluated for any aircraft` | detect has no DEM: no `height_120m` violation can be raised anywhere (`height_checks_not_evaluated` counts each sample); the status is never at info level while this holds | mount the ground volume (`GROUND_DIR`; `deploy/fetch-ground.sh`, `docs/runbooks/ground.md`) |
| `PROHIBITED zone GEO/<id> needs terrain, not configured` (or `geoid`) | the zone has an AGL limit (or a WGS84 limit) and detect has no DEM (or geoid): inside it the zone warns with `limit_not_judged` instead of its own severity (Z-09, SC-13) | mount the ground volume (`GROUND_DIR`, `GEOID_FILE`; `deploy/fetch-ground.sh`, `docs/runbooks/ground.md`) |

Without terrain the height limit is not evaluated at all
(`height_checks_not_evaluated` counts each sample); it is never judged
against a ground of 0 m (D-04).

## Counters to watch

On detect's status line and `/metrics`: `track_refused` (tracks the
schema refuses, never judged), `aircraft_refused` and the monitor's
`rejected_capacity` / `rejected_source_share` (aircraft refused for
capacity: unjudged, logged at error level), `alrt_publish_failed`
(violations waiting in the outbox), `alrt_outbox_dropped` (lost: error
level), `violations_republish_failed` and `violations_republish_deferred`
(active violations not republished in a tick: the bus failed or the
tick's `DETECT_TICK_BUDGET_MS` ran out; the next tick starts with them),
`violations_cleared_reconfigured`, `conflict_events_ignored`,
`rejected_late`, `rejected_backlog`, `zone_checks_not_evaluated`,
`zone_limits_not_judged`. On api's: `violation_messages_malformed`,
`violation_apply_failed` (redelivered), `violation_excerpt_truncated`,
`violations_closed_detector_silent`, `violations_revived`.

## Configuration

detect: `DETECT_MAX_AIRCRAFT`, `DETECT_EXCERPT_WINDOW_S`,
`DETECT_EXCERPT_MAX_SAMPLES`, `DETECT_OUTBOX_MAX`,
`DETECT_PUBLISH_TIMEOUT_MS`, `DETECT_TICK_BUDGET_MS`, `DETECT_ZONES_REFRESH_S`,
`DETECT_RESTRICTIONS_REFRESH_S`, `DETECT_POLICY_REREAD_S`,
`DETECT_MAX_ACK_PENDING`, `DETECT_ACK_WAIT_S`, `DETECT_FETCH_MAX`.
api: `VIOLATIONS_EXCERPT_MAX_SAMPLES`, `VIOLATIONS_SILENT_AFTER_S`,
`VIOLATIONS_SILENT_CHECK_S`, `VIOLATIONS_SILENT_BATCH`,
`VIOLATIONS_MAX_ACK_PENDING`, `VIOLATIONS_ACK_WAIT_S`,
`VIOLATIONS_FETCH_MAX`, `VIOLATIONS_RETRY_MS`,
`VIOLATIONS_WRITE_TIMEOUT_S`. The thresholds are not configuration: they
are the active policy (`/v1/policy`), which api writes to KV `policy`
and detect follows; `height_limit_in_uspace: skip_when_authorised` has no
effect until WP-26 (the height limit is evaluated everywhere, and detect
says so).
