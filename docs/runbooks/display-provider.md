# Runbook: the Display Provider (dp-poller)

`dp-poller` is the authority's ASTM F3411-22a Display Provider (WP-14,
spec `02 F7`): it finds every USSP's network Remote ID through the DSS,
polls the USSPs' Service Providers for the areas the authority shows,
and publishes their flights on the picture as `trust: provider`. It
observes only. Caddy routes `/uss/*` and `/v1/dp/observations/*` to it;
api serves the administration under `/v1/dp/*`.

| Route | Served by | Who |
|---|---|---|
| `GET /v1/dp/views`, `POST /v1/dp/views` | api | admin |
| `GET /v1/dp/providers` | api | admin |
| `PUT /v1/dp/providers/{uss_id}/availability` | api | admin (audited) |
| `POST /uss/identification_service_areas/{id}` | dp-poller | a Service Provider's token: `rid.service_provider`, `aud` = this host |
| `GET /v1/dp/observations/display_data?view=`, `.../display_data/{id}` | dp-poller | `dp.observe` (lab-01 only) |

## Views

What is shown is the union of:

- the **oversight areas**: `POST /v1/dp/views {label, bbox: [west,
  south, east, north]}` (admin, audited; at most 256; never across the
  antimeridian). api stores the area, then publishes every area to KV
  bucket `dp_oversight` (key `views`) with the table's version, never
  replacing a newer value, and republishes every `DP_VIEWS_REPUBLISH_S`
  (60 s). The areas are shown whether or not a console looks at them.
- the **console viewports**: picture-ws writes the viewports its
  consoles subscribed to (snapped outwards to 1e-4°, at most 64 per
  instance) to KV bucket `dp_views` every 15 s; the bucket's TTL is
  60 s, so a viewport no console shows any more stops being polled
  within a minute.

dp-poller reads both every `DP_VIEWS_REREAD_S` (5 s), at most
`DP_MAX_VIEWS` (64), and cuts each into tiles whose diagonal is at most
the policy's `dp_view_diagonal_km` (7 km, never above F3411's
`NetMaxDisplayAreaDiagonalKm`), at most `DP_MAX_TILES` (512) in all.

## Discovery

Per tile: `GET /rid/v2/dss/identification_service_areas?area=` and one
DSS subscription (`PUT /rid/v2/dss/subscriptions/{id}`, 24 h, renewed
once 75 % has run, deleted when the tile is no longer viewed) whose
`uss_base_url` is `DP_USS_BASE_URL` (default `AUTHORITY_PUBLIC_URL`).
A renewal the DSS refuses with 404 or 409 (it no longer holds the
subscription) forgets it and the next sync makes a new one
(`subscriptions_lost_remade`).
Tokens: `rid.display_provider` with `aud` = the DSS's host, from this
system's own client (`DP_CLIENT_ID`, `DP_CLIENT_SECRET_FILE`).

The Service Provider that owns an ISA posts its changes to
`POST /uss/identification_service_areas/{id}` (F3411: the DSS only lists
the subscribers). The token must come from an allow-listed issuer (this
system's, or the lab's in the lab), with `aud` one of
`AUTHORITY_AUDIENCES` and `rid.service_provider`; the service area's
owner must be the token's subject (403 otherwise), and a held ISA is
replaced or deleted only by its held owner (`isas_refused_owner_change`).
Searches repeat every `DP_DISCOVERY_REREAD_S` (30 s) in case a
notification is lost.

An ISA learned only from a notification is provisional: its `time_end`
is capped at now plus `DP_NOTIFIED_ISA_MAX_LIFETIME_S` (24 h,
`isas_notified_time_end_capped`), and the next DSS search of a tile its
extent meets drops it when the DSS does not list it
(`isas_notified_not_listed_by_dss`). At `DP_MAX_PROVIDERS`, a Service
Provider a DSS-listed ISA names takes the place of one only
notifications named (`providers_evicted_unconfirmed`), and a provider no
held ISA names for `DP_PROVIDER_FORGET_AFTER_S` (10 min) is forgotten
(`providers_forgotten`).

**The Service Providers polled come only from the ISAs** (`00 §7`):
never from a configured USSP address. Each is identified by the ISA's
`owner` (its client id at the DSS), which is the `source_instance` of
its tracks and its source-control instance.

**`provider_unknown`**: the owner matches no operating certificate.
The certified owners are the client ids (`ussp-<code>-01`) of the USSP
certificates operating or limited whose holder operates, which api
publishes to KV bucket `certificates` (`CERTIFICATES_BUCKET`, WP-16)
after every change and every `CERTIFICATES_REPAIR_S`; dp-poller reads it
every `DP_CERTIFICATES_REREAD_S` (10 s) and moves a provider at the next
reconcile, so a suspension makes its provider `provider_unknown` within
seconds. Until the bucket is read every provider is `provider_unknown`,
and the status line says `certificate_register_read: false`. An unknown
provider is **still polled and shown**
(nothing is hidden), counted `provider_unknown`, and its status and its
`ussp_flights` rows say `provider_unknown: true`. Investigate: a USSP
operating without a certificate, or a register not yet updated.

## Limits (LESSONS R-14)

Every limit has a counter on the provider's status and `/metrics`, and
a log line at most once a minute.

| Limit | Default | Counter |
|---|---|---|
| poll deadline (the flights shown stay and age) | 5 s `DP_REQUEST_TIMEOUT_MS` | `polls_timed_out` |
| body read | 1 MiB `DP_MAX_BODY_BYTES` | `responses_over_body_cap` |
| flights per response | 500 `DP_MAX_FLIGHTS_PER_RESPONSE` | `flights_over_response_cap` |
| tiles per Service Provider | 64 `DP_MAX_TILES_PER_SP` | `tiles_over_sp_cap` |
| details per poll, at once | 20, 4 | `details_over_poll_cap` |
| details only for tiles ≤ 2 km | F3411 | `details_skipped_tile_over_2km` |
| 413 splits | 3 `DP_MAX_SPLIT_DEPTH` | `tiles_split_after_413`, `tiles_413_at_max_split` |
| poll rate | `dp_poll_hz` (policy, 1 Hz) | `polls` |
| slow rate past p99 3 s | 0.5 Hz `DP_SLOW_POLL_HZ` | `marked_slow` |
| unavailable after failing | 10 s `DP_UNAVAILABLE_AFTER_S` | `marked_unavailable` |
| plain HTTP | loopback only | `polls_refused_plain_http` |
| unchanged state | not republished | `state_unchanged_not_republished` |

## States

`src.v1.network_rid.<uss_id>` every 2 s, shown on the console and in
`GET /v1/dp/providers`:

| State | Means | Action |
|---|---|---|
| `live` | polls answer | none; `slow: true` with `p95_s`/`p99_s` when past 3 s: its flights are refreshed every 2 s and shown with their age |
| `down` | polls have failed for 10 s; `unavailable_since` is the first failure | its flights stay on the picture with their age, never removed; check the USSP, consider arbitration |
| `disabled` | switched off by source control; `disabled_by_who` names who | polling stopped at once (SC-16); its tracks age out as `source_disabled` |
| `unknown` | named by an ISA, no answer yet | wait one poll |

`dss` on every status: `ok`, `dss_unavailable` (since `dss_since`: the
known ISAs stay in use until their `time_end`), or `dss_unconfigured`
(`DSS_BASE_URL` unset: nothing is discovered).

## Records and disposal

Each published state is a `tracks` row and a `ussp_flights` row (the
`RIDFlight` and its details as received, the provider, the ISA, the
receive time), handed to tsdb-writer; rows that cannot be handed over
are counted (`rows_lost_handover_failed`) and recorded in
`writer_gaps` (`dp_handover_failed`). **`ussp_flights.details` is
personal data of the PII class** (it may carry the remote pilot's
position): it is never exported, and only the console realm is shown the
operator position.

F3411 `NetDpMaxDataRetentionPeriodSeconds`: nothing older than 24 h may
remain. `ussp_flights` has one-hour chunks and a retention policy that
drops them past 22 h every 15 minutes (oldest row at most 23 h 15 min).
tsdb-writer checks at start and hourly that nothing older than 24 h is
left; a violation is logged at error level, counted
(`retention_violations`) and on its status line (`retention`). A
violation means the TimescaleDB job is not running: check
`timescaledb_information.job_stats` for `policy_retention` on
`ussp_flights`.

## Availability arbitration (F3548)

`PUT /v1/dp/providers/{uss_id}/availability {availability: Down |
Normal | Unknown, reason}`, admin:

1. the request is recorded (`dp_availability_requested`, committed);
2. the DSS's current version is read and the new state set with it
   (`GET`/`PUT /dss/v1/uss_availability/{uss_id}`, scope
   `utm.availability_arbitration`, `aud` = the DSS's host), one
   arbitration of a USS at a time across api replicas (409 otherwise);
3. the outcome is recorded (`dp_availability_set` or
   `dp_availability_failed`); a DSS that refuses or cannot be reached
   answers 502.

`uss_id` is the USS's client id at the DSS (the ISA owner shown in
`/v1/dp/providers`). A `Down` USS cannot create or change operational
intents at the DSS until set `Normal` again; record the reason with the
evidence of its unavailability.

## Conformance hook (Q-A7)

`uss_qualifier`'s Display Provider tests call the InterUSS Remote ID
observation interface (`api/clients/interuss-observation/`, at the
commit `api/clients/SOURCE` records) with base
`/v1/dp/observations`: `display_data?view=` answers flights for a view
within 2 km and clusters only for a wider one; `display_data/{id}` the
operator id's public part, the operator location and the serial. Scope
`dp.observe`, issued to `lab-01` only. Not a product endpoint.

## Start without its dependencies (E-02)

- No `DSS_BASE_URL`: starts, logs `no DSS` at error level, status
  `dss_unconfigured`, nothing polled.
- No `DP_CLIENT_SECRET_FILE`: starts, logs `no client secret` at error
  level; every outbound call is refused locally.
- No geoid: flights have no AMSL altitude and are not judged
  vertically (R-07), said at start.
- Registry projection not loaded: flights are identified
  `registry_unavailable` until it is (SC-22).
- This issuer unreachable: notifications and the hook are refused (503)
  until its keys are fetched.
