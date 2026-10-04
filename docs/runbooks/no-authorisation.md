# Runbook: the no_authorisation detector (WP-26)

`detect` raises `no_authorisation` (spec 04 §3.3, Art. 6(4)) for an
aircraft inside a U-space airspace (a `USPACE` zone in `proj_zones`)
that no operational intent of any USSP covers for longer than the
policy's grace, and gives `height_limit_in_uspace = skip_when_authorised`
its effect. It reads the DSS only; it never writes to it and never
contacts an aircraft. Code: `internal/intents` (the DSS reads, the
cache, the matching), `internal/detectsvc/noauth.go` (the cases, the
raise and clear, the height gating).

**Gated on spec 08 Q2.** No U-space airspace is designated yet. Until
GCAA designates one (or the lab agrees a demo designation through
`POST /v1/uspace` and `.../designate`), there is nothing to judge: the
status says `dss_state: no_uspace_designated` and the DSS is never
asked.

## Configuration (detect)

| Variable | Default | Meaning |
|---|---|---|
| `DSS_BASE_URL` | unset | The InterUSS DSS (F3548 under `/dss/v1`). Unset: not judged. |
| `ISSUER_URL` or `DETECT_TOKEN_URL` | unset | This system's token endpoint (`ISSUER_URL` + `/oauth/token`). |
| `DETECT_CLIENT_ID` | `authority-01` | The client the DSS token is asked for. |
| `DETECT_CLIENT_SECRET_FILE` | unset | Its secret. Unset: not judged. |
| `DETECT_INTENT_REQUERY_S` | 5 | Read of every U-space airspace in force (stands in for a DSS subscription, see below). |
| `DETECT_INTENT_HORIZON_S` | 3600 | How far ahead an airspace is read. |
| `DETECT_INTENT_RECHECK_MS` | 2000 | Least time between two reads of one aircraft's position. |
| `DETECT_INTENT_CHECKS_PER_S` | 20 | Position reads per second at most; the rest wait (`intent_checks_deferred`). |
| `DETECT_INTENT_CHECK_RADIUS_M` | 10 | Radius asked around an aircraft. |
| `DETECT_INTENT_VERTICAL_MARGIN_M` | 10 | Each way around its WGS84 height. |
| `DETECT_INTENT_OUTCOME_MAX_AGE_S` | 10 | How long a judgement of an aircraft stands. |
| `DETECT_INTENT_MAX_AIRCRAFT` | 10000 | Aircraft held; past it refused (`intent_checks_refused`). |
| `DETECT_INTENT_MAX_ZONES` | 64 | Airspaces read; past it `uspace_zones_not_watched`. |
| `DETECT_INTENT_MAX_CACHED` | 10000 | References held; past it evicted (`intent_cache_evicted`). |
| `DETECT_INTENT_MAX_REFS` | 1000 | References in one DSS answer; a larger answer is refused whole. |
| `DETECT_INTENT_MAX_BODY_BYTES` | 1048576 | Largest DSS answer read. |
| `DETECT_INTENT_REQUEST_TIMEOUT_MS` | 5000 | Deadline of one DSS read. |

The token asked is for the DSS's host (M18) with
`utm.conformance_monitoring_sa` only (Q-A5); the client must hold that
scope at the token service, and the DSS must list this issuer's key
(02 F6 Auth row).

Policy (`authority_policy`, `POST /v1/policy`, audited; **pending
GCAA**):

| Column | Default | Meaning |
|---|---|---|
| `no_authorisation_grace_s` | 10 | How long an aircraft may show no matching intent before the raise. |
| `no_authorisation_severity` | warning | The severity raised. |
| `height_limit_in_uspace` | evaluate | `skip_when_authorised` lifts the 120 m rule for a matched aircraft whose height was checked. |
| `clear_after_s` | 3 | The hysteresis of the clear on a match. |

## What it does

1. Every `DETECT_INTENT_REQUERY_S` it reads each U-space airspace in
   force (its box, every height, the next hour) and caches the
   references (24 h at most, F3548 `ExternalDataMaxRetentionTimeHours`).
   A reference the next read no longer lists is `withdrawn`.
2. For each aircraft inside an airspace it asks the DSS for the intents
   at the aircraft's position (and WGS84 height when the track has
   one) — unless no cached intent of the airspace could match, when the
   cache answers. An intent matches when it is flying (`Activated`, or
   `Nonconforming` / `Contingent`, which the USSP's conformance
   monitoring covers) and the sample is inside its window.
3. Unmatched for longer than the grace: `no_authorisation` is raised,
   with `zone_id` the airspace and `detail.candidates` every intent
   considered and why it failed (`withdrawn`, `not_activated`,
   `before_start`, `after_end`, `not_at_position`).
4. Matched for `clear_after_s`: cleared `resolved`. Leaving the airspace:
   cleared with the presence's reason (`resolved` with
   `clearing_detail.left_uspace`, `stale`, `landed`, `source_disabled`).
   The airspace withdrawn: `reconfigured`.

## Reading the status line

`no_authorisation.dss_state`:

- `no_uspace_designated`: nothing to judge (spec Q2).
- `dss_unconfigured`: no DSS or no secret. With an airspace in force the
  status is at error level and `not_judged` says so; each aircraft
  entering one counts `no_authorisation_not_judged`.
- `starting`: an airspace is in force, the DSS has not answered yet.
- `available`: judging.
- `dss_unavailable` (with `dss_unavailable_since`, `dss_last_error`):
  the detector is **suspended**. It raises nothing and clears nothing on
  a match; an open `no_authorisation` stays open and is republished with
  `detail.suspended: true`. It resumes, with the grace starting over,
  when the DSS answers. This is never shown as "clear" (E-02).

Per worker: `uspace_aircraft`, `no_authorisation_open`,
`no_authorisation_unknown` (suspended cases), `no_authorisation_matched`,
`no_authorisation_grace_running`, `height_lifted`.

## Known limits (spec gaps, docs/PLAN.md Q-A22)

- **No identity match.** F3548 references name no operator or UAS, and
  the intent details need `utm.strategic_coordination`, which the
  authority does not hold. A match is an intent at the aircraft's place
  and time; `detail.identity` says `not_exposed`.
- **No DSS subscription.** It needs `utm.strategic_coordination` or
  `utm.constraint_processing`; the periodic read stands in. An intent
  ended by its USSP is seen at the next position read (≤
  `DETECT_INTENT_RECHECK_MS`), withdrawn at the next airspace read.
- **The DSS's resolution.** The DSS intersects at its cell size, so an
  aircraft close to an authorised intent may be taken as authorised: a
  miss, never a false raise.
- **Restart.** Nothing is kept: after a detect restart the cache is read
  again, open violations are closed `detector_silent` by api, and a
  condition that still holds is raised again after a fresh grace.

## Checks

- Unit: `go test ./internal/intents/ ./internal/detectsvc/ -run 'NoAuth|HeightLimitLifted|Board|Judge|Cache|Parse|Client'`.
- Through the stack (NATS, TimescaleDB, PostgreSQL, the fake DSS over
  HTTP): `INTEGRATION=1 go test -run TestIntegrationNoAuthorisationThroughTheStack ./internal/violations/`.
