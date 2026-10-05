# Runbook: the picture feed (picture-ws)

`picture-ws` serves the authority's picture to the console (WP-21) and
to the police realm (WP-19): every Remote ID track, every manned aircraft
the ANSP feeds, every active violation and the state of every source,
for the viewport a console subscribes to. It renders; it judges nothing
and commands nothing. Caddy routes `/v1/picture/*` to it.

| Route | What |
|---|---|
| `GET /v1/picture/ws` | the WebSocket of the common console frame |
| `GET /v1/picture/snapshot?bbox=w,s,e,n[&layers=...]` | the `console/snapshot/v1` frame of a box, over HTTP |
| `GET /v1/picture/sources` | every source with its state, the projection ages, the CIS age, the bus |

`api/openapi.yaml` describes the three (`x-picture`); they are excluded
from api's generated server and served by `internal/picture`.

## The frame contract (for WP-21)

Every frame, in both directions, is the common console frame of
`uspace-lab/schemas/common/` (decision M29): the `04 §2` envelope
(`schema`, `msg_id`, `producer`, `ts`, `rx_ts`, `captured_at`,
`time_source`, `backlog`) and a `body` named by `schema`. The shapes are
the lab's and are not repeated here; `internal/picture/testdata/lab/`
holds verbatim copies at the commit in `internal/picture/testdata/SOURCE`,
and the tests validate every frame picture-ws sends against them.

| Direction | `schema` | When | Envelope |
|---|---|---|---|
| console → | `console/subscribe/v1` `{bbox, layers[]}` | on open and whenever the viewport changes | `schema` and `body` only; `msg_id` is ignored |
| → console | `console/status/v1` | on connect, after every subscription, every 2 s | `authority/picture-ws`, `time_source: system` |
| → console | `console/snapshot/v1` | on connect and after every subscription, after its status | `authority/picture-ws` |
| → console | `track/telemetry/v1` | every track message of the viewport (throttled, below) | the producer's (`authority/rid-ingest`, later `authority/dp-poller`) |
| → console | `track/manned/v1` | every manned message of the viewport (`manned` layer); the same sample again in a later state (`stale`, `source_disabled`) replaces it, so an aircraft whose source stopped ages instead of vanishing | `authority/manned-ingest` (WP-15), forwarded as received |
| → console | `violation/v1` | a raise, a clear, or the first sighting of an active violation (`alerts` layer) | `authority/detect` |
| → console | `source/status/v1` | every change of a source's state, disabled by whom, or lagging | `authority/picture-ws` |

A snapshot replaces the console's store; it is never merged. Its items
are complete messages with their own envelopes. `alerts[]` holds the
violations active in the viewport (C-08), `zones_version` the published
zones version of the projection (null while there is none).

A snapshot is bounded by `PICTURE_SNAPSHOT_MAX_BYTES` of items: active
violations first, then tracks, then manned aircraft. Past the bound the
rest is left out, `truncated` is `true` (`schemas/picture/snapshot/v1.json`)
and `snapshots_truncated` is counted; the console should narrow its
viewport. Live frames still arrive for every aircraft in view.

A snapshot is built with no lock that the bus path takes, so a console
that re-subscribes does not delay track delivery to the other consoles.
Live frames of the new viewport that arrive while it is built are held
for that console and sent after its snapshot. Subscriptions of one
connection are applied at most once per `PICTURE_SUBSCRIBE_MIN_INTERVAL_MS`.
Those superseded while one waits are never applied, and they are counted
in `subscribes_coalesced`.

### This system's extras, in full

`console/status/v1` body (`schemas/picture/status/v1.json`):

| Member | Meaning |
|---|---|
| `policy_version`, `stale_after_s`, `live_max_age_s` | the active `authority_policy` (INV-03); a console never defaults them. Version `0` with `policy_default` in `degraded` means no policy has been read yet and the documented defaults are shown |
| `dropped_frames` | frames this connection did not receive since it opened: throttled, or past its send queue |
| `degraded[]`, `degraded_since{}` | what is degraded now, and since when (table below) |
| `sources[]` | every source: the type rows (`source_instance: null`) and every instance heard or switched off, each `source/status/v1`'s body plus `lagging` and `lag_s` |
| `projection_age_s` | age of the registry projection on the database's clock; absent while never projected |
| `cis_version`, `cis_age_s` | the restrictions version of the CIS cache and its age; absent while never projected |
| `dp_state` | `polling`, `stale`, `disabled` or `unavailable`: the F3411 Display Provider (`network_rid` sources). `unavailable` until WP-14 lands |
| `nats`, `nats_since` | `connected`, or `unavailable` with the instant the bus was lost |

`track/telemetry/v1` body (`schemas/picture/track/v1.json`):

| Member | Meaning |
|---|---|
| `age_s` | now − `captured_at` on this system's clock when the frame was sent |
| `source_state` | the state of the track's source instance (`live`, `stale`, `disabled`, `down`, `unknown`) |
| `operator_position` | the remote pilot or operator position of a Display Provider flight: sent to the **console realm only**, omitted for the police realm and any public subset (06 §5) |

Every direct Remote ID track carries `trust: broadcast` and an
identification `basis: as_broadcast`: "as broadcast and unverified"
(R-05). No frame carries a name, an address or a contact (06 T6).
`identification.operator_reg` and `registered_operator_reg` carry only
the public part of the number (`regnum.PublicPart` under the active
policy's `registration_number_pattern`). The EU registration secret a
broadcast may carry never leaves the picture, for any realm or role
(G-04).

### Viewport and throttle

The viewport is the c5 cells covering `bbox` plus one ring of
neighbours (05 §3); `west > east` crosses the antimeridian. More than
`PICTURE_MAX_CELLS` (2000) cells is refused: the connection keeps its
previous viewport and says `viewport_too_large`. When the viewport holds
more than `PICTURE_THROTTLE_ABOVE_TRACKS` (200) tracks, each track is
sent at most `PICTURE_THROTTLE_HZ` (2) times a second; at 200 or fewer
every message is sent. A frame that does not fit the connection's queue
is dropped. Both count in `dropped_frames`; the console stays connected.
`GET /v1/picture/snapshot` answers for the box itself, without the
margin.

## Degraded states and what they mean

| Slug | Meaning | What the console should show |
|---|---|---|
| `nats_unavailable` | picture-ws lost the bus (`nats_since`) | the picture is frozen: nothing is removed, every aircraft ages; violations are not confirmed |
| `projections_unreadable` | the telemetry database cannot be read; the last ages are shown, ageing | projection ages are estimates |
| `registry_projection_absent` | the registry was never projected | identifications say `registry_unavailable` |
| `cis_absent`, `cis_stale` | no CIS restrictions version, or older than the policy's `cis_stale_bound_s` | restrictions may be missing or old |
| `dp_unavailable` | no Display Provider view (`dp_state`) | provider-trust tracks are missing |
| `manned_unavailable` | the ANSP manned traffic feed (`ansp_feed`) is not live: down since T, stale, or never heard (WP-15) | manned aircraft are missing or old; the sky is not empty. Not raised while the feed is switched off, which its source row says, with by whom |
| `alerts_unconfirmed` | an active violation was not republished for `PICTURE_ALERT_SILENT_S` (detect silent, C-08) | the violation may have ended; it is kept, not dropped |
| `alerts_replaying` | ALRT is being read back (start, or the bus came back) | violations are filling in |
| `session_verifier_unavailable` | this issuer's JWKS has not been fetched | new consoles are refused (1013) |
| `source_control_unknown` | the switches were never read: every source counts as enabled (B-09) | "disabled by" may be missing |
| `policy_default` | no policy read: the documented defaults are in force | thresholds may differ from the authority's |
| `tracks_evicted` | the track cache is at `PICTURE_MAX_TRACKS` and evicts | aircraft may be missing |
| `no_subscription` | this connection has not subscribed | an empty picture is not an empty sky |
| `viewport_too_large` | the last viewport was refused | the previous viewport is still shown |
| `session_unchecked` | the session could not be re-checked (api unreachable) | the connection closes after `PICTURE_SESSION_GRACE_S` |

## The same-origin WebSocket rule (M22)

- The console opens the WebSocket **same-origin**; the browser sends the
  `uspace_session` cookie with the upgrade. There is no ticket and
  nothing is read from the query string.
- An upgrade without the `uspace_session` cookie is refused with 401
  `unauthenticated` and never upgraded, whatever its Origin: it carries
  no credential, and that is said first (conformance C4; a bearer header
  is not the picture's credential). Counted as
  `upgrade_refused_no_session`.
- The `Origin` header must equal one of `PICTURE_ALLOWED_ORIGINS`
  exactly (scheme, host, port; default the origin of
  `AUTHORITY_PUBLIC_URL`). With the cookie, any other Origin, or none,
  is refused with 403 and never upgraded.
- The token is verified by uspace-core's verifier (`ISSUER_URL`,
  `PICTURE_JWKS_URL`, `AUTHORITY_AUDIENCES`, `StrictSessionClaims`) and
  must be a session (`scope = "session"` alone; a machine token is
  refused) of the console or police realm. Then api's
  `GET /v1/auth/session` (`PICTURE_SESSION_URL`, on the private network)
  says whether its `sessions` row is live: picture-ws never opens the
  relational database (B-15), and a logout, a revocation, a disabled
  account or the idle expiry ends the stream as it ends every api call.
- The session is checked again every `PICTURE_SESSION_RECHECK_S` (15 s)
  with `GET /v1/auth/session?activity=false`. That read checks the row
  without counting as activity, so watching the picture does not keep a
  session alive: only the console's own requests do, and an idle console
  ends at the idle timeout. The check at the upgrade is the console's own
  action and counts as activity.
  A session that has ended closes the connection with **4401**; at the
  token's `exp` too. When api cannot be reached the connection is kept
  for `PICTURE_SESSION_GRACE_S` (60 s), says `session_unchecked`, then
  closes with **1013**. A redirect from api is never followed.

| Close code | Meaning | The console |
|---|---|---|
| 4401 | a refused session, or one that ended | signs in again |
| 1013 | the session could not be checked | reconnects later |
| 1007 | a frame that is not a `console/subscribe/v1` (the reason names the member) | fixes the frame |
| 1009 | a frame over `PICTURE_SUBSCRIBE_MAX_BYTES` | |
| 1001 | picture-ws is stopping | reconnects |

Before the upgrade, in this order: 401 `unauthenticated` (no
`uspace_session` cookie), 426 `upgrade_required`, 403 `origin`, 503
`picture_full` (with `Retry-After`, past `PICTURE_MAX_CLIENTS`).

## Operating it

- Configuration: `uspace-authority picture-ws --help`. Required:
  `NATS_URL`, `TS_URL` (read-only, role `authority_ts_reader`),
  `AUTHORITY_PUBLIC_URL`, `PICTURE_SESSION_URL`.
- It starts with the bus, the database or api down and says so on the
  status line and in every console status; nothing is shown as an empty
  sky. `/readyz` does not depend on the bus: a console of a picture
  without its bus is told, not refused.
- The status line carries `consoles`, `tracks`, `manned`,
  `active_violations`, the projection ages and `bus_messages_dropped`
  (NATS slow-consumer drops); every refusal and drop is a counter on
  `/metrics` (components `picture`, `sessions`, `session_verifier`,
  `projections`, `bus`).
- The cache is in memory: after a restart the tracks reappear with their
  next message (1 Hz) and the active violations at once (ALRT read back).

## Measured (WP-13 load smoke)

`INTEGRATION=1 PICTURE_LOAD=1 go test -run LoadSmoke -v ./cmd/picture-ws/`:
10 consoles × 200 tracks at 1 Hz for 60 s, development stack on a
16-core Windows workstation: 120000 track frames, 2000 frames/s out,
`dropped_frames` 0, 9.5 s of CPU in 60 s (16 % of one core) for the whole
test process (picture-ws, the publisher and the ten consoles together).
