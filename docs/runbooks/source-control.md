# Switching a source off (source control)

Every position source of the authority can be switched off without a
deploy, by type or by instance, and back on (spec 02 §3 `/v1/sources/*`,
04 §3.6 `source/control`, LESSONS B-09, B-10, B-11, B-16). Rewritten for
this system from the predecessor's U-15 runbook.

| Type | Adapter process | Instance |
|---|---|---|
| `direct_rid` | rid-ingest | a Remote ID receiver id (`rx-tbs-01`) |
| `network_rid` | dp-poller (WP-14) | a USSP's id |
| `ansp_feed` | manned-ingest (WP-15) | the feed itself (`MANNED_FEED_INSTANCE`, default `ansp`: switching it off, or the type, closes the stream) or one ANSP adapter (`adsb-tbs`: its aircraft are refused and aged `source_disabled`) |

## Doing it

As an admin (a viewer, or any other role, gets 403):

```
PUT /v1/sources/direct_rid                {"enabled": false, "reason": "receiver firmware recall"}
PUT /v1/sources/direct_rid/rx-tbs-01      {"enabled": false, "reason": "suspected tampering"}
GET /v1/sources
```

A reason is required. The answer carries the switch as stored, the
state's `epoch` and `version`, and `changed`: a switch to the state it
already holds changes and records nothing (`changed: false`).

`GET /v1/sources` lists every switch and every source a switch names or
an adapter has reported, each with:

- `switch`: `enabled` or `disabled`, and when disabled `disabled_by`
  (`type`, `instance` or `default_deny`), `disabled_by_who` and
  `disabled_reason`;
- `health`: `healthy`, `stale`, `lagging` or `never_heard`, from the
  adapter's last `source/status/v1`; `status_age_s` is the age of that
  status, and past `SOURCE_STATUS_STALE_S` (10 s) the source is `stale`
  whatever it said: the adapter itself is silent.

## The rule

A type switched off disables every instance, even one switched on. An
instance switched off stays off under a type that is on. An instance
with no row of its own is enabled, unless api runs with
`SOURCES_DEFAULT_DENY=true`; the flag travels in the published state, so
every follower applies the same default, and an instance row switched on
overrides it. Before anything is published every source is enabled. The
decision is uspace-core `sources` (`State.Query`); the knowledge vector
`source_control.json` pins it and runs through this system's encoding
(`internal/sources`).

## How a switch travels

```
admin --PUT /v1/sources/...--> api --one transaction--> source_controls row + events row
                                 |                       + KV source_control/state (the whole state)
                                 +--> after commit: push on ctl.sources
                                                 |
   rid-ingest, dp-poller, manned-ingest, detect, tsdb-writer, picture-ws, api:
   internal/sources follower (KV watch + push + re-read every SOURCE_CONTROL_REREAD_S)
```

- **api is the only writer.** `source_controls` (relational migration
  `00011_source_controls`) holds the current switch per type
  (`instance_id` NULL) and per instance, with the reason, the actor and
  the time. Every switch is an `events` row: entity `source`, id
  `<type>/<instance>` or `<type>/*`, event `source_disabled` or
  `source_enabled`, the reason and the previous switch in the payload.
- **Versions only rise.** Each switch draws its version from
  `source_control_version_seq`. The state's epoch is random, made with
  the table. Within an epoch a follower takes only a strictly higher
  version; a state under another epoch is taken whatever its version.
- **Writers serialise** on the transaction advisory lock
  `source_controls`, switches and republishes alike, so two api replicas
  never write back a state the other has just replaced.
- **The KV write is inside the transaction.** If the bucket cannot take
  it, the transaction rolls back and api answers 503
  `source_control_unavailable`: nothing changed, and the database and
  the adapters still agree. If the commit fails after the write, api
  republishes the database's state over it before answering.
- **A state that does not fit** the bucket's value bound
  (`SOURCE_CONTROL_MAX_VALUE_BYTES`, 256 KiB) is refused with 400
  naming the bound and the bucket (E-10).
- **Repair.** api republishes the state from the database at start and
  every `SOURCE_CONTROL_REPUBLISH_S` (60 s), writing only when the bucket
  differs: a lost or corrupt bucket, a changed default. A bucket ahead of
  the database within the same epoch is a database restored from a
  backup (or a commit that failed after its write): api starts a new
  epoch, records `source_control_epoch_started`, and republishes, so the
  followers take the database's state instead of ignoring it as older.

## What each part does with a disabled source

| Part | A disabled source |
|---|---|
| rid-ingest | A batch from the receiver is refused with **503** `source_disabled` and `Retry-After` (never 401 or 403, which a receiver treats as fatal, B-10) before it is verified or stored, and counted. Its `src.v1.direct_rid.<receiver>` status says `disabled`, `disabled_by` and `disabled_by_who` (B-11). The receiver keeps buffering and retrying, and delivers its buffer as backlog once switched on. |
| dp-poller (WP-14) | The provider is not polled. |
| manned-ingest (WP-15) | The feed is closed with 1013 and reconnects are refused with 503. |
| detect (WP-12) | Tracks of the source age out as `source_disabled` and their violations clear with that reason at once. |
| console | Each source: enabled or disabled by whom, and healthy, stale, lagging or never heard; a disabled source looks different from one that is merely silent. |

The registry's own disable of one receiver
(`POST /v1/rid/receivers/{id}/status`) is separate and also refuses it
with 503; either one off is enough.

## When NATS or JetStream is unavailable

- **Followers never fail closed.** They keep the last state they read;
  with none, every source stays enabled. At start they try the read
  `NATS_START_ATTEMPTS` times (3) from `NATS_START_BACKOFF_MS` (500 ms)
  doubling, then start anyway and log `source-control state unknown:
  every source is enabled until it can be read (B-09)`. They apply the
  state as soon as the watch, the push or the re-read delivers it.
- Every process's status line carries `source_control_known`,
  `source_control_epoch`, `source_control_version` and
  `source_control_applied_age_s`, and the counters `source_control`
  (`applied`, `ignored_older_version`, `new_epoch`) and
  `source_control_reads` (`read_failed`, `read_not_published`,
  `ignored_malformed`). A malformed value in the bucket is ignored and
  counted; api overwrites it at the next republish.
- **api refuses switches** with 503 `source_control_unavailable` and
  changes nothing; `source_switches.store_write_refused` counts them.
  The console says "not changed" and re-reads the switches.
- Every process connects with unlimited reconnects; at start it tries
  three times and then starts degraded, saying so (B-08). api's
  readiness does not depend on NATS: it keeps serving its control plane.

## Verifying it

`make integration` runs the SC-08 steps this system owns
(`cmd/api/sources_integration_test.go`) against real PostgreSQL and NATS:
a type switched off refuses every receiver within a second and the
receiver's status says by whom; switched on, it is accepted again; a
viewer's switch is 403 beside the admin's 200; every switch is an
`events` row with the actor and the reason; a follower started with the
store down starts enabled and says so, while a switch meanwhile is
refused with 503 and nothing changes. `internal/sources/switches`
covers the store refusal, the monotonic version, the new epoch and the
republish of a deleted key.
