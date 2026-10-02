# Runbook: Remote ID receivers

A Remote ID receiver hears the Open Drone ID broadcasts around it
(Bluetooth or Wi-Fi) and posts what it heard to the authority (spec
`02 F9`). The broadcast cannot be authenticated; the receiver can, and
must be (LESSONS R-05, R-06, threat T2 of spec `06 §2`). This page is
the receiver contract and the operator's view. The request body is
`schemas/rid/observation/v1.json`; the endpoints are in
`api/openapi.yaml` (tags `rid-receivers`, `rid-ingest`, `rid-frames`).

## Onboarding a receiver

1. An admin registers it: `POST /v1/rid/receivers` with an `id` (slug,
   `^[a-z0-9][a-z0-9-]{1,62}$`, for example `rx-tbs-01`), a `label`,
   the pinned position (`lat_deg`, `lon_deg`, WGS84, where it is
   mounted), the `owner` (`authority` or `third_party`, with
   `owner_name`) and optionally its `config`.
2. The answer carries the credentials **once**: `bearer_key`
   (`<id>.<43 base64url characters>`) and `hmac_secret_hex` (32 random
   bytes, hex). Neither can be read back: the registry keeps an argon2id
   hash of the key and the secret sealed with the PII key. Copy both
   into the receiver's secure storage; a lost value is replaced by a
   rotation, not recovered.
3. The receiver fetches `GET /v1/rid/receivers/{id}/config` with its
   bearer key: its batch interval, backlog cap, heartbeat interval,
   position tolerance, the fields it reports, the ingest's limits and
   the authority's clock (`server_time_ms`, to see its own skew).
4. It starts its heartbeat (`POST /v1/rid/receivers/{id}/heartbeat`
   every `heartbeat_interval_s`, 10 s by default) and its batches
   (`POST /v1/rid/observations`, at most every `batch_interval_ms`).
5. `rid-ingest` follows the key set within a second (KV
   `rid_receiver_keys`, pushed and re-read every
   `RID_INGEST_KEYSET_REREAD_S`). A `rid-ingest` started with no
   receiver registered listens on loopback only and says so
   (`no receiver keys: listening on loopback only (R-06)`); restart it
   once the first receiver exists.

Rotation: `POST /v1/rid/receivers/{id}/keys/rotate` issues new
credentials, shown once. The previous ones keep working for `grace_s`
(default `RID_KEY_ROTATION_GRACE_S`, 1 h) so the receiver can be
re-flashed without a gap; `grace_s: 0` revokes them at once (a captured
receiver). Deleting a receiver revokes everything; its stored frames
stay.

## The signing contract

Every request carries the bearer key:

```
Authorization: Bearer <bearer_key>
```

Every request with a body (a batch, a heartbeat) also carries the
HMAC-SHA256 of **the exact body bytes**, under `hmac_secret_hex`
decoded to its 32 bytes, as 64 lower-case hex characters:

```
X-Report-Signature: <hex(HMAC-SHA256(secret, body))>
```

- The body is signed as sent: no JSON canonicalisation, no reordering,
  no whitespace change after signing. An ESP32 signs the buffer it is
  about to send with its SDK's HMAC.
- The authority reassembles `body + "\nsig=" + header` and verifies it
  with uspace-core `auth.ReceiverVerifier`
  (`knowledge/vectors/rid_receiver_auth.json`).
- `receiver_id` in the body must be the receiver the bearer key names.
- `sent_at_ms` is the receiver's clock in epoch milliseconds at sending.
  More than **30 s** from the authority's clock is refused: keep the
  receiver on NTP or GNSS time.
- `nonce` is new for every request: 1 to 256 bytes of UTF-8 without
  control characters. A nonce seen again from the same receiver within
  **60 s** (twice the window) is refused as a replay. A counter or a
  random 128-bit value in hex is enough; never reuse one after a
  restart within a minute.
- `rx_ts` of each observation is the receiver's clock when the frame
  was heard, RFC 3339 in UTC ending in `Z`. Without it the frame is
  placed at its arrival and never merged with another (LESSONS T-12).

A batch (`rid/observation/v1`): at most 65,536 bytes and 64
observations, about one second of reception. Each observation has
`transmitter` (the MAC, `AA:BB:CC:DD:EE:FF`), `payload_hex` (the ODID
message or message pack exactly as received, at most 512 bytes), and
optionally `rssi_dbm`, `rx_ts` and `receiver_position`. The receiver
decodes nothing; decoding is the authority's.

While the authority is unreachable the receiver buffers up to
`backlog_cap` observations and replays them afterwards with
`backlog: true`, their original `rx_ts` and a fresh `sent_at_ms` and
`nonce`. Replaying observations that were in fact accepted is harmless:
an observation accepted from the same receiver in the last 60 s (same
transmitter, `rx_ts` and payload) counts as a duplicate and is not
stored twice.

## Answers a receiver must handle

| Status | Problem type (slug) | Meaning | What the receiver does |
|---|---|---|---|
| 202 | — | Durably queued. `accepted` new, `duplicates` already had | drop the batch from its buffer |
| 400 | `validation` | the batch does not match the schema; `errors[]` names each field | fix the firmware; do not resend as is |
| 401 | `unauthenticated` | no bearer key, a malformed one, an unknown or revoked one | stop and alert its operator: re-provision |
| 401 | `signature` | unsigned, a wrong signature, or a body naming another receiver | check the secret and that the signed bytes are the sent bytes |
| 401 | `skew` | `sent_at_ms` more than 30 s from the authority's clock | fix the clock; resend with a fresh `sent_at_ms` and nonce |
| 409 | `replay` | the nonce was seen within 60 s | resend with a new nonce |
| 413 | `body_too_large` | over 65,536 bytes (heartbeat: 4,096) | split the batch |
| 503 | `source_disabled` | the receiver is disabled in the registry, or (from WP-10) the `direct_rid` source is disabled by type or instance; nothing was stored | keep buffering; retry after `Retry-After` (never give up on a 503) |
| 503 | `queue_full`, `queue_unavailable`, `in_flight`, `busy` | the authority cannot take the batch now; nothing was accepted | retry after `Retry-After` with a fresh nonce |

The authority never answers a receiver with 403 (LESSONS B-10): 401 is
"your credentials are wrong", 503 is "try again later".

## What the operator sees

- `GET /v1/rid/receivers/{id}`: status, `disabled_by` and
  `disabled_reason`, the last heartbeat (`last_seen_at`, api's clock),
  the reported position, `position_deviation_m` and
  `position_deviations` (heartbeats farther from the pinned position
  than `position_tolerance_m`, default `RID_DEFAULT_POSITION_TOLERANCE_M`
  100 m; the start of a deviation is an events row, T2).
- `src.v1.direct_rid.<receiver>` every 2 s (`source/status/v1`):
  `live`, `stale` with `silent_since`, `unknown` (never heard),
  `disabled` with `disabled_by` (`instance`, `type`, `default_deny`) and
  `disabled_by_who`; counters `accepted`, `refused` and
  `refused_<reason>`, `duplicates`, `stored`, `dropped_shed`;
  `queue_depth`; `lagging` with `lag_s` while the receiver replays
  backlog older than 15 s.
- The status line and `/metrics` of `rid-ingest`: `rid_ingest`
  (`batches_accepted`, `observations_accepted`, `batches_refused`, one
  `refused_*` per reason, `observations_duplicate`,
  `rows_handed_to_writer`, `storage_unavailable`,
  `queue_shed_full_batches`, `queue_shed_age_batches`,
  `queue_shed_observations`, `gap_records_written`,
  `gap_records_waiting`: a batch due to be shed stays queued until its
  gap record is stored, so a restart never loses the record), `keyring`
  (`key_unknown`, `key_check_busy`, `key_argon2_checks`,
  `keyset_refused`), `queue_depth`, `nonces_evicted`.
- Raw frames: `GET /v1/rid/frames?from=&to=&transmitter=&purpose=`
  (inspector, incident officer; `purpose` required and audited; a
  window over 24 h is refused, never thinned) and
  `GET /v1/rid/frames/{frame_id}`.

## When something is wrong

| Symptom | Cause | Action |
|---|---|---|
| `rid-ingest` exits at start with `receiver key set invalid` | an entry of `rid_receiver_keys` does not parse, or an id appears twice (B-14) | api re-projects the bucket within `RID_KEYSET_REPROJECT_S`; restart after it has; if it persists, read the named entry |
| every receiver `401 unauthenticated` after a restart | `rid-ingest` started without the key set (NATS down) and is on loopback | check the start line; restart once NATS is up |
| a receiver change answers `503 key_store_unavailable` | the KV bucket cannot be written; nothing was changed | restore NATS, repeat the change |
| `storage_unavailable` rising, `queue_depth` rising | tsdb-writer's input (`tsw.v1.*`) is down; batches wait in `ingest.v1` | restore it; the queue drains with nothing lost |
| `queue_shed_*` rising, `writer_gaps` rows | the queue passed `RID_INGEST_QUEUE_MAX_BATCHES` or `RID_INGEST_QUEUE_MAX_AGE_S` (10 min) | the gap rows say which receiver and how many; restore storage |
| a receiver `stale` with `silent_since` | it stopped posting: power, network, or it is buffering | check its heartbeat; a disabled receiver says `disabled`, never merely stale |
| `position_deviations` rising | the receiver reports a position away from its pin | inspect it (T2: a moved or captured receiver) |

## Not yet here

- Decoding, identity, time placement and tracks are WP-8 (`ridpipe.Sink`);
  until then rows are stored raw and `pipeline.rows_not_decoded` counts
  them, as the start line says.
- Source control by type and instance is WP-10 (`internal/sources`).
  **Until WP-10 lands, a `direct_rid` switch (by type or by instance) has
  no effect on rid-ingest**: nothing feeds its follower, so every
  receiver is enabled by source control, as the start line says. To stop
  a receiver now, disable it in the registry
  (`POST /v1/rid/receivers/{id}/status`), which takes effect within a
  second; there is no way yet to stop all receivers at once short of
  disabling each.
- The writer of `rid_observations` and `writer_gaps` is WP-9
  (`tsdb-writer`).
