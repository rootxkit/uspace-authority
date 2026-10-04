# WP-7: Remote ID receivers and observation ingest

Branch `feat/WP-7-rid-receivers-ingest`. Milestone A-M2. Owns
`internal/receivers`, `cmd/rid-ingest` (the HTTP side: authentication,
batch acceptance, raw storage handoff, backpressure), the `rid_receivers`
migration, the `rid_observations` hypertable migration (writer side in
WP-9), the routes `/v1/rid/receivers/*`, `/v1/rid/observations`,
`/v1/rid/frames/*`, and `schemas/rid/observation/v1.json`. Depends on
WP-1, WP-9, WP-10. WP-8 adds the decode-to-track pipeline behind the
`ridpipe.Sink` interface this WP defines. Consumers: WP-8, WP-17 (raw
frames), WP-25.

Safety-relevant (the only unauthenticated radio source enters here).
Reviewed adversarially.

## Read first

1. `docs/PLAN.md` §2.1 `rid-ingest`, §4, §5 receiver rows, §6
   (`ingest.v1`, `tsw.v1`), §7, §8.
2. Spec `02 F9` (data, API, auth, volume, failure), `04 §2` envelope and
   `backlog`, `05 §5` backpressure rows for receivers, `06 §2` T2, T8,
   T11.
3. `uspace-core/auth`: `ReceiverVerifier`, `NewReceiverVerifier`,
   `AddReceiverKey`, `WithNonceMemory`, `WithMaxDatagramBytes`, `Report`,
   `Verify`, its counters and the vector phrases; `odid.TypeOf` (for
   routing only; decoding is WP-8).
4. LESSONS R-06, R-15, B-05, B-07, B-10, B-11, B-12, B-14, B-16, E-09,
   E-10, T-11, T-12; scenarios SC-08 (receiver side), SC-18.
5. Reference only: utm `gateway/remote_id_auth.py`,
   `gateway/remote_id_ingest.py`, `gateway/remote_id_store.py`,
   `docs/runbooks/p1-15-remote-id.md`.

## What to build

### Receiver registry (`api`)

- `rid_receivers`: `id` slug, `name`, `geom` (pinned position), `owner`
  (GCAA / third party), `key_hash` (bearer key, argon2id), `hmac_secret`
  (encrypted with the PII key, ≥ 32 bytes, generated here), `status`
  enabled/disabled, `disabled_by`, `disabled_reason`, `last_seen_at`,
  `last_position`, `firmware`, `config` JSONB (batch interval, backlog
  cap, reporting fields). Creation returns the bearer key and HMAC secret
  **once**; rotation (`POST .../keys/rotate`) issues new ones with a
  grace period for the old; every change audited.
- `GET /v1/rid/receivers/{id}/config` (bearer) and `POST .../heartbeat`
  every 10 s (bearer, body HMAC): updates `last_seen_at`, position
  (compared with the pinned position; a deviation beyond a configured
  radius is counted and shown, T2).
- The key set is projected into KV `rid_receiver_keys` (id → bearer hash,
  HMAC secret) for `rid-ingest`, re-read on push and every 60 s; a
  receiver with an empty or duplicate id is a startup error of the
  ingest (B-14).

### Ingest (`cmd/rid-ingest`)

- `POST /v1/rid/observations`: bearer key identifies the receiver;
  the body is the exact bytes the receiver signed; the signature travels
  in the `X-Report-Signature` header (hex HMAC-SHA256) — the datagram
  form core verifies (`report\nsig=hex`) is assembled from body and
  header, so the receiver signs the body bytes alone and an ESP32 can do
  it. `ReceiverVerifier.Verify` with `maxSkew` 30 s and the per-receiver
  nonce memory. Refusals: 401 for unknown receiver or bad signature,
  400 for malformed, 409 for a repeated nonce, 503 + `Retry-After` for a
  disabled receiver (B-10) or a full queue — never 403 — each counted
  and logged once per interval.
- Body: `rid/observation/v1` batch (≤ 1 s, ≤ 64 observations, ≤ 64 KiB):
  `receiver_id`, `sent_at_ms`, `nonce`, `backlog`, `observations[]
  {transmitter, payload_hex, rssi_dbm, rx_ts, receiver_position}`.
  `rx_ts` is the receiver's clock; `ingest_ts` is this process's.
- Source control: the `sources.Follower` (WP-10) is consulted per
  receiver (`direct_rid` type, instance id) before verification;
  disabled → 503, counted, nothing stored (B-10, B-11).
- Acceptance: a batch is acknowledged (202) only after it is written to
  the JetStream work queue `ingest.v1.<cell3>` (B-05); the queue is
  bounded (10 min) and a full queue sheds the **oldest** with a
  `writer_gaps` record and a counter, never the newest (`05 §5`).
  Dedupe window per receiver on `(transmitter, rx_ts, payload hash)`
  for 60 s so a replayed batch publishes nothing twice (B-05).
- Each accepted observation is handed to `ridpipe.Sink` (WP-8) for
  decoding and to the raw-storage path: `tsw.v1.rid_observations` rows
  with the raw payload bytes (R-15, B-12), `backlog`, `receiver_id`,
  `transmitter`, `rssi_dbm`, `rx_ts`, `ingest_ts`. Decoded columns are
  filled by WP-8 before the row is handed over (one row, written once).
- `src.v1.direct_rid.<receiver>` status every 2 s: enabled, last seen,
  accepted, refused by reason, queue depth, `lagging` with `lag_s`
  (B-03), `silent since T`, `disabled by <who>` (B-11).
- Raw frames API (`api`): `GET /v1/rid/frames?transmitter=&from=&to=`
  and by id, from `rid_observations` read-only, bounded window (refuse
  a window above 24 h rather than thin it, B-13), audited with purpose.

## Tests

- Vectors: `rid_receiver_auth.json` through `RunOwned("authority")` over
  the HTTP adapter (header + body → datagram → `Verify`), proving the
  mapping and not re-testing core.
- E-01 pairs for every refusal (unsigned, unknown, bad signature, skew,
  replay, disabled, malformed, oversize, queue full) beside an accepted
  batch.
- E-02: with no keys configured the ingest binds to loopback only and
  says so (R-06; superseded by WP-L6 finding 5: it binds its configured
  address, refuses every batch, counts it and fails `/readyz`
  `receiver_keys`, and accepts later keys without a restart); the success path acknowledges and the row reaches the
  writer in the integration test.
- E-10: nonce memory bound, dedupe window bound, queue bound (SC-18 step
  3: oldest dropped and counted).
- Integration: SC-18 (storage down: rows wait in the queue, written when
  it returns, none lost, cap respected); SC-08 steps 2–3 for the receiver
  side (disable by type → 503 and the refusal counter; enable → accepted
  within 1 s).
- Load smoke: 50 simulated receivers × 20 aircraft × 3 msg/s for 60 s on
  the CI runner; every accepted + refused + dropped = sent (`05 §7` no
  silent loss).

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] Receiver lifecycle through the API: create (key shown once),
  heartbeat, disable, enable, rotate, delete; every step audited.
- [ ] The load smoke numbers in the PR with the counters that account
  for every message.
- [ ] `docs/runbooks/receivers.md`: receiver onboarding, the signing
  contract (what bytes are signed, header name, nonce rules), the
  refusal codes a receiver must handle.
- [ ] CHANGELOG line; `internal/receivers/doc.go`, `cmd/rid-ingest` doc.

## Commits

`feat(receivers): receiver registry with keys shown once and audited switches [WP-7 A-M2]`,
`feat(rid-ingest): authenticate signed observation batches and acknowledge after the queue write [WP-7 A-M2]`,
`feat(rid-ingest): keep every raw frame and report each receiver's state [WP-7 A-M2]`,
`test(rid-ingest): run the receiver authentication vectors through the HTTP adapter [WP-7 A-M2]`.
