# Changelog

All notable changes to this repository. One line per work package under
Unreleased; the format follows Keep a Changelog.

## Unreleased

- WP-0: Go module on uspace-core v1.0.0; seven process stubs and the
  `uspace-authority` entrypoint with the `migrate` subcommand; config,
  logging, metrics, tracing and httpx baselines; OpenAPI skeleton with
  generated server, client and types; empty relational and timeseries
  migration trees; Makefile, CI, Dockerfile and the development compose
  stack.
- WP-1: `internal/store` (pgx pools with statement timeout,
  `application_name` and a per-process role; `sqlc` query sets for the
  relational database and the telemetry writer and reader; `WithTx`,
  session advisory locks for jobs, the schema-version check of D7;
  `migrate.Status` and `Latest`); the `events` audit log, partitioned by
  month, append-only by grant and trigger, with a monthly SHA-256 hash
  chain, `Verify` and `GET /v1/audit/events`; the versioned
  `authority_policy` with documented defaults, E-15 validation, audited
  create and activate, a `Follower` and `/v1/policy*`; the
  `authority_app`, `authority_ts_reader` and `authority_ts_writer` roles;
  the `requireRole` placeholder WP-2 replaces.
- WP-2: uspace-core v1.1.0; the ecosystem token service (`/oauth/token`
  client credentials with `client_secret_post` or `private_key_jwt`,
  `aud` = target host, scopes from table B, every issuance and refusal
  an event; `/.well-known/jwks.json` and issuer metadata; signing keys
  from PEM files with two-person rotation and a 24 h overlap; the
  publication key in the same JWKS; `/v1/oauth/clients*` and
  `/v1/oauth/keys*`); console accounts with argon2id, TOTP MFA sealed
  with the PII key, recovery codes, two-step sign-in without user
  enumeration, rate limits, sessions of table A with idle expiry and
  revocation, `/v1/auth/*` and `/v1/users*`, the first-admin bootstrap;
  the core/auth verifier wiring (own keys, CISP, ANSP and lab issuers);
  `tokens.Client` for outbound calls; the token-service and
  session-contract runbooks.
- WP-3: the registry (`internal/registry`, migrations
  `00009_registry` and `00003_registry_projection`): operators with the
  Art. 14(2) field set, UAS and remote pilots with competencies;
  registration numbers and serials through core `regnum` and `serial`
  only, the number's format from the new policy column
  `registration_number_pattern`; personal columns sealed with the PII
  key, the secret part and national id as keyed hashes
  (`REGISTRY_HASH_KEY_FILE`); one status graph with an expiry job;
  every change an event and an F8 change-feed entry; the projection
  `proj_registry_operators` / `proj_registry_uas` written as
  `authority_ts_projector` with the change (rolled back with it), and
  repaired at startup and every 300 s under an advisory lock;
  `ProjectionReader` for the resolvers; `/v1/registry/*` for registrars
  with purpose-logged personal-data reads; F8 `validate` (status only,
  batch of 100) and `changes` behind scope `registry.validate`.
- WP-7: Remote ID receivers and observation ingest
  (`internal/receivers`, `internal/receivers/ingest`, `cmd/rid-ingest`,
  migrations `00010_rid_receivers` and `00004_rid_observations`,
  `schemas/rid/observation/v1.json`): the receiver registry with keys
  shown once (argon2id bearer hash, HMAC secret sealed with the PII
  key), audited disable, enable, rotation with grace and delete, the
  key set projected into KV `rid_receiver_keys` inside each change and
  repaired every 60 s; the receivers' own config and signed heartbeat
  with the pinned-position deviation (T2); `POST /v1/rid/observations`
  through uspace-core `auth.ReceiverVerifier` (body plus
  `X-Report-Signature`, 30 s window, nonce memory), 503 with
  `Retry-After` for a disabled receiver or source type, a 60 s dedupe
  window, 202 only after the JetStream work queue `ingest.v1.<cell3>`
  confirmed the write, the oldest shed past the queue's bound with a
  `writer_gaps` record; every raw frame handed to tsdb-writer on
  `tsw.v1.rid_observations` behind the `ridpipe.Sink` seam WP-8 fills;
  `src.v1.direct_rid.<receiver>` every 2 s; loopback only without keys;
  purpose-logged raw frames `/v1/rid/frames*`; the receivers runbook.
  The type-level (and instance-level) `direct_rid` source-control switch
  has no effect until WP-10 feeds rid-ingest's follower; the registry
  disable is the working switch until then.
- WP-10: uspace-core v1.2.0; `internal/bus` (per-process NATS
  credentials, reconnect for ever, three start attempts then a degraded
  start that says so; `bus.Ensure` run by api for the streams TRK, ALRT,
  IDENT, CIS, INGEST and TSW and the KV buckets source_control, policy,
  cells, registry_version, zones_version and rid_receiver_keys, each
  with an explicit size bound, idempotent; typed subjects that refuse a
  widening token, the 04 §2 envelope, bounded pull consumers and a
  push-then-reread KV follower), which replaces WP-7's stand-ins;
  `internal/cell` over core `geodesy/cell` (subject tokens, viewport with
  a one-cell margin, the cell3 ownership map with `GET/PUT /v1/cells`,
  and detect refusing to start without cells unless `CELLS=all`);
  source control (`source_controls` with a version sequence and an
  epoch, audited switches by type and instance in one transaction with
  the KV write and 503 without it, the push on `ctl.sources`, the 60 s
  republish and a new epoch for a restored database, `/v1/sources*` for
  admins, every process following the state and starting enabled when
  it cannot read it, rid-ingest refusing a disabled `direct_rid` and
  saying who disabled it, api keeping every adapter's status for the
  console); `schemas/source/control/v1.json`; the source-control
  runbook. The drain closes connections that never sent a request, so a
  spare client dial no longer makes a shutdown overrun its bound.
- WP-9: tsdb-writer (`internal/tswriter`): a durable pull consumer per
  table on `tsw.v1.<table>` (explicit ack, bounded `max_ack_pending`), a
  queue bounded to 10 s or 30000 rows that stops pulling at its bound
  (`spilling`), batches of at most 1000 rows or 500 ms written by COPY
  into a staging table and `INSERT .. ON CONFLICT DO NOTHING`, messages
  acknowledged only after the commit; `writer_gaps` with the producers'
  records, `stream_retention` holes seen as sequence steps the TSW stream
  no longer holds, `malformed` messages and `rejected` rows, each in the
  transaction of the rows beside it; the counters `rows_written`,
  `rows_deduplicated`, `batches`, `spills` and `gaps`; a degraded start
  with the database down and a stop on an older schema; the hourly
  retention check. `internal/store/ts`: the adapters' `Writer`
  (`Enqueue`, `EnqueueGap`), the table registry, `WriterPool.Write` and
  `OlderThan` (the pool type is now `WriterPool`). Timeseries `00005`:
  `writer_gaps`, the `(frame_id, ingest_ts)` dedupe index, 1-day chunks
  and compression after 7 days for `rid_observations` (no 90-day
  retention until WP-27's archive), `authority_hypertable_policies` for
  the later hypertables, `TEMPORARY` for the writer role;
  `schemas/tsw/rows/v1.json`, `schemas/tsw/gap/v1.json`; the tsdb-writer
  runbook.
- WP-8: the Remote ID pipeline (`internal/ridpipe.Pipeline`, rid-ingest's
  Sink): T-02 receipt placement, `odid.Decode` with refusals counted by
  phrase, `timeplace.PlaceBroadcast`, `rid.Tracker` per transmitter (a
  live and a backlog tracker), `rid.AltitudeSelector` with the geoid,
  `rid.VelocityNED`/`Airborne`, `identify.ResolveRemoteID` over the
  registry projection (read by rid-ingest, `registry_unavailable` until
  loaded), all bounded and counted; `internal/track` (track/telemetry/v1
  typed from the lab's common schema, T11 validation, `trk.v1` subjects,
  `ident.v1` changes with `schemas/ident/change/v1.json`, tracks rows);
  timeseries `00006` (decoded `rid_observations` columns, the `tracks`
  hypertable) handed over by the worker on `tsw.v1.tracks`; the `RID_*`
  thresholds; the five Remote ID vector files run through the ingest
  adapters and scenarios SC-06, SC-10, SC-11, SC-22 in process.
  tsdb-writer records a purge of `TSW` as a `stream_purge` gap
  (timeseries `00007`, `writer_positions`).
- WP-11: `internal/ground` over core's `terrain` and `geoid`: `Env`
  (known, unknown or not-configured ground, never 0 m for what is not
  known; the undulation or nil), the `Undulator` and `Ground`
  interfaces, `Problems` and the status line with the datasets and the
  Copernicus attribution; `Daylight` is core's `ed318.NOAADaylight`;
  `GROUND_DIR`, `GEOID_FILE`, `GROUND_TILE_CACHE`,
  `GROUND_RETRY_AFTER_S`; rid-ingest computes AMSL through
  `GEOID_FILE` (HAE only without it) and detect says what ground it
  has; `deploy/fetch-ground.sh` (SHA-256-pinned geoid grids, checked
  terrain tiles); CI runs the GeographicLib vector cases; the ground
  runbook.
- WP-5: zones and U-space airspaces (`internal/zonesvc`, relational
  `00012_geo_zones` and `00013_publications`, timeseries
  `00009_zones_projection`, `/v1/zones*`, `/v1/uspace*`): versioned
  ED-318 features stored as `ed318.Export` wrote them (draft, approved,
  published, superseded; period of validity mandatory; circles as centre
  and radius; WGS84 flagged as this project's extension); every write
  through `ed318.Parse` and `ed318.ToZones`; ED-318 and ED-269 import all
  or nothing with problems by path, and the airspace.gov.ge converter
  with a rules file; U-space designations with the Art. 3(4) block in
  the CISP's `cis/uspace_requirements/v1` shape; publication into a
  pending, unsigned outbox row (signed and sent by WP-6), the
  `proj_zones` projection written with it and repaired every 300 s, and
  `zones.v1.changed` / KV `zones_version`; export `?at=` and
  `?applies_at=` (M17); `ProjectionReader` building the `zones.Index`;
  the ed318 round trip and zones applicability vectors through storage.
