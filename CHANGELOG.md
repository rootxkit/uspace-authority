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
  the ed318 round trip and zones applicability vectors through storage;
  daylight schedules resolved through `ground.Daylight` (WP-11).
- WP-6: the CISP client (`internal/cisp`, relational `00014_cisp`,
  timeseries `00010_restrictions_projection`, `GET /v1/publications`,
  `POST /v1/cis/notifications`): publications of zones, U-space
  airspaces and the USSP list held to the CISP's checks and its pinned
  `cis/uspace_requirements/v1` and `cis/ussp_list/v1` before they are
  signed (a detached JWS with the publication key through core's
  helpers) and queued, one pending snapshot per dataset; an ordered
  sender with `If-Match`, conflict detection that never overwrites,
  backoff capped at 5 min for 24 h, every state change an event; the
  publisher heartbeat every 15 s; the subscriber (registration, webhook
  receiver with compact JWS from the CISP or the ANSP, `aud`, single-use
  `jti`, the `pull_url` guard, M16 reasons; the mandatory 60 s HEAD
  reconciliation, deltas, `ed318.Parse` on receipt, the publisher's
  signature verified on every pulled version, `cis_cache`, `cis_age_s`
  and `cis_stale`); `proj_restrictions` announced on `cis.v1.*`; the
  pinned `api/clients/cisp.yaml` and `cisp-schemas/` with `SOURCE` and a
  CI diff; a fake CISP in `internal/ltest/fakecisp`; the
  cisp-publication runbook.
- WP-12: uspace-core v1.3.0; the violation detectors (`cmd/detect`,
  `internal/detectsvc`): one uspace-core `alerting.Monitor` per claimed
  cell3 over a durable `trk.v1` consumer, built from the zones and
  restrictions projections and the active policy (followed from KV
  `policy`, which api now writes and repairs) and rebuilt when either
  changes, conflicts skipped; raises mapped to `violation/v1`
  (`height_120m`, `zone_incursion`, `unregistered`,
  `identification_mismatch`; USPACE presence as `in_uspace`) with
  evidence excerpts, republished every second, cleared with their reason
  (`reconfigured` when a rebuild no longer raises one), source switches
  clearing `source_disabled` at once; an error-level status line while a
  zone in force is not judged. `internal/violation` (the message and
  `schemas/violation/v1.json`); `internal/violations` (relational
  `00015_violations`): the `alrt.v1` consumer, idempotent, every
  transition an event, `detector_silent` for what detect stopped
  republishing, `GET /v1/violations`, `GET /v1/violations/{id}`,
  `POST /v1/violations/{id}/review`; the violations runbook.
- WP-13: the picture feed (`cmd/picture-ws`, `internal/picture`):
  `GET /v1/picture/ws` with the common console frame (M29), opened
  same-origin with the `uspace_session` cookie and an exact `Origin`
  allow-list (M22), verified by uspace-core's verifier and checked
  against api's sessions table through `GET /v1/auth/session` at the
  upgrade and every 15 s (4401 on logout or revocation, 1013 when it
  cannot be checked); viewport subscriptions over c5 cells with a
  one-cell margin, a status and a snapshot before the live stream, a
  2 Hz per-track throttle above 200 tracks and `dropped_frames`; track,
  manned and active-violation caches (ALRT read back at start and after
  the bus returns, C-08), nothing removed while the bus is lost
  (`nats_unavailable` since T); source rows with "disabled by <who>"
  from the followed switches (`sources.Follower.InstancesOff`);
  `GET /v1/picture/snapshot` and `/v1/picture/sources`; the extras in
  `schemas/picture/`; the operator position for the console realm only;
  the picture runbook.
- WP-14: the ASTM F3411-22a Display Provider (`cmd/dp-poller`,
  `internal/dp`): views from the oversight areas (`/v1/dp/views`, KV
  `dp_oversight`) and the console viewports picture-ws reports (KV
  `dp_views`, expiring), cut into tiles within `dp_view_diagonal_km`
  (≤ 7 km); ISA discovery per tile through the DSS with a 24 h
  subscription renewed at 75 %; the ISA change notification
  `POST /uss/identification_service_areas/{id}` (owner = token subject,
  `rid.service_provider`, own audiences); one poller per (Service
  Provider, tile) at `dp_poll_hz` with every R-14 limit counted (5 s,
  1 MiB, 500 flights, 64 tiles, 20 details at 4 within 2 km, 413 split
  three times, slow at 0.5 Hz past p99 3 s, unavailable since T after
  10 s, plain HTTP only to loopback); flights on `trk.v1` as
  `trust: provider` with the direct broadcast's track id for a CTA
  serial (SC-06 row 3) and identification on the provider basis;
  `ussp_flights` (timeseries 00011) disposed of within 24 h and checked
  hourly by tsdb-writer; `src.v1.network_rid.<uss_id>` every 2 s;
  source control per USSP (SC-16); `/v1/dp/providers` and F3548 USS
  availability arbitration in api; the InterUSS observation hook under
  `/v1/dp/observations` (Q-A7); the pinned F3411, F3548 and observation
  contracts in `api/clients/` with generated clients on uspace-core's
  types; the fake DSS and Service Provider in `internal/ltest/fakedss`;
  the Display Provider runbook.
- WP-17: incidents and evidence packs (`internal/incidents`, migration
  `00017_incidents`, `/v1/incidents*`): case files opened from an
  escalated violation in the review's transaction (and a backfill of
  earlier escalations), from the authority's own observation or an
  ANSP or USSP notice, with aircraft by registration public part,
  append-only notes and every change audited; evidence packs for a
  window with tracks cut at silences, recorded writer gaps and samples
  without a position (holes labelled, never interpolated), raw frames,
  Display Provider rows, zone and policy versions, violations, events,
  the ground of every AGL number and the USSP service record fetched on
  demand, every unreadable source stated as unavailable; deterministic
  ZIP archives sealed by SHA-256 (in `evidence_packs` and `events`) and
  a detached JWS of the seal statement by the publication key, stored
  once under `EVIDENCE_DIR`, legal packs sealed at rest with the PII key
  and gated to personal-data roles; downloads and verifications that
  re-check the hash first and are audited with the purpose; the
  incidents runbook.
- WP-16: USSP and CISP certificates (`internal/certs`, migration
  `00018_certificates`): issue with the holder's code and its client in
  the token service with least-privilege scopes in one transaction;
  status derived from operations, limitation, suspension and end;
  suspend (client suspended, next token refused, `tokens_valid_until`),
  limit, revoke, reinstate, each audited with the reason; the holder's
  operating-status notices from its own client (`POST
  /v1/certificates/{id}/status`) or by letter; the Art. 16(2) lapse job
  on policy periods (`certificate_lapse_*_months`); the public register;
  the `cis/ussp_list/v1` dataset queued in WP-6's outbox inside each
  change, with a durable repair; the certified USSPs in KV for
  dp-poller (replacing `DP_CERTIFIED_USSPS`) and USSP base URLs for
  evidence packs from the register (replacing the CIS list); the
  certificates runbook.
- WP-15: manned-ingest (`internal/manned`, timeseries `00012_manned_tracks`):
  the ANSP's manned traffic stream and snapshot (`api/clients/ansp.yaml`
  and its `track/manned/v1` schema pinned at uspace-ansp 2f9a700) with a
  token of scope `ansp.traffic` for the ANSP's host and, with
  `AUTHORITY_MTLS_MODE=required`, this system's client certificate
  (`off` said at error level on every status line); frames dispatched on
  schema, bodies validated against the ANSP's schema, placed with
  `PlaceBatch` (arrival minus the ANSP's age; at arrival and counted
  without `rx_ts`), the two altitudes kept apart, deduplicated per
  aircraft and aged forward (stale, source_disabled) never removed;
  published on `man.v1` and written to `manned_tracks`; the feed's state
  (healthy, stale, unavailable since T, lagging, disabled by whom) and
  each ANSP adapter's on `src.v1.ansp_feed`, reconnecting forever and
  following source control; the picture's `manned_unavailable` and
  aged-sample replacement; evidence packs' `manned_tracks` section around
  the evidence (replacing WP-17's "unavailable"); the fake ANSP of
  `internal/ltest`; the manned-ingest runbook.
- WP-21: the console (`web/`): Next.js App Router on uspace-ui
  0.1.0-rc.1 (pnpm, frozen lockfile); the BFF's three routes on the
  kit's `bffHandlers` (two-step sign-in against `/v1/auth/login` and
  `/v1/auth/mfa`, the `uspace_session` and `uspace_csrf` cookies, a
  GET-only proxy to an anchored allow-list, logout); ka/en catalogues
  with a lint rule against JSX literals; branding and the map's first
  view from the environment; the shell with the navigation by role; the
  inspector map on `/v1/picture/ws` (viewport subscription, tracks with
  trust, identification, "as broadcast and unverified", ages and source
  state, the zone layer, the sources, the active violations, every
  degraded slug in words with the bus's `nats_since`, `dropped_frames`
  and what was not shown); the operator position dropped before
  anything is stored; generated API and frame types verified in CI; the
  CI job `web` with a Playwright smoke against a stub api and picture-ws
  serving the lab's examples; `web/Dockerfile` and the signed web image
  on main; the web runbook.
- WP-L6 finding 5: rid-ingest binds `RID_INGEST_ADDR` with or without
  receiver keys (it no longer falls back to loopback); with none every
  batch is refused, counted as `refused_no_receiver_keys` and reported
  by the `receiver_keys` check of `/readyz`; a receiver registered later
  is accepted without a restart.
- WP-18: occurrence reports under Reg. 376/2014 (`internal/occurrences`,
  migration `00020_occurrences`): the `occurrences` schema worked by its
  own role `authority_occurrences` through a second pool only that
  package imports, with no grant for `authority_app` and no link to
  violations or incidents (proved on the live catalogue through
  `pg_depend`); `schemas/occurrence/v1.json` with examples, owned here,
  matching the ANSP's outbox body; `POST /v1/occurrences` (scope
  `occurrences.write`, the token's `sub` as `reporter_org`, idempotent
  on the reference, late reports flagged by the database's
  `within_72h`, never refused, the reporter reference sealed under its
  own `OCCURRENCE_KEY_FILE`, registrations cut to their public part);
  reads without the reporter for incident officers and inspectors, the
  reporter for incident officers only with a purpose (audited),
  classification from a configured scheme, analysis and closure; the
  de-identified, hash-sealed and audited export in the pluggable
  `eccairs-compatible-draft` format (Q-A12); the occurrences runbook.
- WP-19: uspace-core v1.4.0. `internal/ground` loads `GEOID_FILE` with
  `geoid.LoadMapped` (after its own 128 MiB bound) and the DEM tiles
  with `terrain.MappedDirOpener`, so detect, dp-poller and rid-ingest on
  one host share the grid and each tile in the page cache; the status
  line says `geoid_mapped` and, once a tile is read, `terrain_mapped`.
- WP-19: the police realm (`internal/police`, migration `00021_police`):
  police accounts per agency holding `police.query` alone, with an IP
  allow-list checked at the password step, the TOTP step and every
  query (client address behind the trusted proxies), and
  `PUT /v1/users/{id}/police-access`; `GET /v1/police/aircraft` (now or
  at an instant, from the tracks, with the picture's freshness and
  writer gaps), `/operators/{reg}` and `/serials/{serial}`, each with a
  configured purpose and a case reference, one `police_queries` row and
  one `police_query` events row before anything personal is opened,
  the operator's identity only for a configured personal-data purpose;
  per-user and per-agency budgets on the database clock; legal exports
  through WP-17's packs (an area export opens an incident
  `police_request`) downloaded by the exporting agency only; no path to
  occurrence reports (imports, queries, role); the monthly DPO report
  `GET /v1/audit/dpo-report`; the police-realm runbook.
- WP-20: the uas.gov.ge import (`internal/regimport`, `POST
  /v1/registry/import`, registrar): a CSV or flat JSON export read under
  a rules file of configuration (columns, value maps, date formats and
  offset, mass unit, the export's number pattern and secret suffix),
  all or nothing in one registry transaction, every problem by record
  and field, a dry run that writes nothing but its events row,
  idempotent on the record's source id (`source = uas_gov_ge_import`,
  `source_ref`, migration `00022_registry_import`), the `registry_imports`
  ledger and the periodic re-import from the agreed `REGISTRY_IMPORT_URL`
  that never reruns content it ran to an outcome; the public status-only
  `GET /v1/registry/check` with a per-address limit; the registration
  applications of the portal behind `REGISTRY_APPLICATIONS=on`
  (`internal/regportal`, migration `00023_registry_portal`: e-mail verification by a signed link, sealed
  content, database budgets per address, review, approval that issues a
  number under the policy's pattern and a secret part mailed once,
  refusal, purge), and an operator's single-use e-mailed link into
  WP-18's intake (`POST /v1/occurrences/operator`) behind
  `REGISTRY_OPERATOR_REPORTS=on`; the mail outbox sent after the commit
  with bounded retries and `en`/`ka` catalogues; the registry-import
  and registry-portal runbooks. Defaults pending GCAA.
- WP-26: the `no_authorisation` detector (`internal/intents`,
  `internal/detectsvc/noauth.go`, migration `00024_no_authorisation_policy`):
  every U-space airspace in force read from the DSS
  (`queryOperationalIntentReferences`, `utm.conformance_monitoring_sa`)
  into a bounded cache never older than 24 h, each aircraft inside one
  asked at its position; unmatched past `no_authorisation_grace_s`
  raises with the candidates and why each failed, a match or the exit
  clears it, the DSS down suspends it (never a clear); with
  `height_limit_in_uspace = skip_when_authorised` the 120 m rule is
  lifted for a matched aircraft whose height was checked (clear reason
  `authorised`); policy defaults pending GCAA; the fake DSS answers the
  query; spec gap Q-A22 (no details, identity or subscription with the
  decided scope); the no-authorisation runbook.
- WP-27: retention, archive and record verification (`internal/retention`,
  `internal/archive`, relational `00025_retention`, timeseries
  `00013_archive`). The spec 08 Q8 periods as configuration, pending
  GCAA (90 days telemetry online, 2 years archive, 5 years violations,
  incidents indefinite, audit 10 years), the regulatory floor enforced by
  the database; `rid_observations`, `tracks` and `manned_tracks` chunks
  past the online window exported by one `COPY` to gzip NDJSON in
  `ARCHIVE_URL` (a local directory), read back and checked, then dropped
  only through `authority_archive_drop_chunk` against the `archive_chunks`
  ledger; the remote pilot position removed from archived System frames
  unless an incident references the aircraft (06 §5); legal holds
  (`/v1/retention/holds*`) and open incidents keep everything they cover;
  expired violations deleted in bounded, audited batches and the oldest
  audit months dropped with the chain's anchor; the monthly hash-chain
  verification recorded in the chain and `GET /v1/audit/verify`; the
  monthly evidence-pack re-verification; the daily USSP records pull
  with the missing-day alarm; the `job_runs` ledger on the database
  clock; `GET /v1/retention/status`; the retention runbook.
- WP-25: the scenario harness (`internal/ltest`): fixtures that run
  rid-ingest, tsdb-writer, detect, dp-poller and manned-ingest in the
  test binary with each binary's own wiring (`detectsvc.RunProcess` now
  holds detect's whole body) against real NATS, PostgreSQL and
  TimescaleDB, with api's violation store, projector and switch and
  policy services; a simulated Remote ID receiver that encodes real ODID
  frames (HAE = AMSL + N, no timestamp before UTC, R-16), signs them
  with a run-time key and posts them with drops, latency and backlog;
  a token endpoint double; a runner that fails a scenario on a missed or
  a false alert, checks every raise and clear against api's rows and
  events, measures the raise latency against the plan's 2 s and the
  no-silent-loss identity per receiver, and writes a results JSON naming
  the commits it measured. Scenarios (`internal/ltest/scenarios`) raise
  and clear every violation kind (`zone_incursion`, `unregistered`,
  `height_120m`, `identification_mismatch`, `no_authorisation`) and
  every clear reason the authority produces (`resolved`, `stale`,
  `landed`, `source_disabled`, `reconfigured`, `authorised`), and the
  degraded states of a receiver, a Display Provider and the manned feed
  (SC-04, SC-06, SC-07, SC-08, SC-10, SC-11, SC-12, SC-13, SC-16, SC-17,
  SC-18, SC-22, the smoke run with no detector). rid-ingest refuses a
  batch carrying `X-Lab-Scenario` with 400 `lab_header` unless
  `LAB_HEADERS_ALLOWED=true` (default false, T11; additive: the
  contract's description of the 400 names it). `make scenarios`, CI job
  `scenarios` with the results uploaded, `docs/runbooks/scenarios.md`.
- WP-22: the console's registry, zone, U-space and certificate pages
  on uspace-ui 0.1.0: operators, UAS and pilots with the look-up by
  number and serial, the Art. 14(2) forms and status transitions with a
  reason; personal data only behind a configured purpose
  (`WEB_PII_PURPOSES`, defaults pending GCAA) sent with the request;
  the import's dry run by record and field; the applications queue;
  the ED-318 zone editor on the map (every property by its standard
  name, polygons and circles sent as centre and radius, schedules by
  daylight event, WGS84 flagged), versions with their difference,
  approval, the applicability check, export, the ED-318 and ED-269
  import with every problem by path; U-space designation with the Art.
  3(4) block; publication with its exact effect and the outbox state;
  certificates (issue with the secret once, suspend, limit, revoke,
  reinstate, the operating-status timeline, the public register
  preview, the USSP list); the BFF's writes on an anchored allow-list
  with a body bound; the editor's bodies validated by the zone service
  in Go; Playwright and axe on every page; the runbook section and the
  A-M1 console run against the fake CISP.
- WP-23: the console's oversight pages, the police realm and the public
  pages (`web/`, on uspace-ui v0.1.0): violations with their filters and
  the excerpt drawn in api's segments and holes, each hole labelled and
  nothing interpolated (`GET /v1/violations/{id}` answers
  `excerpt_segmenting`, cut by the evidence packs' rule), every AGL
  number with its terrain dataset, spacing and attribution, the
  broadcast warning and the review; incidents with aircraft, notes and
  evidence packs (build with a purpose and a case reference, manifest,
  hash, verify, download); the occurrence officer realm (incident
  officer only: the 72 h flag, the reporter only from api's answer,
  classification, analysis, the de-identified export and its narrative
  warning); sources with who disabled what and a mandatory reason for
  every switch; the audit log, the monthly chain verification and the
  DPO report; the police realm in its own layout and colour band, a
  purpose and a case reference on every query (the purposes as
  configuration, defaults pending GCAA), and no picture WebSocket; the
  registration check (status only), the public register and the rules
  from configured Markdown; ka/en, Playwright and an axe check (WCAG 2.2
  AA) in English light and Georgian dark.
- WP-L7 conformance C6 (bug fix, no contract change): a request the
  generated code cannot parse (a missing or malformed parameter, an
  unreadable body) is put to the operation's access rules first
  (`apiserver.Admission`, the gate `Authorize` applies): without a
  credential it is `401 unauthenticated`, without the role or scope
  `403 forbidden`, and only an admitted caller hears `400 validation`.
  `apiserver.Options.Admit` left unset fails closed (401 on every
  operation that is not public).
- WP-L7 conformance C4 (contract: additive `401` on `getPictureWS`):
  picture-ws answers an upgrade without the `uspace_session` cookie
  `401 unauthenticated` before it judges the upgrade or the Origin
  (counted as `upgrade_refused_no_session`), instead of `403 origin`
  without an Origin or a 4401 close after the upgrade with one. With
  the cookie, a missing or foreign Origin is still `403 origin`; 4401
  now means a refused or ended session.
- WP-L7 conformance C7 (contract bug fix): `postDPISANotification`
  declares its refusal body: every 400, 401, 403, 413 and 503 of the
  dp-poller notification route is `application/problem+json`, the new
  component `DPNotificationProblem` (problem/v1 with the F3411
  `ErrorResponse` member `message` beside it, equal to `detail`), and
  the code writes exactly that instead of a bare `{"message"}` the
  contract did not declare. A 400 names the field in `errors`.
- WP-24: the staging deployment. `deploy/compose.yaml`, the staging and
  production shape: the seven processes from one image, the one-shot
  `migrate` every process waits for, `web`, one timescaledb-ha
  container holding both databases, NATS with one user per process,
  named volumes (the image now creates the evidence and archive mount
  points owned by its non-root user), memory and CPU limits from the
  demo budget, read-only roots, an internal project network, Caddy's
  edge network joining only api, rid-ingest, dp-poller, picture-ws and
  web, and each process given only the DSN it opens;
  `deploy/staging.env.example` with GCAA's open choices at the spec's
  defaults, marked pending GCAA; `deploy/env/<process>.env.example`
  generated from every process's `--help`; `deploy/gen-secrets.sh`;
  `deploy/caddy/authority.snippet` (mTLS subject only on the token
  endpoint, `/basemap/*` with ranges and cache headers, `/metrics` and
  `/readyz` never routed) and its proof against the pinned Caddy;
  `deploy/verify-image.sh`; `deploy/deploy.sh` (verify, pull, migrate
  and its versions, rolling restart, then `/healthz`, every `/readyz`
  check, version and status line of each process, exiting non-zero on
  the check that failed); `deploy/backup.sh` (both databases and the
  KV buckets, read back before kept, optional rclone copy) and
  `deploy/restore-check.sh` (restores into scratch databases and prints
  the counts); the lab's registry fixture for REG-NOPII
  (`deploy/fixtures/operator.json`, `GEOTESTLAB0001`). CI: the `deploy`
  job (`make check-deploy`), the `staging-smoke` job (`deploy/smoke/run.sh`:
  the stack from scratch through `deploy.sh`, the Go driver through the
  public host, backup and restore check with known counts, the
  older-schema refusal, the teardown checked), and SPDX SBOMs attested
  with cosign and both signatures read back on `main` and tags. The
  runbooks `staging.md` and `cutover.md`.
- System audit 2026-10-05 H-2 (bug fix; contract: the ANSP's additive
  `GET /v1/restrictions/{id}/direct`): the ANSP's degraded direct
  delivery (02 F2 failure rule, cross-plan M4, M5) was acknowledged and
  discarded. Its record's `version`, the restriction's `ansp_version`,
  was read as the CIS restrictions version and skipped as a replay, and
  the ANSP's `pull_url` was never followed. The receiver now hands an
  ANSP restriction notification whose `pull_url` is on the ANSP's issuer
  URL to the subscriber's direct path: it pulls the ANSP's signed
  `restriction/direct/v1` (no credential), verifies `X-JWS-Signature`
  with the ANSP's publisher keys, checks it is the restriction,
  identifier and `ansp_version` the record named, stores it
  (`cis_direct_restrictions`, migration `00026`, so a restart keeps it),
  projects it into `proj_restrictions` over the CISP's version and
  announces `cis.v1.restrictions`, until the CISP holds that
  `ansp_version` or a newer one; an end delivered the same way is
  projected `ended`. A full queue answers `503` before the delivery id is
  recorded; a failed pull is retried. `CIS_DIRECT_MAX` (500) and
  `CIS_DIRECT_KEEP_S` (86400, pending GCAA). The ANSP's contract fixture
  is vendored in `internal/cisp/testdata/ansp-direct` at the commit its
  `SOURCE` names.
