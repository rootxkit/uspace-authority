# WP-6: CISP publisher and subscriber

Branch `feat/WP-6-cisp-client`. Milestone A-M1. Owns `internal/cisp`,
the migrations for `publications` and `cis_cache`, the projection table
`proj_restrictions`, the route `POST /v1/cis/notifications`, the outbox
behind `/v1/zones/publish`, `/v1/uspace/publish` and
`/v1/certificates/publish-list`, and `api/clients/cisp.yaml`. Depends on
WP-2 (token client, JWS key) and WP-5. Consumers: WP-12 (restrictions),
WP-13, WP-16 (`ussp_list`), WP-22.

## Read first

1. `docs/PLAN.md` §5 (outbound clients), §6 (`cis.v1`), §7 (JWS), §14
   Q-A2.
2. Spec `02 F1` (API, `If-Match`, detached JWS, failure rule), `02 F3`
   (pull with `ETag`, `since_version`, `/v1/changes`, webhook
   `cis/change/v1`, the mandatory 60 s reconciliation, `cis_version` and
   `cis_age_s` on every output), `04 §3.4`, `05 §6` CISP row, `06 §2` T4,
   T9 (ED-318 validated on receipt, never repaired).
3. `uspace-core/ed318.Parse` (receipt validation), `auth` (JWS through
   `jwx`), the CISP repo's `api/openapi.yaml` once published (copy it
   into `api/clients/cisp.yaml` with the commit recorded in a `SOURCE`
   file).
4. LESSONS B-08, E-02, E-14, Z-12.

## What to build

### Publisher (F1)

- Outbox `publications`: a publish endpoint snapshots the full dataset
  (ED-318 `FeatureCollection` from WP-5's export, or the USSP list from
  WP-16), computes `payload_hash`, signs it as a detached JWS (RS256,
  this system's active signing key, `kid` in the header; the CISP
  verifies against this issuer's JWKS) and inserts `state = pending`.
- A sender job (`api`, advisory lock) delivers in order per dataset:
  `PUT /v1/publications/{dataset}` with `If-Match: <cisp_version last
  acknowledged>`, bearer from `tokens.Client` with scope
  `cis.publish:<dataset>` and audience `cisp`; on 2xx store the CISP's
  version; on 412 (precondition failed) refetch the current version,
  mark `conflict` and stop for an operator decision (never overwrite
  blindly); on 5xx or network error retry with exponential backoff (cap
  5 min) for 24 h, then `failed` with the reason. Every state change is
  an `events` row.
- Status for the console: `GET /v1/publications` with `state`, `age_s`
  since pending ("not yet published" age, `02 F1` failure rule).

### Subscriber (F3)

- `cis_cache` per dataset (`zones`, `uspace_airspace`, `ussp_list`,
  `restrictions`) with `version`, `etag`, `fetched_at`, `payload`.
- Registration: on startup (idempotent) `POST /v1/subscriptions
  {callback_url, datasets, bbox}` with scope `cis.read`; the callback
  URL is config.
- Webhook `POST /v1/cis/notifications`: body is a JWS; verify with the
  CISP's JWKS (issuer and audience from config, `core/auth`), parse
  `cis/change/v1`, then **pull** the delta (`GET /v1/{dataset}?
  since_version=`) — never trust the notification body for content.
  Refused notifications are counted and logged once per interval.
- Reconciliation every 60 s per dataset: `HEAD` on the `ETag`, `GET` on
  change; this is mandatory and runs whether or not webhooks arrive
  (`02 F3`; E-02: a test kills the webhook path and proves the pull
  catches the change within 60 s).
- Every received `FeatureCollection` is validated with `ed318.Parse`;
  a collection that fails is refused whole, counted
  (`cis_rejected_publications`), reported to the console, and the
  previous version stays (T9).
- Restrictions (`reason` `DAR`) are written to `proj_restrictions` in
  the telemetry database with their state and window and announced on
  `cis.v1.restrictions`; `detect` (WP-12) merges them into its zone set
  within one tick (Z-12). The USSP list is kept for WP-14's discovery
  and for the console.
- `cis_version` and `cis_age_s` exposed on `/v1/picture/sources`
  (WP-13) and on the status line; beyond `cis_stale_bound_s` the
  console shows `cis_stale` (this system refuses nothing on it: the
  authority issues no authorisations).

## Tests

- Unit: JWS signing and verification round trip with a run-time key;
  `If-Match` handling for 2xx / 412 / 5xx; backoff bounds; a malformed
  ED-318 collection refused with the problem list (E-01 beside an
  accepted one).
- Integration against a fake CISP in `internal/ltest` (an HTTP server
  implementing exactly `02 F1`/`F3`): publish, acknowledge, conflict;
  webhook delivery, then webhook suppressed and the 60 s pull observed;
  CISP down for the whole test → previous version served with
  `cis_age_s` rising, publication `pending` with age (E-02).
- E-10: outbox bounded per dataset (one pending snapshot replaces an
  older pending one; the superseded one is recorded as `superseded`).

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] A-M1: a zone authored in WP-5 is published to the fake CISP,
  acknowledged, and a change pushed by the fake CISP lands in
  `cis_cache` and `proj_restrictions`.
- [ ] `api/clients/cisp.yaml` with `SOURCE` recording the uspace-cisp
  commit; a CI step diffs it against that commit.
- [ ] `docs/runbooks/cisp-publication.md`: states, conflict handling,
  what the console shows.
- [ ] CHANGELOG line; `internal/cisp/doc.go`.

## Commits

`feat(cisp): signed full-dataset publications with an ordered outbox and retry [WP-6 A-M1]`,
`feat(cisp): subscribe to the CIS with signed webhooks and the 60 s reconciliation pull [WP-6 A-M1]`,
`feat(cisp): project dynamic restrictions for the detectors [WP-6 A-M1]`.
