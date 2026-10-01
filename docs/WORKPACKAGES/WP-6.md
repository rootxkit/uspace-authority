# WP-6: CISP publisher and subscriber

Branch `feat/WP-6-cisp-client`. Milestone A-M1. Owns `internal/cisp`,
the migrations for `publications` and `cis_cache`, the projection table
`proj_restrictions`, the route `POST /v1/cis/notifications`, the outbox
behind `/v1/zones/publish`, `/v1/uspace/publish` and
`/v1/certificates/publish-list`, the publisher heartbeat job, and
`api/clients/cisp.yaml`. Depends on WP-2 (token client, JWS key), WP-5
and `uspace-core` v1.1.0 (the JWS helpers `auth.SignDetached`,
`VerifyDetached`, `SignCompact`, `VerifyCompact`, `KeyRing`; core
WP-14, M27 — this WP is not on the critical path and waits for it
rather than writing its own `jwx` code). Consumers: WP-12
(restrictions), WP-13, WP-16 (`ussp_list`), WP-22.

## Read first

1. `docs/PLAN.md` §5 (outbound clients), §6 (`cis.v1`), §7 (JWS), §14
   Q-A2.
2. Spec `02 F1` (API, `If-Match`, detached JWS, failure rule), `02 F3`
   (pull with `ETag`, `since_version`, `/v1/changes`, webhook
   `cis/change/v1`, the mandatory 60 s reconciliation, `cis_version` and
   `cis_age_s` on every output), `04 §3.4`, `05 §6` CISP row, `06 §2` T4,
   T9 (ED-318 validated on receipt, never repaired).
3. `uspace-core/ed318.Parse` (receipt validation), `auth` (the v1.1.0
   JWS helpers), the CISP repo's `api/openapi.yaml` and its
   `schemas/cis/*` from its WP-0 skeleton onward (copy them into
   `api/clients/cisp.yaml` and `api/clients/cisp-schemas/` with the
   commit recorded in a `SOURCE` file; bump in `build:` commits only).
   The CISP's open questions Q8 (detached JWS) and Q9 (webhook JWS) are
   the wire formats; `docs/WORKPACKAGES/WP-2.md` table A restates them.
4. LESSONS B-08, E-02, E-14, Z-12.

## What to build

### Publisher (F1)

- Outbox `publications`: a publish endpoint snapshots the full dataset
  (ED-318 `FeatureCollection` from WP-5's export, or the USSP list from
  WP-16), validates it against the pinned copy of the CISP's schema
  (`cis/uspace_requirements/v1` for the Art. 3(4) block,
  `cis/ussp_list/v1` for the list; the CISP owns both, M7), computes
  `payload_hash`, signs it as a detached JWS in the CISP's format
  (`X-JWS-Signature: <protected>..<signature>`, RFC 7515 App. F,
  RFC 7797 `b64: false`, `crit: ["b64"]`, `alg RS256`, `kid`, `iat` ≤
  5 min; M26) with this system's publication-signing key, which WP-2
  lists in this issuer's JWKS under its own `kid`, and inserts
  `state = pending`.
- A sender job (`api`, advisory lock) delivers in order per dataset:
  `PUT /v1/publications/{dataset}` with `If-Match: <cisp_version last
  acknowledged>`, bearer from `tokens.Client` with scope
  `cis.publish:<dataset>` and audience = the CISP's host (M18; client
  id `authority-01`, M24); on 2xx store the CISP's
  version; on 412 (precondition failed) refetch the current version,
  mark `conflict` and stop for an operator decision (never overwrite
  blindly); on 5xx or network error retry with exponential backoff (cap
  5 min) for 24 h, then `failed` with the reason. Every state change is
  an `events` row.
- Status for the console: `GET /v1/publications` with `state`, `age_s`
  since pending ("not yet published" age, `02 F1` failure rule).
- Publisher heartbeat (M3): a job in `api` (advisory lock) posts
  `POST /v1/publishers/heartbeat {sent_at}` to the CISP every 15 s with
  any `cis.publish:*` scope (`active_refs` is omitted: the authority
  publishes no restrictions); the CISP marks a publisher stale after
  three misses (60 s). The job's last success and the CISP's answer are
  on the status line; a failing heartbeat is a counter, never a crash.

### Subscriber (F3)

- `cis_cache` per dataset (`zones`, `uspace_airspace`, `ussp_list`,
  `restrictions`) with `version`, `etag`, `fetched_at`, `payload`.
- Registration: on startup (idempotent) `POST /v1/subscriptions
  {callback_url, datasets, bbox}` with scope `cis.read`; the callback
  URL is config.
- Webhook `POST /v1/cis/notifications` (the one receiver path every
  subscriber implements, M1): body is a compact JWS (`Content-Type:
  application/jose`) whose payload is `cis/change/v1`; verify with
  `core/auth` against an allow-list of **two** issuers,
  `AUTHORITY_CIS_NOTIFY_ISSUERS` = the CISP and the ANSP with their
  JWKS URLs (the ANSP's degraded direct delivery posts the same message
  here signed with its own key, M5), `aud` = this host (`AUTHORITY_
  AUDIENCES`, M19), `jti` single-use. Then **pull** the delta
  (`GET /v1/{dataset}?since_version=`) — never trust the notification
  body for content; a `pull_url` in the message is honoured only when
  its host equals the issuer's configured base host (SSRF guard), else
  the configured CISP URL is used and the mismatch counted. Reasons
  `subscription_test`, `republished` and any reason unknown to this
  receiver are acknowledged `204` without a pull (additive-enum rule
  of `04 §4`, M16). Refused notifications are counted and logged once
  per interval.
- Reconciliation every 60 s per dataset: `HEAD` on the `ETag`, `GET` on
  change; this is mandatory and runs whether or not webhooks arrive
  (`02 F3`; E-02: a test kills the webhook path and proves the pull
  catches the change within 60 s). Reads use the CISP's filtering
  `?at=` where the detectors need only what applies now, and carry
  the CISP's top-level `cis_dataset`, `cis_version`, `cis_updated_at`
  and `ETag` (core's `ed318.Metadata` names inside, M15).
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

- Unit: detached JWS signing and verification round trip with a
  run-time key through core's helpers, including the `b64: false`
  payload bytes; `If-Match` handling for 2xx / 412 / 5xx; backoff
  bounds; a malformed ED-318 collection refused with the problem list
  (E-01 beside an accepted one); a payload failing the pinned CISP
  schema refused before signing (beside one that passes); webhook
  from the CISP accepted, from the ANSP accepted, from a third issuer
  refused, with a `pull_url` on another host ignored and counted;
  `subscription_test` → `204` and no pull, `zones` change → pull.
- Integration against a fake CISP in `internal/ltest` (an HTTP server
  implementing exactly `02 F1`/`F3` plus the heartbeat endpoint):
  publish, acknowledge, conflict; heartbeat every 15 s observed and the
  fake marking stale after a 60 s silence (E-01); webhook delivery,
  then webhook suppressed and the 60 s pull observed; CISP down for the
  whole test → previous version served with `cis_age_s` rising,
  publication `pending` with age (E-02).
- E-10: outbox bounded per dataset (one pending snapshot replaces an
  older pending one; the superseded one is recorded as `superseded`).

## Done when

- [ ] `make lint race integration` clean; outputs in the PR.
- [ ] A-M1: a zone authored in WP-5 is published to the fake CISP,
  acknowledged, and a change pushed by the fake CISP lands in
  `cis_cache` and `proj_restrictions`.
- [ ] `api/clients/cisp.yaml` and `api/clients/cisp-schemas/` with
  `SOURCE` recording the uspace-cisp commit; a CI step diffs them
  against that commit; WP-5's and WP-16's outputs validate against the
  schemas in CI.
- [ ] `docs/runbooks/cisp-publication.md`: states, conflict handling,
  what the console shows.
- [ ] CHANGELOG line; `internal/cisp/doc.go`.

## Commits

`feat(cisp): signed full-dataset publications with an ordered outbox and retry [WP-6 A-M1]`,
`feat(cisp): subscribe to the CIS with signed webhooks and the 60 s reconciliation pull [WP-6 A-M1]`,
`feat(cisp): publisher heartbeat every 15 s with its state on the status line [WP-6 A-M1]`,
`feat(cisp): project dynamic restrictions for the detectors [WP-6 A-M1]`.
