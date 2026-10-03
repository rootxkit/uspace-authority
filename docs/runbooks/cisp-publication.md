# CISP publication and subscription (WP-6)

How the authority publishes its datasets to the CISP (spec 02 F1), keeps
the CIS datasets it reads (F3), and what the console shows about both.
The code is `internal/cisp`; the CISP's contract is the pinned copy
`api/clients/cisp.yaml` with its schemas in `api/clients/cisp-schemas/`
(the commit is in `api/clients/SOURCE`; CI fails when a copy differs
from the CISP's file at that commit).

## Configuration

| Variable | Default | What it does |
|---|---|---|
| `CISP_BASE_URL` | unset | The CISP. https only (http to a loopback host for tests). Unset: nothing is sent or pulled; the console says `cisp_configured: false` and every age grows. |
| `PUBLICATION_KEY_FILE` | unset | The publication key (WP-2, listed in this issuer's JWKS under its own `kid`). Unset: every publication is refused 503 `publication_key_missing`, nothing is queued. |
| `CISP_CLIENT_ID`, `CISP_CLIENT_SECRET_FILE`, `CISP_TOKEN_URL` | `authority-01`, unset, `ISSUER_URL/oauth/token` | The client this system uses at its own token service for the CISP's tokens (audience = the CISP's host, M18). Create it with `POST /v1/oauth/clients` (scopes `cis.read`, `cis.publish:zones`, `cis.publish:uspace`, `cis.publish:ussp_list`; audience the CISP's host). |
| `CIS_CALLBACK_URL` | unset | This system's `POST /v1/cis/notifications` as the CISP must call it. Unset: no subscription; the 60 s reconciliation alone keeps the cache. Its host must be one of `AUTHORITY_AUDIENCES` (the CISP signs `aud` as that host): api refuses to start otherwise. |
| `AUTHORITY_CIS_NOTIFY_ISSUERS` | the CISP and ANSP peers | `<iss>=<jwks_url>`, at most two: the CISP (`CISP_ISSUER_URL`) and the ANSP's direct delivery (`ANSP_ISSUER_URL`, M5). |
| `CIS_ANSP_PUBLISHER_JWKS_URL` | `ANSP_JWKS_URL` | The ANSP's keys, which must have signed every restrictions version this system uses. |
| `CIS_RECONCILE_S` | 60 | The reconciliation of every dataset (at most 60, 02 F3). |
| `CIS_HEARTBEAT_S` | 15 | The publisher heartbeat (M3). |
| `CIS_SEND_BACKOFF_MIN_S`, `CIS_SEND_BACKOFF_MAX_S`, `CIS_SEND_GIVE_UP_S` | 2, 300, 86400 | The sender's retry: doubling from the minimum, capped at 5 min, given up 24 h after the row was queued. |
| `CIS_PUBLISHER_SIG_MAX_AGE_S` | 31622400 (366 d) | How old the publisher signature of a pulled version may be (a signature is as old as its version). |
| `CIS_JTI_MAX_LIVE` | 100000 | Delivery ids remembered by the receiver (E-10). |

`cis_stale_bound_s` is a policy column (`/v1/policy`, default 300 s).

## Publication states

`POST /v1/zones/publish` and `POST /v1/uspace/publish` (and WP-16's
`POST /v1/certificates/publish-list`) export the whole dataset, hold it
to what the CISP accepts, sign it and write it to the outbox in the
same transaction as the publication. A payload the CISP would refuse is
refused there, 400 `publication_refused`, with every problem by JSON
path; nothing is published, signed or queued.

| State | Meaning | What happens next |
|---|---|---|
| `pending` | Queued, or waiting for its retry (`next_retry_at`, `last_status`, `last_error`). | The sender sends it when due. A newer publication of the dataset supersedes it. |
| `sent` | A PUT is in flight. A row found `sent` after a crash is sent again; the CISP's 412 then shows whether the first attempt landed. | Acknowledged, retried, failed or conflict. |
| `acknowledged` | The CISP answered 2xx (or 412 with this row's bytes current); `cisp_version` is its version. | The next publication is sent against it. |
| `superseded` | A newer snapshot of the dataset was queued before this one was sent (one pending snapshot per dataset). | Nothing. |
| `failed` | The CISP refused it (400, 404, 413, 415, 428: `last_error` names the problems), or 24 h of retries passed. | An operator fixes the cause and publishes again. |
| `conflict` | The CISP holds another version than the one this outbox last saw (412). `conflict_version` is the CISP's version. Nothing was overwritten. | The dataset stops. See below. |

Every change of state is an `events` row (`publication_queued`,
`publication_superseded`, `publication_sent`,
`publication_acknowledged`, `publication_retry_scheduled`,
`publication_failed`, `publication_conflict`) with the publication's id
as `entity_id`.

Each attempt re-signs the exact bytes (the CISP refuses a signature
older than five minutes) and sends `If-Match` with the version last
acknowledged, `"zones:0"` before the first.

## Conflict handling

A conflict means someone else's version is current at the CISP for a
dataset the authority owns: an operator at the CISP republished, the
authority's database was restored from a backup, or a second authority
deployment points at the same CISP.

1. Read the CISP's current version: `GET /v1/publications?state=conflict`
   shows `conflict_version`; the CISP's console or
   `GET /v1/{dataset}/versions/{conflict_version}` shows its content and
   publisher.
2. If the authority's data is right, publish again
   (`POST /v1/zones/publish` after approving what is needed). The new
   row is sent against `conflict_version`, so it replaces the CISP's
   version on purpose; the decision is the publication's `events` row.
3. If the CISP's version is right, bring the authority's zones in line
   (import or author the changes), then publish.

The sender never sends the conflict row again, and nothing queued
automatically after it is sent either: a USSP list queued by a
certificate change or by the list repair waits `pending` behind the
conflict (its `age_s` rises on the status line) until an operator
publishes (`POST /v1/zones/publish`, `POST /v1/uspace/publish`
or `POST /v1/certificates/publish-list`). Only an operator's
publication is sent against `conflict_version` (the row's
`resolves_conflict`, also in its `publication_queued` event); a newer
automatic snapshot that supersedes it before it is sent carries the
decision on.

## What the console shows

`GET /v1/publications` (admin, inspector, viewer):

- `publications`: the outbox rows, newest first, with `state`,
  `attempts`, `last_status`, `last_error`, `cisp_version`,
  `conflict_version`, and `age_s` while pending or sent: how long the
  dataset has not been published (02 F1 failure rule).
- `cache`: per dataset (`zones`, `uspace_airspace`, `ussp_list`,
  `restrictions`) the version held (`cis_version`), `cis_age_s` (since
  the CISP last confirmed it) and `stale` (beyond `cis_stale_bound_s`, or
  nothing ever read: the console shows `cis_stale`; the authority
  refuses nothing on it); `held_version` and `held_reason` when a newer
  version was not used because its publisher's signature did not verify;
  `refused_version` and `refused_reason` when a newer version failed
  `ed318.Parse` or the pinned schema (the previous version stays); the
  last pull error.
- `heartbeat`: the last success, the CISP's last status and the
  consecutive failures. The CISP marks the authority stale after 60 s of
  silence.
- `subscription`: the callback, the CISP's subscription id and status.

The status line carries the same: `cisp_configured`,
`cis_<dataset>_version`, `cis_<dataset>_age_s`, `cis_stale` (the stale
datasets), `publication_<dataset>_pending_age_s`,
`cis_heartbeat_failures`, `cis_heartbeat_age_s`, and what keys are
missing. Counters (`/metrics`, component `cisp`) count every refusal,
retry, conflict, held or refused version and webhook outcome.

## Subscription and pulls

- On start the subscriber registers `CIS_CALLBACK_URL` for the four
  datasets (idempotent: an existing subscription with the same callback
  is reused or patched) and reads every dataset. The subscription is
  asked for again every five reconciliations: one the CISP lost (a
  restore, a delete) is made again, and the console shows the status
  the CISP answered last (`cis_subscription_rechecks`,
  `cis_subscription_changed`).
- A notification is a hint: it is verified (compact JWS from an allowed
  issuer, `aud` one of `AUTHORITY_AUDIENCES`, `iat` within five
  minutes, `jti` single-use) and, for `publication` and the
  `restriction_*` reasons, starts a pull. `subscription_test`,
  `republished` and reasons unknown here are acknowledged without one.
  A `pull_url` is followed only when it is https on the CISP's
  configured host and port.
- Every 60 s each dataset is reconciled: HEAD with the held ETag, and on
  a change the delta from the version held.
- A version is used only when its publisher signed it: the authority for
  zones, uspace_airspace and ussp_list, the ANSP for restrictions. A
  version the CISP made itself (a restriction expiring) carries no
  publisher signature and is held until the publisher's next signed
  version; the restriction's own window still ends it for the
  detectors.
- What is installed must be what was signed, not only signed: the
  served collection (or the one merged from a delta) is compared,
  feature by feature without the CISP's `cis_*` members, with the
  version as published. For zones, uspace_airspace and ussp_list the two
  must be equal; for restrictions the ANSP's request's feature must be
  served as signed. Any difference holds the version
  (`cis_signed_content_mismatch`, `held_reason` names the feature).
- Restrictions are written whole to `proj_restrictions` (with the
  version in `proj_restrictions_state`; version 0 with no rows when the
  CISP holds none yet) and announced on `cis.v1.restrictions`.

## Spec gaps

- The CISP builds the restrictions collection it serves; the ANSP's
  signature covers one request, so only that request's feature is tied
  to it, the version's other restrictions to the requests that made
  them. The CISP's own `X-CIS-Signature` is not verified (shared with
  the USSPs).
- Reads are unfiltered (`?at=` is not used): the provenance check needs
  the version as published, and the detectors judge each restriction's
  window.
- A version signed with an earlier publication key of the authority is
  held until the next publication: the verifier has the key configured
  now.
