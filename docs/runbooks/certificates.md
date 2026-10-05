# Certificates, the public register and operating status (WP-16)

The authority certifies USSPs and the single CISP (Reg. 2021/664 Art.
14-15, Annex VI-VII), keeps the public register of certified providers
(Art. 18(a)), records the providers' start, cease and restart of
operations (Art. 7(6)) and lapses a certificate not used or idle beyond
the Art. 16(2) periods. Everything below is `admin` unless it says
otherwise; every step is an `events` row with the actor and the reason.

## Status

A certificate's status is derived from four facts that change
independently, so lifting one never clears another:

| Fact | Set by |
|---|---|
| operations: `not_started`, `operating`, `ceased` | the holder's notices |
| limited (with `limitations`) | `POST .../limit`, lifted by `POST .../reinstate` |
| suspended | `POST .../suspend`, lifted by `POST .../reinstate` |
| ended: `revoked` or `lapsed` | `POST .../revoke`, the lapse job; final |

`status` = ended, else `suspended`, else `ceased`, else `limited`, else
`operating`, else `issued`. A reinstatement lifts a suspension first (a
limitation held stays), and only then a limitation.

## Onboarding a USSP

1. **Certificate.** `POST /v1/certificates` with `holder: ussp`, the
   holder's name, registered address and published contact (the
   organisation's, never a person: the CIS USSP list carries it), the
   `code` (one to eight upper-case letters and digits, e.g. `AB12`;
   unique and never changed or reused: it is the `ussp_id` of the CIS
   USSP list, the USSP's `USSP_SYSTEM_ID`, the USSP code of its
   authorisation numbers and the `<code>` of its client id), the
   national API `base_url` (https), the `services` (Annex VI:
   `network_identification`, `geo_awareness`, `flight_authorisation`,
   `traffic_information`, `weather`, `conformance_monitoring`), the
   conditions and limitations, the `terms_url` (Art. 5(3)), `valid_until`
   and the client's `auth_method`. The certificate is `issued`; the
   active policy's lapse periods are copied onto it.
2. **Client.** The same transaction registers `ussp-<code>-01` in the
   token service with the scopes the services imply (least privilege):
   every USSP gets `registry.validate`, `occurrences.write`,
   `certificates.status`, `rid.service_provider`, `cis.read`,
   `ansp.traffic` (the ANSP's manned traffic, F4) and
   `ansp.coordination` (Annex V notices to the ANSP, F13; cross-plan
   Appendix B);
   `network_identification` and `traffic_information` add
   `rid.display_provider`, `geo_awareness` adds
   `utm.constraint_processing`, `flight_authorisation`
   `utm.strategic_coordination`, `conformance_monitoring`
   `utm.conformance_monitoring_sa`. Its audiences are this system's
   host, the CISP's (`CISP_BASE_URL`) and the ANSP's (`ANSP_BASE_URL`);
   a peer unset at issue is left out, said at start, and its national
   tokens are refused until the client is patched. A `client_secret_post` secret is in the answer
   **once**: hand it to the USSP out of band (never by e-mail in clear)
   and do not keep a copy. For `private_key_jwt`, register the USSP's
   public JWKS in the request instead.
3. **Conformance report.** The USSP runs the conformance suite (`00
   §7`) against the lab with that client and sends the report; file it
   with the certificate (outside this system).
4. **Start of operations.** The USSP posts `POST
   /v1/certificates/{id}/status {state: started, at, reference}` with a
   token of its own client (`certificates.status`; any other client is
   403). The certificate becomes `operating` and the USSP list is queued
   with it; dp-poller sees it as certified. A notice received by letter
   is entered with `POST /v1/certificates/{id}/status-notices` (the
   letter's reference required).
5. **The list.** The USSP list (`cis/ussp_list/v1`) is queued, signed,
   in the F1 outbox on every change that touches it; `GET
   /v1/publications` shows it pending, sent, acknowledged.
   `POST /v1/certificates/publish-list` queues it at once.

The CISP is certified the same way with `holder: cisp`, `services:
[common_information]`; its client is `cisp-01` with
`certificates.status` only (its own operating-status notices). If
`cisp-01` was registered by hand before, issuing is refused with 409;
revoke or rename that client first.

## Suspension

`POST /v1/certificates/{id}/suspend {reason}`:

- the client is suspended in the same transaction: its **next token
  request is refused** (`invalid_client`). A token issued before stays
  valid to its `exp`; the answer's `tokens_valid_until` (now plus the
  token TTL, 1 h by default) says until when, and peers that verify our
  tokens cannot be told sooner;
- the USSP list is queued without the holder (06 §2 T9); the KV register
  dp-poller follows drops it, so its Service Provider is shown
  `provider_unknown` (still polled and shown, nothing hidden);
- a `ceased` notice is still recorded while suspended; `started` and
  `restarted` are refused.

`POST .../reinstate {reason}` reactivates the client and lists the USSP
again. `POST .../revoke {reason}` is final: the client is revoked.

## The lapse rules (Art. 16(2))

A daily job (`CERTIFICATES_LAPSE_EVERY_S`, one replica at a time under an
advisory lock, on the database clock, idempotent) lapses:

| Rule | When |
|---|---|
| `lapse_unused` | operations never started within `lapse_unused_after_months` of the issue (default 6) |
| `lapse_ceased` | operations ceased `lapse_ceased_after_months` ago (default 12) |

The periods are the policy's `certificate_lapse_unused_months` and
`certificate_lapse_ceased_months` (INV-03), copied onto a certificate
when it is issued: a later policy does not move the lapse of a
certificate already issued. A certificate's `lapses_at` says when the job
will lapse it. Lapsed is final; the client is revoked. A suspension does
not stop the clock.

## The public register

`GET /v1/certificates/register` (no sign-in): every certificate not
ended, and one ended for a year after: holder kind and name, code,
services, status, validity, limitations. No address, contact,
conditions or client id. Cacheable for 60 s; per client address
`CERTIFICATES_REGISTER_PER_MIN` (60) with burst
`CERTIFICATES_REGISTER_BURST` (20), then 429 with `Retry-After`.

## When the list is not published

A change that cannot queue the list (no `PUBLICATION_KEY_FILE`, a list
the CISP's schema refuses) answers `list_publication: {state: pending,
reason}` and keeps `certificate_list_state.wanted` above `enqueued`. The
repair (`CERTIFICATES_REPAIR_S`, 60 s) queues it as soon as it can, on
any replica, and also when a listed certificate passes its
`valid_until`. Counters: `ussp_list_queued`, `ussp_list_pending`,
`ussp_list_repaired`, `ussp_list_repair_failed`.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CERTIFICATES_LAPSE_EVERY_S` | 86400 | period of the lapse job |
| `CERTIFICATES_REPAIR_S` | 60 | period of the list repair and the KV republish |
| `CERTIFICATES_BUCKET` | `certificates` | KV bucket of the certified USSPs (same variable on dp-poller) |
| `CERTIFICATES_REGISTER_PER_MIN`, `_BURST`, `_MAX_IPS` | 60, 20, 10000 | the public register's rate limit |

Counters (`/metrics`, status line `certificates`):
`certificates_issued`, `certificates_issue_refused`,
`certificates_updated`, `certificate_transitions`,
`certificate_transitions_refused`, `certificate_notices_recorded`,
`certificate_notices_replayed`, `certificate_notices_refused`,
`certificate_notices_wrong_client`, `certificates_lapsed_unused`,
`certificates_lapsed_ceased`, `certificate_lapse_runs`,
`certificate_lapse_skipped_locked`, `certificate_lapse_failed`, the list
counters above, `certificates_kv_published`,
`certificates_kv_publish_failed`, `certificates_kv_bucket_ahead`,
`certificate_register_served`, `certificate_register_rate_limited`.

## Known gaps

- The lab's USSP code is `USSP-DEV` (uspace-ussp `USSP_SYSTEM_ID`), which
  is not upper-case alphanumeric and cannot be a code here (M8 and the
  client-id pattern of M24). A spec gap, written in the WP-16 pull
  request.
- Clients issued before the ANSP scopes and audience (audit H-3) lack
  `ansp.traffic`, `ansp.coordination` and the ANSP's host. Nothing
  rewrites a registered client: give each one the scopes and audience
  with `PATCH /v1/oauth/clients/{client_id}` (audited), or the USSP's manned
  picture and Annex V notices are refused at `/oauth/token`.
