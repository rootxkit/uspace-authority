# The registry's public portal

The public check of a registration number, the operator registration
applications of the portal, and an operator's occurrence report through
an e-mailed link (WP-20; spec 01 §1 operators, 06 §5; `docs/PLAN.md`
Q-A10, Q-A11, Q-A17). `api` serves them; WP-23 builds the public pages
that call them.

**Pending GCAA.** Whether the authority is the registry of record and
takes applications (spec Q4, Q-A11), whether operators get accounts
(Q-A17: here they do not; an e-mail link is their credential), the
registration-number format (Q5, Q-A10), the retention of applications
and every budget below are open. This build ships the spec's defaults,
off unless switched on; none of them is a policy answer.

## The public check

`GET /v1/registry/check?number=<number>`, unauthenticated, answers
`{"status": "valid" | "suspended" | "revoked" | "unknown", "valid_until"}`
and nothing else (no name, type or id; a contract test fails if the
response schema grows one). The number is compared on its public part
ignoring case; a secret part sent with it is removed and never echoed.
An expired registration answers `revoked` with its `valid_until`. Each
client address (behind `AUTHORITY_TRUSTED_PROXIES`) has
`REGISTRY_CHECK_PER_MIN` requests a minute with a burst of
`REGISTRY_CHECK_BURST`; past it 429 with `Retry-After`. The limiter
remembers `REGISTRY_CHECK_MAX_IPS` addresses (E-10). The check is always
on.

## Applications (`REGISTRY_APPLICATIONS=on`)

Off by default: every application operation is 404. On, it needs
`REGISTRY_PORTAL_KEY_FILE`, `REGISTRY_PORTAL_URL` and the mail settings,
or `api` does not start.

1. **Submit** `POST /v1/registry/applications` with the Art. 14(2)
   fields of a registration (no number, no validity) and `lang` (`en`
   or `ka`). The application is checked whole by the registry's own
   rules before anything is stored (400 naming every field); the client
   address's budget (`REGISTRY_APPLICATIONS_PER_IP` per
   `REGISTRY_APPLICATIONS_WINDOW_S`, counted in the database across
   replicas and restarts, 429 past it) is spent; the content is sealed
   (AES-256-GCM, the PII key); the verification e-mail is queued. 202,
   `unverified`.
2. **Verify** by the e-mailed link within
   `REGISTRY_APPLICATION_VERIFY_TTL_S`: the page posts
   `POST /v1/registry/applications/{id}/verify` with the link's token in
   `X-Application-Token`; the application becomes `submitted`. An
   expired link is 409 `link_expired` (apply again); a token that does
   not verify, or of another application, is 404. The same link shows
   the state later (`GET /v1/registry/applications/{id}`), never the
   content.
3. **Review** (registrars): `GET /v1/registry/applications?state=submitted`
   lists without personal data; `GET .../{id}/personal-data?purpose=`
   opens the content and records `registry_application_pii_viewed` with
   the purpose first; `POST .../{id}/review` takes it (`under_review`).
4. **Approve** `POST .../{id}/approve {"valid_until"?}`: the portal
   issues the number (`REGISTRY_ISSUE_PREFIX` followed by
   `REGISTRY_ISSUE_RANDOM_LEN` random lower-case letters and digits,
   `GEO` + 12 by default, the EU AMC shape without its unverified
   checksum character; it must match the policy's
   `registration_number_pattern`, else 409 `issuance_pattern_mismatch`)
   and a three-character secret part, registers the operator through
   the registry (`source = portal`, valid until `valid_until` or
   `REGISTRY_APPLICATION_VALIDITY_S` from now) and queues the approval
   e-mail. **The secret part is shown once, in that e-mail**: it is in no
   response and, once the approval commits, exists only as the
   registry's keyed hash. A number is never issued twice (the registry's
   unique compare key, drawn again on a collision). A retried approval
   finds the operator it registered instead of registering it twice,
   and approves what the first attempt chose: a retry with another
   `valid_until` is 409 (retry with the same one, or none, or refuse).
   **Refuse** `POST .../{id}/refuse {"reason"}`: the reason is mailed.
5. **Purge**: every `REGISTRY_PORTAL_PURGE_EVERY_S` the job deletes
   decided applications `REGISTRY_APPLICATIONS_RETAIN_S` after the
   decision and unverified ones a link lifetime after their link
   expired, in one `registry_applications_purged` events row. The
   registered operator stays in the registry.

## Operator reports (`REGISTRY_OPERATOR_REPORTS=on`)

An operator reports an occurrence (2019/947 Art. 19(2), 376/2014) without
an account:

1. `POST /v1/registry/operator-links {"registration_number", "lang"}`
   answers 202 whatever the number. Only for a registration in good
   standing is a single-use link mailed, to the e-mail address the
   registry holds for it, valid `REGISTRY_OPERATOR_LINK_TTL_S`. Budgets:
   `REGISTRY_OPERATOR_LINKS_PER_IP` per address (429 past it) and
   `REGISTRY_OPERATOR_LINKS_PER_OPERATOR` per operator (beyond it the
   request is answered 202 and mails nothing).
2. The page posts the report, `occurrence/v1` as for
   `POST /v1/occurrences`, to `POST /v1/occurrences/operator` with the
   link's token in `X-Operator-Token`. The body is checked first; then
   the link is spent once (`registry_portal_links_used`, database
   clock); then WP-18's intake stores the report as
   `operator:<public part>` on the mandatory channel. A link used again
   or expired is 401 `link_spent`. If the intake fails after the spend
   (the occurrence key missing, say), the operator asks for a new link.

## Mail

Every e-mail is written to the outbox (`registry_portal_mail`) in the
transaction of the change it reports and sent after the commit, every
`REGISTRY_MAIL_EVERY_S`, at most `REGISTRY_MAIL_BATCH` a run, at least
once. Messages are sent one at a time and no transaction is open while
the relay is talked to: a message is claimed and leased for twice
`REGISTRY_MAIL_TIMEOUT_S` (another replica skips it meanwhile; after a
crash it is sent again when the lease ends), and each outcome commits
on its own. Its content (recipient, link, number, secret part) is sealed until
it is delivered or given up, then cleared. A failed delivery is retried
after `REGISTRY_MAIL_RETRY_S`, doubling up to an hour, at most
`REGISTRY_MAIL_MAX_ATTEMPTS` times; a permanent refusal (SMTP 5xx) is
given up at once. Every delivery and give-up is an events row
(`registry_portal_mail_sent`, `registry_portal_mail_failed`). Texts are
the `en` and `ka` catalogues (`internal/regportal/catalogue`); links
open `REGISTRY_PORTAL_URL` pages with the token in the URL fragment,
which never reaches a server log.

`REGISTRY_MAIL_TLS=starttls` (default) refuses a relay that does not
offer STARTTLS; `tls` is implicit TLS; `none` is allowed only to a
loopback relay and never with a password.

## Keys

`REGISTRY_PORTAL_KEY_FILE` (one line of base64, `openssl rand -base64
32`) signs the links (HMAC-SHA-256) and keys the hashes of client
addresses in the budgets. It must differ from `PII_KEY_FILE` and
`REGISTRY_HASH_KEY_FILE` (`api` refuses to start otherwise). Rotating it
invalidates every link in flight: applicants verify again from a new
application, operators ask for a new link.

## Configuration

| Variable | Default (pending GCAA) |
|---|---|
| `REGISTRY_CHECK_PER_MIN` / `_BURST` / `_MAX_IPS` | `30` / `10` / `10000` |
| `REGISTRY_APPLICATIONS` | `off` |
| `REGISTRY_OPERATOR_REPORTS` | `off` |
| `REGISTRY_PORTAL_KEY_FILE`, `REGISTRY_PORTAL_URL` | unset (required when a flag is on) |
| `REGISTRY_APPLICATION_VERIFY_TTL_S` | `86400` (24 h) |
| `REGISTRY_APPLICATIONS_RETAIN_S` | `7776000` (90 days) |
| `REGISTRY_APPLICATION_VALIDITY_S` | `157680000` (5 years) |
| `REGISTRY_APPLICATIONS_PER_IP` / `REGISTRY_APPLICATIONS_WINDOW_S` | `5` / `3600` |
| `REGISTRY_ISSUE_PREFIX` / `REGISTRY_ISSUE_RANDOM_LEN` | `GEO` / `12` |
| `REGISTRY_OPERATOR_LINK_TTL_S` | `86400` |
| `REGISTRY_OPERATOR_LINKS_PER_IP` / `_PER_OPERATOR` | `10` / `5` |
| `REGISTRY_MAIL_SMTP_ADDR`, `REGISTRY_MAIL_FROM` | unset (required when a flag is on) |
| `REGISTRY_MAIL_TLS` | `starttls` |
| `REGISTRY_MAIL_USER`, `REGISTRY_MAIL_PASSWORD_FILE` | unset |
| `REGISTRY_MAIL_EVERY_S` / `_BATCH` / `_MAX_ATTEMPTS` / `_RETRY_S` / `_TIMEOUT_S` | `10` / `20` / `8` / `60` / `30` |
| `REGISTRY_PORTAL_PURGE_EVERY_S` | `3600` |

Counters: `registry_public_checked`, `registry_check_rate_limited`,
`registry_portal_off`, `registry_portal_budget_spent`,
`registry_portal_token_refused`, `registry_applications_submitted`,
`_verified`, `_link_expired`, `_approved`, `_refused`, `_purged`,
`registry_issue_number_taken`, `registry_portal_mail_sent`, `_retried`,
`_failed`, `registry_operator_links_mailed`,
`registry_operator_links_not_mailed`,
`registry_operator_link_spent_refused`, `registry_operator_reports`.
