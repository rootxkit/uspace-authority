# The police realm

Lawful queries from police and other agencies about an aircraft, an
operator or a flight, with audit (spec 01 A9, 02 F10, 06 §2 T6, 06 §5;
`docs/PLAN.md` §7 and Q-A14; WP-19). `api` serves them under
`/v1/police/*`; the data protection officer's report is
`GET /v1/audit/dpo-report`. The realm reads; it never alerts anyone,
never changes the registry and never acts on an aircraft.

**The legal basis and the access levels are not decided here.** Which
agencies, which purposes, and which of them may see an operator's
identity are the authority's determination under Art. 18(b)-(c) of
2021/664 and the Law of Georgia on Personal Data Protection (spec Q8,
owner-only). This build ships a demo default (below); the owner and the
DPO replace it through configuration, and a DPIA precedes go-live (06
§5).

## Onboarding an agency

1. Agree the agency's name (the `agency` of its accounts, 1 to 100 of
   letters, digits, space `. _ -`, e.g. `TEST-POLICE`), the addresses its
   officers connect from, and who at the agency answers for the
   accounts.
2. An admin creates one account per officer, never a shared one:

   ```
   POST /v1/users
   {"username": "officer.one", "password": "<initial>", "realm": "police",
    "roles": ["police.query"], "agency": "TEST-POLICE",
    "ip_allowlist": ["192.0.2.0/24"]}
   ```

   A police account holds `police.query` and nothing else; a console
   role is refused on it, and `police.query` is refused on a console
   account (the database repeats both rules, migration `00021_police`).
   `ip_allowlist` takes CIDRs or single addresses (at most 32) and is
   required: an empty list admits no address.
3. The officer signs in like any account (password, then TOTP, enrolled
   at the first sign-in; WP-2). A sign-in from an address outside the
   list is refused with the answer of a wrong password and recorded as
   `login_refused` / `mfa_refused` with reason `address_not_allowed`.
   The address is the client's as the trusted proxies report it
   (`AUTHORITY_TRUSTED_PROXIES`); without that variable behind Caddy
   every request carries Caddy's address and the list cannot work.
4. Changing an agency's addresses: `PUT /v1/users/{id}/police-access
   {"agency", "ip_allowlist"}` (admin). It ends the account's sessions
   and is one `user_police_access_changed` row with the before and the
   after. Every police query checks the address against the account's
   row as it is at that moment, so a narrowed list applies to an open
   session at once (403 `address_not_allowed`, recorded as
   `police_query_refused`).
5. Offboarding: `POST /v1/users/{id}/disable` ends the sessions; the
   record of the account's queries stays.

A police session is refused on every console operation, and a console
session (an admin's included) on every police operation; a machine
token is refused on both, whatever its scopes. The picture WebSocket
(`picture-ws`) admits a police session read-only and leaves out the
remote pilot position for it (WP-13); its address is checked at sign-in.

## The purpose list

Every query names `purpose`, one of `POLICE_PURPOSES`, and `case_ref`,
the agency's own case reference (free text, 1 to 100 characters).
Without either, or with a purpose off the list, the request is 400
naming the field and nothing is read or recorded. `POLICE_PII_PURPOSES`
names the purposes that release the operator's identity and allow a
legal export.

| Variable | Demo default |
|---|---|
| `POLICE_PURPOSES` | `public_order,traffic_enforcement,criminal_investigation,security_threat` |
| `POLICE_PII_PURPOSES` | `criminal_investigation,security_threat` |

A purpose is a lower-case code (`[a-z][a-z0-9_]{0,63}`); a list with a
malformed or repeated code, or a personal-data purpose that is not in
`POLICE_PURPOSES`, stops `api` at start naming the variable. The start
line `police realm ready` prints both lists.

## What is answered at each level

| Query | Status-only purpose | Personal-data purpose |
|---|---|---|
| `GET /v1/police/aircraft?bbox=&purpose=&case_ref=` (now) or `&at=` (then) | per aircraft: track, serial, registration number's public part as identified, identification status and reason, trust, source, first and last seen, positions in the box (the newest `POLICE_MAX_POSITIONS`), emergency | the same, plus the operator's identity (`operator`) or why there is none (`operator_unresolved`: `not_identified`, `not_in_registry`, `ambiguous_registration`, `registry_unavailable`) |
| `GET /v1/police/operators/{reg}` | registration status, operator type, validity, fleet (serial, status, class, manufacturer, model, mark; at most `POLICE_MAX_FLEET`) | the same, plus `identity` |
| `GET /v1/police/serials/{serial}` | the aircraft's status and its operator's registration | the same, plus `identity` |
| `POST /v1/police/exports` | refused (403 `purpose_not_pii`) | a `legal` evidence pack (below) |
| `GET /v1/police/exports/{pack}/download` | refused | the archive, to the exporting agency only |

The identity is the operator's name or legal name, postal address,
e-mail and phone (G-10: what reaches the person). The date of birth,
the identification number and the insurance policy are never answered
here. The remote pilot position is never answered. Occurrence reports
and their reporters are never reachable from this realm (376/2014 Art.
15(2), 16): `internal/police` does not import `internal/occurrences`,
names no occurrences table, and works as `authority_app`, which has no
grant on the `occurrences` schema (`TestIntegrationThePoliceRealmCannotReachOccurrences`).

**Now and then.** Without `at` the answer is the tracks last seen
within `POLICE_LIVE_WINDOW_S` (30 s) of the telemetry database's clock;
with `at`, the tracks seen within `POLICE_AT_WINDOW_S` (60 s) either side
of it, no older than `POLICE_HISTORY_MAX_AGE_S` (90 days, the online
retention). A box has sides of at most `POLICE_MAX_BBOX_DEG` (1°); at
most `POLICE_MAX_AIRCRAFT` aircraft are answered (`truncated: true`
beyond: narrow the box). `sources` says how old the newest sample of the
picture is and which writer gaps were recorded in the window;
`degraded: true` means an empty answer is not an empty sky.

**Exports.** `{"incident_id": ...}` builds a legal pack of an incident
of the authority over [`from`, `to`). `{"query": {"bbox": ...}}` first
opens an incident `opened_from: police_request` (kind `other`, the
notice reference `<agency>: <case_ref>`) holding the aircraft the
picture had in the box over the window (at most 32; more is 413
`too_many_aircraft`, none is 422 `nothing_to_export`), then builds its
legal pack. The pack is WP-17's: hash-sealed, the seal statement signed
by the publication key, sealed at rest, every personal-data read of
the build a `registry_pii_viewed` row. `police_exports` links it to the
agency; another agency's download is 404 and a `police_query_refused`
row (`not_this_agency`).

## The record

Every answered query, export and download is one `police_queries` row
and one `police_query` events row, written in one transaction before
any personal data is opened:

| Column | What |
|---|---|
| `id`, `at` | the query and the database's clock |
| `user_id`, `agency`, `session_jti`, `remote_ip` | who, and from where |
| `kind` | `aircraft`, `operator`, `serial`, `export`, `download` |
| `purpose`, `case_ref` | why |
| `query` | what was asked (a registration number's public part only) |
| `result_count` | how many results (0 for an unknown number: the 404 is recorded) |
| `pii` | whether the purpose released personal data and there was some to release |

The table is append-only (no grant, and a trigger refuses UPDATE and
DELETE for every role). Every personal-data read made for a query (the
registry's `registry_pii_viewed`, the pack's `evidence_pack_built` and
`evidence_pack_downloaded`) carries `police_query_id`, `case_ref` and
`agency` in its payload.

**Budgets.** `POLICE_USER_QUERIES` per account and `POLICE_AGENCY_QUERIES`
per agency per `POLICE_RATE_WINDOW_S` (30, 300, 60 s). They count the
`police_queries` rows of the window on the database clock under the
agency's advisory lock, so every api replica shares them and a restart
keeps them. Past one: 429 with `Retry-After` (when the oldest row leaves
the window) and a `police_query_refused` row (`budget_spent_user`,
`budget_spent_agency`). A refused query is not a `police_queries` row.

Counters on the status line and `/metrics` (`police` group):
`police_queries`, `police_queries_refused_budget`,
`police_queries_refused_address`, `police_downloads_refused_agency`,
`police_pii_released`, `police_pii_unresolved`, `police_exports`,
`police_export_not_linked` (a pack built whose agency link failed: its
download is refused until an admin links it; investigate at once),
`police_downloads`, `police_refusal_event_failed`, `dpo_reports`.

## The DPO report

`GET /v1/audit/dpo-report?month=YYYY-MM` (admin, auditor), a UTC
calendar month:

- `police_queries`: every row of the month (the columns above);
- `pii_views`: every events row of the month whose type the audit
  catalogue tags as a personal-data read, `police_query` aside (it is
  the first list): `registry_pii_viewed`, `rid_frames_viewed`,
  `evidence_pack_built`, `evidence_pack_downloaded`,
  `occurrence_reporter_viewed`, `occurrence_reporter_unopened`; with the
  actor, the realm, the purpose, the entity and, for a police read, the
  case reference, the agency and the police query;
- `totals`, and `truncated: true` past `DPO_REPORT_MAX_ROWS` per list
  (read the month in the audit log, `GET /v1/audit/events`, then).

Reading the report is itself a `dpo_report_viewed` row. The DPO reviews
it monthly: queries without a plausible case, an account querying
outside its agency's pattern, personal-data purposes used where a
status-only one would do, and `police_query_refused` rows (addresses
off the list, spent budgets).
