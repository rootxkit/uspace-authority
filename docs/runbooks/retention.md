# Retention, archive and record verification

How long this system keeps what, how the telemetry goes to the archive
before it leaves the database, how a record is held past its period,
and what the verification jobs say when the records no longer match
what was sealed (spec 05 §4, 06 §2 T7, 06 §5, 02 F7, 08 Q8; plan
Q-A15, Q-A18; WP-27). Everything here runs inside `api`; nothing here
acts on an aircraft.

## The periods (pending GCAA)

GCAA and the DPO have not answered spec Q8. The periods are the spec's
defaults, in configuration, and every place that shows them says
`pending_gcaa: true` (the status line, `GET /v1/retention/status`, each
archive manifest and each deletion's events row).

| Data | Where | Period | Variable (default) | Then |
|---|---|---|---|---|
| Telemetry: `rid_observations`, `tracks`, `manned_tracks` | TimescaleDB, 1-day chunks | online | `RETENTION_ONLINE_DAYS` (90) | each chunk archived, verified, then dropped |
| The same, archived | archive store | from the data's day | `RETENTION_ARCHIVE_YEARS` (2) | object and manifest deleted |
| USSP daily records bundles | archive store | from the bundle's day | `RETENTION_ARCHIVE_YEARS` (2) | deleted |
| Violations (the authority's alerts) | `violations` | after it closed | `RETENTION_VIOLATIONS_YEARS` (5) | deleted in batches |
| Intents | none here | | | WP-26 caches peer intents for 24 h; this system stores none |
| Incidents, evidence packs | `incidents`, `evidence_packs`, `EVIDENCE_DIR` | indefinite | `RETENTION_INCIDENTS` (`indefinite`, the only value) | never deleted |
| Audit log `events` | monthly partitions | after the month ended | `RETENTION_AUDIT_YEARS` (10) | the oldest month dropped whole, its anchor kept |
| DP cache `ussp_flights` | TimescaleDB | 24 h | (F3411, not configurable) | WP-14's policy; never archived |

The database enforces a floor whatever the configuration says:
`authority_retention_delete_violations` and
`authority_archive_drop_chunk` refuse anything inside 30 days
(2021/664 Art. 15(1)(g)), `authority_retention_drop_events_month`
anything inside a year. `RETENTION_ONLINE_DAYS` below 30 is refused at
start.

## The jobs

All are due on the database clock (`job_runs`), each under its own
session advisory lock, so several `api` replicas never run one twice and
a restart neither skips a due run nor repeats a finished one. Every run
is a `job_runs` row with its start, end, outcome and a summary in
numbers; `GET /v1/retention/status` shows each job's newest run.
`RETENTION_TICK_S` is how often `api` looks for a due job;
`RETENTION_RETRY_S` how long a failed or interrupted run waits.

| Job | When | What |
|---|---|---|
| `retention` | every `RETENTION_EVERY_S` (daily) | archive and drop the telemetry beyond the online window; delete the archived objects past their period; delete the expired violations; drop the expired months of the audit log |
| `audit_verify` | monthly | verify every month of the hash chain, each recorded as `audit_chain_verified` |
| `evidence_verify` | monthly | recompute every evidence pack's hash against storage and check its seal |
| `ussp_records` | every `RETENTION_EVERY_S` (daily) | pull every operating USSP's daily records bundle |

Each step of `retention` runs even when one before it failed (an
unreachable archive store does not stop the deletion of violations);
the run is `failed` when any step was, and its summary says which.

## How the telemetry is archived

For each of the three tables, oldest first and at most
`RETENTION_CHUNKS_PER_RUN` chunks per run, a chunk whose range ended
`RETENTION_ONLINE_DAYS` ago:

1. is recorded in `archive_chunks` (telemetry database) as `exporting`;
2. is exported in one `COPY` statement (no transaction held open by
   `api`, bounded by `RETENTION_EXPORT_TIMEOUT_S`) to the archive store as
   gzip-compressed newline-delimited JSON, one row per line as `to_jsonb`
   renders it. Parquet would need a dependency this repository does not
   carry; the format is recorded in each manifest;
3. is read back: the object's size, SHA-256 and row count must be what
   was written;
4. gets a manifest beside it (rows, bytes, hash, the aircraft it holds,
   what was redacted and why, the periods);
5. is recorded `archived` with an `archive_chunk_archived` events row;
6. is dropped, unless it is held (below), through
   `authority_archive_drop_chunk`, which refuses unless the ledger says
   `archived` with exactly the rows the chunk still holds; the drop is an
   `archive_chunk_dropped` events row.

A failure at any step leaves the chunk online, is named in the run's
summary (`failed`, by chunk) and logged at error level, and the next
run starts the export again. A row written into an old chunk after its
export (a late backlog) makes the drop refuse; the chunk goes back to
`exporting` and is exported whole by the next run.

Without `ARCHIVE_URL` nothing is archived and nothing is dropped; every
run fails saying so (`retention_archive_unconfigured`).

### The remote pilot position (06 §5)

In the archived copy of `rid_observations`, every ODID System message
(alone or in a message pack) has its operator position (latitude,
longitude, geodetic altitude) set to the standard's "unknown" through
uspace-core's codec; every other byte of the frame is as received, and
the row says `"archive_redaction": "operator_position_removed"`. A
frame that cannot be decoded and checked has its payload left out
(`"payload_removed_undecodable"`, an empty payload). `payload_sha256`
always keeps the hash of the frame as received, so a restored frame
whose hash differs from it is a redacted one.

The position is kept for the aircraft of an incident (open or closed)
that occurred within `RETENTION_INCIDENT_MARGIN_S` of the chunk's range,
matched by serial or track id (for a raw frame, core's
`rid.AircraftID` of its serial and `rid.UnidentifiedID` of its
transmitter). The manifest says how many positions were kept and for
which incidents.

### The archive layout

Under the directory of `ARCHIVE_URL` (`file:///<absolute directory>`;
an S3-compatible store is not implemented and is refused at start):

```
telemetry/<table>/<YYYY>/<MM>/<DD>/<range start>_<chunk>.ndjson.gz
telemetry/<table>/<YYYY>/<MM>/<DD>/<range start>_<chunk>.manifest.json
ussp-records/<USSP code>/<YYYY>/<MM>/<YYYY-MM-DD>-<first 16 hex of the hash>.json
```

Objects are written once (a temporary file, synced, linked into place,
read-only), never overwritten. Back the directory up to a second
account (06 §2 T7, WP-24).

### How to restore a chunk

The rows go back into their table with `jsonb_populate_record`, which
ignores the archive's own markers. As the migration owner on the
telemetry database (the hypertables refuse `INSERT` to every other role
but `tsdb-writer`'s):

```
CREATE TEMP TABLE restore (doc jsonb);
\copy restore (doc) FROM PROGRAM 'gzip -dc <object>.ndjson.gz' WITH (FORMAT csv, QUOTE e'\x01', DELIMITER e'\x02')
INSERT INTO tracks SELECT r.* FROM restore, jsonb_populate_record(NULL::tracks, restore.doc) r;
```

(`csv` with quote and delimiter characters that never occur keeps each
line one value, backslashes included.) Check the count against the
manifest's `rows` and the object's SHA-256 against `archive_chunks.sha256`
or the `archive_chunk_archived` events row first. A restored chunk is
beyond the online window: the next `retention` run archives and drops it
again, so restore into a scratch database, or place a hold first. The
integration test `TestIntegrationArchiveDropsExpiredChunksAndKeepsRecentOnes`
restores every line of an archived chunk through
`jsonb_populate_record(NULL::tracks, ...)` and counts the rows back; the
`\copy` line is the psql way of loading the file and is not run by any
test.

## Legal holds

`POST /v1/retention/holds` (admin, incident officer) keeps records past
every period until `POST /v1/retention/holds/{id}/release`. A hold
names a case reference and a reason, and covers:

- the violations in `violation_ids` (whenever they were), and their
  aircraft's telemetry within the margin of them;
- with a window `[window_from, window_to)`: everything of that time
  when no list is given, else the rows of the listed `track_ids` and
  `serials`;
- without a window: the listed aircraft at any time.

Besides the holds, these are never deleted: a violation an incident was
opened from; anything of an open incident's aircraft within the margin
of when it occurred. A held chunk is archived and stays online; a held
month of the audit log stops the drop of every later month (the chain's
anchor must be the newest dropped month); a held archive object stays
(its aircraft are read from its manifest; a USSP bundle is opaque, so
any hold naming aircraft on its day keeps it). Past `RETENTION_MAX_HOLDS`
active holds, everything is treated as held.

Placing or releasing a hold is an events row. Every deletion takes
`legal_holds` in `SHARE` mode inside its own transaction (the hold
gate), so a hold being placed waits for the batch and is never missed by
the next one.

## Deletions

Violations: closed more than `RETENTION_VIOLATIONS_YEARS` ago, at most
`RETENTION_BATCH_ROWS` per transaction and `RETENTION_MAX_BATCHES`
batches per run, oldest first; each batch is one
`retention_rows_deleted` events row naming every id. The rest waits for
the next run and the summary says `left_for_next_run`.

The audit log: the oldest month that ended more than
`RETENTION_AUDIT_YEARS` ago is detached and dropped whole, one month per
transaction, after `audit_dropped_months` records its row count, id
range and last hash; the `audit_month_dropped` events row carries the
same figures and is itself in the chain.

## What the verification alarms mean

**`audit_chain_broken_months` on the status line, an
`audit_chain_verified` row with `intact: false`, the counter
`audit_chain_months_broken`.** A row of that month does not give its
hash, or does not link to the row before it: the log was changed after
it was written (06 §2 T7). The row id and the reason are in the events
row. Do not repair it: keep the database as it is, take a copy, compare
with the backup of the second account, and open an incident. The month
is named broken until a later verification of it holds, also across a
restart. `GET /v1/audit/verify?month=YYYY-MM` verifies one month on
request and records that too. `anchored_to` names the dropped month the
oldest kept month links to; a month older than every drop links to
nothing (the genesis hash).

**An `evidence_packs_reverified` row with `tampered` packs, the counter
`evidence_packs_tampered`.** A stored archive's SHA-256 no longer equals
its `content_hash`, or its seal's signature no longer verifies: the pack
was changed after sealing. Each check is also an `evidence_pack_verified`
row (`via: schedule`). `unreadable` packs are an outage (the storage, the
PII key), not tampering: whether they match is unknown. A run that could
not check a pack fails and names it.

**`ussp_records_missing` on the status line, an
`ussp_records_day_missing` events row, the counter
`ussp_records_days_missing`.** An operating USSP has not served its
daily records bundle (`GET {base_url}/v1/records/daily/{date}`, scope
`ussp.records`) `USSP_RECORDS_GRACE_DAYS` after the day ended (02 F7: a
missing day is an alarm on both sides). The day is retried every run
while it is within `USSP_RECORDS_BACKFILL_DAYS`, and stays an alarm
until it is fetched. No USSP contract pins the bundle's body yet (spec
gap): it is kept verbatim with its hash. Without
`RECORDS_CLIENT_SECRET_FILE` or `ARCHIVE_URL` every day is missing with
that reason.

**`retention_chunk_failures`, a `failed` chunk in the run's summary.**
The export, the read-back or the drop failed; the chunk is online. The
reason is in the summary and in `archive_chunks.last_error`.

## Database roles

`api` works the archive as `authority_ts_archiver` (`TS_ARCHIVER_ROLE`,
created by timeseries `00013_archive`): `SELECT` on the three
hypertables, the ledger, and the two functions; no `DELETE` anywhere.
The deployment grants the login user membership, as for the other
telemetry roles. The relational side needs nothing new for
`authority_app`: it deletes only through the `SECURITY DEFINER`
functions of relational `00024_retention`.

## Known gaps

- An S3-compatible archive store is not implemented (`ARCHIVE_URL`
  takes a local directory); backing the directory up to a second account
  is WP-24's.
- An incident opened about a chunk in the moment between the hold check
  and the drop of that chunk does not stop the drop; place a hold for
  data that must stay.
- The USSP daily bundle's body and route are this system's reading of
  02 F7; no USSP contract pins them yet.
