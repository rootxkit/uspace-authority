# The telemetry writer (tsdb-writer)

tsdb-writer is the only writer of the telemetry hypertables (spec 05
§5, WP-9). Adapters hand it rows on `tsw.v1.<table>` (JetStream stream
`TSW`, kept 10 minutes) and never open the database. It writes them in
batches and acknowledges a message only after its rows are committed
(LESSONS B-05). This runbook says what its states and counters mean and
what an operator does about each.

| Table | Producer | Dedupe key | Policies |
|---|---|---|---|
| `rid_observations` | rid-ingest (WP-7) | `(frame_id, ingest_ts)`; `frame_id` hashes (receiver, transmitter, `receiver_ts`, payload hash) | 1-day chunks, compressed after 7 days (`segmentby transmitter`), no retention until WP-27's archive |
| `writer_gaps` | rid-ingest's shed batches; tsdb-writer itself | `dedupe_key` | none |

`tracks` (WP-8), `ussp_flights` (WP-14, 24 h retention) and
`manned_tracks` (WP-15) are added by their work packages, with
`authority_hypertable_policies` (timeseries `00005`).

## Reading the status line

Every `STATUS_INTERVAL_S` the process logs a `status` line with:

- `writer_state`: `ok`, `write_failing` (a table's writes fail and are
  retried) or `spilling` (a table's queue is at its bound). The worst
  table wins.
- `tables`: per table, `state`, `queue_rows`, `queue_messages`,
  `queue_age_s` (how long the oldest queued row has waited) and
  `last_seq` (the last TSW sequence taken).
- `counters.tsdb_writer`: `rows_written`, `rows_deduplicated`,
  `batches`, `spills` and `gaps`, plus `write_failed`, `fetch_failed`,
  `hole_check_failed`, `ack_failed`, `messages_malformed`,
  `rows_rejected`, `rejected_unrecorded`, `gaps_observed`,
  `retention_checks`, `retention_violations` and
  `retention_check_failed`. The same names are on `/metrics`.
- `retention`: for each table with a retention period, `clean`,
  `violated` or `unknown`.

A healthy writer under load shows `writer_state: ok`, `queue_age_s`
under a second, and `rows_written` rising.

## spilling

**Meaning.** A table's in-memory queue has reached its bound:
`TSDB_WRITER_QUEUE_MAX_AGE_S` (10 s) of rows or
`TSDB_WRITER_QUEUE_MAX_ROWS` (30000). The consumer stops pulling and
new rows wait in the TSW stream. Nothing is lost while spilling.

- The log says "writer queue at its bound: not pulling, rows wait in
  JetStream (spilling)" once per episode.
- `spills` counts the episodes.
- "writer queue below its bound: pulling again" ends an episode.

**Why.** Almost always the database:

- It is down, slow, or out of disk or connections. `write_failing` and
  a rising `write_failed` appear beside the spill.
- The load is more than the writer can keep up with. `write_failed` is
  flat and `queue_age_s` is pinned at the bound.

**What to do.**

1. Read the "telemetry write failed" warning for the error. Restore the
   database, or free its disk or connections.
2. Watch the age of the oldest TSW message (`nats stream info TSW`,
   first message time). The stream keeps messages for 10 minutes. After
   that, JetStream drops the oldest and the writer records them as
   `stream_retention` gaps (see below). So a database outage longer than
   about 10 minutes at full load loses rows. Those losses are recorded,
   not silent.
3. When the database is back, the writer logs "telemetry writes
   resumed" with `failed_for_s`, drains the stream and returns to `ok`.
   Read the status line until `queue_rows` is 0 and `writer_state` is
   `ok`.

## gap

**Meaning.** A row in `writer_gaps`: a hole in what reached the
hypertables, with its cause and size (LESSONS B-13). `gaps` counts the
records written. Replay and evidence show holes as holes, with these
causes.

| `cause` | Recorded by | Means | `count_unit` |
|---|---|---|---|
| `ingest_queue_full`, `ingest_queue_age`, `ingest_queue_corrupt` | rid-ingest | Queued receiver batches were shed before they were handed over (`docs/runbooks/receivers.md`). `stream` is `INGEST`. | rows |
| `stream_retention` | tsdb-writer | TSW messages left the stream before this table's consumer reached them: the sequences the consumer was delivered stepped over sequences the stream no longer holds. | messages |
| `stream_purge` | tsdb-writer | The TSW stream was purged (or messages deleted) before this table's consumer was delivered them: the consumer's acknowledgement floor moved past sequences the writer never wrote. Seen at the next delivery or within 10 s on an idle table while the writer runs, and at start by comparing the floor with the position the table was written to (`writer_positions`) when the purge happened while it was stopped. | messages |
| `malformed` | tsdb-writer | A TSW message could not be read (`detail` says why). It is acknowledged with the record. | rows when countable, else messages |
| `rejected` | tsdb-writer | The database refused a message's rows (a CHECK or type error, in `detail`). The rest of the batch is written. | rows |

A `stream_retention` or `stream_purge` count is of TSW messages, not rows. It is an upper
bound for the table that records it: one stream carries every table,
and a lost message's table cannot be read once the message is gone.
Each table's consumer records the hole it saw, so one outage can appear
once per table.

**What to do.** List the recent gaps:

```
SELECT at, table_name, cause, stream, from_seq, to_seq, count, count_unit, receiver_id, detail
FROM writer_gaps ORDER BY at DESC LIMIT 50;
```

- `stream_retention`: the writer was down or spilling for longer than
  the stream keeps messages. Find the outage in the log (`spilling`,
  "telemetry write failed") and fix its cause. If outages that long are
  expected, consider a longer TSW `max_age`.
- `ingest_queue_*`: see the receivers runbook.
- `malformed` or `rejected`: a producer sends something the table does
  not take, usually because it was deployed before its migration. Apply
  the migration (`uspace-authority migrate`) and report the `detail` to
  the owning work package.
- `rejected_unrecorded` above zero: a rejected message's own gap record
  was refused too. Those rows are lost and only counted; the log line
  has the stream sequence. Report it.

- `stream_purge`: someone purged `TSW` (`nats stream purge TSW`) or
  deleted messages from it. Never purge `TSW`: every message in it is a
  row not yet written. Find who did it; the rows in the range are lost
  and the record is their only trace. The log line is "TSW stream
  purged: messages never delivered to this table were removed; recorded
  as a gap".

**Position.** Every write commits the highest TSW sequence it covers in
`writer_positions` (one row per table). At start nothing is written
until that position has been read; while it cannot be (the database is
down) the state is `write_failing` and `position_read_failed` rises.

## deduplicated

**Meaning.** `rows_deduplicated` (and `gaps_deduplicated`) counts rows
the writer received whose dedupe key was already stored, so they were
not written again. It rises when a message is delivered again:

- after a writer restart;
- after an acknowledgement was lost;
- when a producer republished outside the stream's two-minute duplicate
  window;
- when a database outage cut off a transaction at its commit and the
  writer retried it.

**What to do.** Nothing, as long as it stays a small share of
`rows_written`. A steady high share means one of two things:

- Acknowledgements are not reaching NATS (`ack_failed` rising). Check
  the writer's NATS link.
- A producer republishes everything. Check the producer's log.

## Other states

- "telemetry database unavailable at start: writes are retried and
  rows wait in JetStream": the process started without its database.
  It retries every 2 s, and "telemetry database connected" ends the
  state. Until then the readiness check `timescaledb` on `/readyz`
  fails.
- "timeseries schema is at version N, this build needs M": the process
  stops. Run `uspace-authority migrate`.
- `hole_check_failed`: the writer could not read the TSW stream's state
  to check a step in the sequences. It gives the messages back and
  checks again, so nothing advances unchecked. A rising count means the
  NATS link is failing.
- "retention violated: rows older than the table's retention period
  remain" (error level, hourly): a table with a retention period (the
  F3411 Display Provider cache, 24 h) holds older rows. The policy
  removes whole 1-day chunks.
  1. Find the table's `policy_retention` job and its last run in
     `timescaledb_information.jobs` and `job_stats`.
  2. Run it with `CALL run_job(<id>)`.
  3. Treat the hours beyond 24 as a disposal breach and report them.

  `unknown` means the check could not run.

## Configuration

`uspace-authority tsdb-writer --help` lists every variable. The bounds
and their defaults:

| Variable | Default |
|---|---|
| `TSDB_WRITER_BATCH_MAX_ROWS` | 1000 |
| `TSDB_WRITER_BATCH_MAX_WAIT_MS` | 500 |
| `TSDB_WRITER_QUEUE_MAX_AGE_S` | 10 |
| `TSDB_WRITER_QUEUE_MAX_ROWS` | 30000 |
| `TSDB_WRITER_MAX_ACK_PENDING` | 1000 |
| `TSDB_WRITER_ACK_WAIT_S` | 60 (must exceed the queue's age bound) |
| `TSDB_WRITER_RETENTION_CHECK_S` | 3600 |
