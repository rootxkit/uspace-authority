// Package tswriter is tsdb-writer (WP-9, spec 05 §5): the only writer
// of the telemetry hypertables.
//
// Pipeline is one table. A durable pull consumer tsdb-writer-<table> on
// tsw.v1.<table> (explicit ack, max_ack_pending bounded) fills a queue
// of whole messages; a writer takes batches of at most BatchMaxRows rows
// (1000), or what has waited BatchMaxWait (500 ms), and writes each in
// one transaction through internal/store/ts (COPY into a staging table,
// INSERT .. ON CONFLICT DO NOTHING on the dedupe key). Messages are
// acknowledged in delivery order only after their transaction commits
// (B-05); a failed write is retried with a doubling wait and nothing is
// acknowledged meanwhile, and held messages are kept from redelivery
// with in-progress.
//
// The queue is bounded to QueueMaxAge (10 s) of rows and QueueMaxRows
// rows; at either bound the consumer stops pulling, the rest waits in
// the TSW stream (10 min), the state is spilling and spills counts each
// time it starts. The status line carries writer_state (ok, spilling,
// write_failing), each table's queue and the counters rows_written,
// rows_deduplicated, batches, spills and gaps (E-09).
//
// Holes are records, never silence (B-13). writer_gaps receives, in the
// transaction of the rows beside them:
//
//   - the producers' records on tsw.v1.writer_gaps (rid-ingest's shed
//     batches), keyed by their message id;
//   - stream_retention: a step in the stream sequences a consumer is
//     delivered, checked against the stream; the sequences the stream no
//     longer holds were aged out (or deleted) before the writer read
//     them. One stream carries every table, so the count is of TSW
//     messages, an upper bound for the table recording it. A consumer
//     that an idle check found caught up (nothing undelivered) and that
//     has fetched ever since cannot have lost a message to the stream's
//     max age, so its steps are not checked, and the check moves its
//     last sequence to the stream's last: a quiet table records no gap
//     when other tables' messages age out;
//   - stream_purge: the consumer's ack floor moved past sequences never
//     delivered to it, which only a purge (or a delete) does. Seen when
//     the next delivery steps over them or, on an idle consumer, by a
//     floor check every PurgeCheck (10 s); and after a restart by
//     comparing the floor the consumer starts from with the position
//     the table was written to, which every write commits with its rows
//     (writer_positions), which a caught-up idle consumer with nothing
//     waiting to be written also raises to the stream's last sequence.
//     Nothing is pulled or written until that position has been read.
//     A purge seen while the consumer is caught up removed none of its
//     messages: counted (purge_steps_while_caught_up), not recorded. The
//     count is of TSW messages, an upper bound;
//   - malformed: a message the writer cannot read, with its row count
//     when that much can be read;
//   - rejected: a message whose rows the database refused (a data error);
//     the batch is retried message by message, so one bad row never holds
//     back the others.
//
// Retention checks a table with a retention period (ussp_flights, 24 h,
// from WP-14) at start and hourly, and logs at error level when anything
// older remains.
//
// The process starts with NATS or the database down and says so; the
// pool opens in the background (LazyStore), and a schema older than the
// build stops the process (D7).
package tswriter
