// Package ingest is rid-ingest (WP-7, spec 02 F9): POST
// /v1/rid/observations from Remote ID receivers.
//
// A request is taken in this order, each refusal counted, logged once per
// interval and answered with a problem: the body bounded (64 KiB, 413);
// the bearer key (receivers.Keyring, 401); the receiver's registry status
// and the direct_rid source-control switch (503 with Retry-After, B-10,
// nothing stored); uspace-core's HMAC, sent_at_ms window and nonce check
// over body + X-Report-Signature (401 signature or skew, 409 replay); the
// rid/observation/v1 batch (ParseBatch, 400 naming each field).
//
// An accepted batch is cut to the observations not accepted from that
// receiver in the last 60 s (Dedupe, keyed by transmitter, rx_ts and
// payload hash; an observation without rx_ts is never merged, T-12),
// written to the JetStream work queue ingest.v1.<cell3> (cell3: the
// receiver's pinned cell, uspace-core geodesy/cell) and acknowledged with
// 202 only after JetStream confirmed the write (B-05). A queue that
// refuses the write is 503 with Retry-After and the reservation is given
// back.
//
// Worker drains the queue: each batch is handed once to the decode
// pipeline (ridpipe.Sink, WP-8) and then its raw rows to tsdb-writer on
// tsw.v1.rid_observations (R-15, B-12), then acknowledged. While the rows
// cannot be handed over the batch waits in the queue (SC-18). A batch
// with more than RID_INGEST_QUEUE_MAX_BATCHES undelivered behind it, or
// older than RID_INGEST_QUEUE_MAX_AGE_S, is shed with a writer_gaps
// record on tsw.v1.writer_gaps and counted: the oldest first, never the
// newest (05 §5). The batch leaves the queue only after JetStream
// confirmed its gap record (B-13); while the record cannot be written the
// batch stays queued. JetStream's own limits are a backstop that refuses new
// writes (503) rather than dropping anything unrecorded.
//
// Status publishes src.v1.direct_rid.<receiver> every 2 s
// (source/status/v1): live, stale with silent_since, unknown (never
// heard) or disabled with how and by whom (B-11), the accepted, stored,
// shed and refused-by-reason counters, the queue depth and lagging with
// lag_s while a receiver replays old backlog (B-03).
//
// With no receiver keys the process listens on loopback only (R-06); a
// key set with an invalid entry or an id twice stops it at start (B-14).
// Until WP-8 and WP-10 land, Run uses ridpipe.Undecoded and an unfed
// sources.Follower (everything enabled, B-09), and says so at start.
package ingest
