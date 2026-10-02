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
// The queue is drained by the next step of this work package (the
// raw rows to tsdb-writer and the receivers' status).
//
// With no receiver keys the process listens on loopback only (R-06); a
// key set with an invalid entry or an id twice stops it at start (B-14).
// Until WP-10 lands, Run uses an unfed sources.Follower (everything
// enabled, B-09), and says so at start.
package ingest
