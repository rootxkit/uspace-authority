// Package ridpipe is the Remote ID pipeline of rid-ingest: verify, decode,
// identity, time, altitude, identification, track (docs/PLAN.md §3).
//
// WP-7 defines only the seam: the batch rid-ingest has authenticated and
// queued (Batch and its raw rows) and the Sink it hands each batch to,
// once, after the batch has left the durable work queue. WP-8 implements
// Sink with the decode-to-track steps (uspace-core odid, rid, timeplace,
// geoid, identify) and fills the decoded columns of each row before the
// row is written; nothing here decodes or judges.
package ridpipe
