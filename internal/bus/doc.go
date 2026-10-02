// Package bus is this system's NATS: the connection, the JetStream
// streams and KV buckets, the subjects, the 04 §2 envelope, pull
// consumers and the KV watch (docs/PLAN.md §6, spec 05 §3, WP-10). One
// NATS cluster per system; nothing here crosses a system (02 §1).
//
// Connection (LESSONS B-08). Connect uses the process's own credentials
// (NATS_URL, NATS_CREDS), reconnects for ever with jitter, and at start
// tries NATS_START_ATTEMPTS times with a doubling backoff. When every
// attempt fails it does not give up: it returns a connection that keeps
// connecting in the background and logs that the process starts
// degraded (E-02: the process starts with NATS down and says so).
//
// Topology. Ensure, run by api at startup, creates every stream and
// bucket that is missing and updates one whose managed settings differ;
// a second run changes nothing and says "bus provisioning: nothing to
// do". Every other process tolerates running before it: OpenStream and
// OpenBucket create only what is missing and never change what exists.
//
//	TRK     trk.v1.>     1 h, file or memory (BUS_TRK_STORAGE)
//	ALRT    alrt.v1.>    7 d
//	IDENT   ident.v1.>   24 h
//	CIS     cis.v1.>     30 d
//	INGEST  ingest.v1.>  work queue, discard new at BUS_INGEST_MAX_MSGS;
//	                     the 10-minute bound is the consumer's, which
//	                     sheds the oldest by age with a writer_gaps
//	                     record (WP-7); a JetStream age limit would drop
//	                     a batch with no record
//	TSW     tsw.v1.>     10 min (spill towards tsdb-writer)
//
// KV buckets source_control, policy, cells, registry_version,
// zones_version and rid_receiver_keys keep a history of 8. Every stream
// has an explicit maximum message size and every bucket an explicit
// maximum value size (E-10); a write past either is refused by the
// server, and a test writes past each.
//
// Subjects are built by typed helpers that refuse a token NATS would
// misread (empty, a dot, a wildcard or white space), so an id from the
// outside can never widen a subject. Every message on a subject that
// carries a 04 message is an Envelope.
package bus
