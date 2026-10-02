// Package receivers is the Remote ID receiver registry of api (WP-7,
// spec 02 F9, 06 §2 T2) and the receiver authentication both api and
// rid-ingest use.
//
// The registry (rid_receivers, migration 00010) holds each receiver's
// id, label, pinned position, owner, status with who disabled it and
// why, last heartbeat and reported position, firmware and config. Its
// keys are generated here and shown once, at creation and at each
// rotation: a bearer key "<id>.<43 base64url>" that names the receiver,
// stored only as an argon2id hash, and a separate 32-byte HMAC-SHA256
// secret, stored sealed with the PII key. A rotation keeps the previous
// generation working until its grace ends (0 revokes it at once). Every
// change is an events row in the same transaction.
//
// The key set (Entry: id, status, pinned position, one or two key
// generations) is projected into the KV bucket rid_receiver_keys inside
// the transaction of every change; a change the bucket cannot take is
// refused with 503 and not recorded (LESSONS B-09), and Reproject
// repairs the bucket from the registry at start and every
// RID_KEYSET_REPROJECT_S.
//
// Keyring authenticates a request: the bearer key picks the receiver and
// generation (argon2id once per key, then a cache; failed keys cached,
// bounded; a bounded number of argon2id checks at once, T8), and the
// generation's uspace-core auth.ReceiverVerifier checks the HMAC over
// the exact body bytes, the 30 s sent_at_ms window and the nonce memory
// (R-06). Datagram assembles the datagram core verifies from the body
// and the X-Report-Signature header; nothing here re-implements the
// check. A reload keeps the verifier, and so the nonce memory, of every
// unchanged secret. VerifyRefusal maps core's refusals onto HTTP: 401
// signature or skew, 409 replay, 400 malformed; a disabled receiver is
// 503 with Retry-After, never 401 or 403 (B-10).
//
// ReceiverAPI serves a receiver's own GET .../config and POST
// .../heartbeat (bearer key; the heartbeat also signed); a heartbeat
// position farther from the pinned one than the receiver's tolerance is
// counted and its start audited. Frames serves the raw frames of
// rid_observations read-only, purpose-logged, refusing a window over
// 24 h rather than thinning it (B-13).
//
// Subpackage ingest is rid-ingest's side: the observation endpoint, the
// dedupe window, the work queue and the receivers' status.
// docs/runbooks/receivers.md is the receiver contract.
package receivers
