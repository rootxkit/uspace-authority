// Package picture is picture-ws, the console picture feed (WP-13; spec
// 02 §3 /v1/picture/*, 05 §3, §5; docs/runbooks/picture.md is the frame
// contract). It renders: it holds no judgement and never commands
// anything. Every frame, in both directions, is the common console frame
// of uspace-lab schemas/common (M29): the 04 §2 envelope and a body
// named by schema. picture-ws makes console/status/v1 (with this
// system's extras, schemas/picture/status/v1.json), console/snapshot/v1
// and source/status/v1; it forwards track/telemetry/v1 (adding age_s and
// source_state, schemas/picture/track/v1.json), track/manned/v1 and
// violation/v1 with their producers' envelopes, so every item keeps its
// own times.
//
// The hub (hub.go). One core NATS subscription each to trk.v1.>,
// man.v1.> and alrt.v1.> feeds three caches: the last message per track
// and per manned aircraft, indexed by c5 cell, bounded (the aircraft
// updated longest ago is evicted, counted and said, tracks_evicted;
// E-10), never moved back in time by an older sample, and swept of what
// is older than the policy's stale_after_s, but only while the bus is
// connected: with the bus lost nothing leaves, every aircraft ages on the
// consoles and the status says nats_unavailable since when (E-02). A
// backlog sample is history and is never shown live. The active
// violations (alertSet) are the raises and republishes of detect (C-08):
// a clear removes one and is remembered so an older message read back
// cannot revive it; one not republished for PICTURE_ALERT_SILENT_S is
// unconfirmed (said), and only past PICTURE_ALERT_FORGET_S does it leave
// the picture, counted and logged, with a fresh snapshot to the
// consoles; a republish brings it back. At start, and when the bus comes
// back, ALRT is read back from the stream (from PICTURE_ALERT_REPLAY_S
// ago, or from the instant the bus was lost), so a violation raised
// before a console connects, or before picture-ws started, is replayed,
// and a clear sent while the bus was away is not missed.
//
// The picture takes every cell from the bus and routes by cell in
// memory: a console's subscription is its cell set, the c5 cover of its
// bbox plus one ring of neighbours (internal/cell.Viewport), at most
// PICTURE_MAX_CELLS cells; a larger viewport is refused and the
// connection keeps the previous one, saying viewport_too_large. On
// connect and on every subscription the console receives
// console/status/v1 then console/snapshot/v1 before any live frame of
// the new viewport (the old viewport's queued frames are discarded).
// Above PICTURE_THROTTLE_ABOVE_TRACKS (200) tracks in a viewport each
// track is sent at most at PICTURE_THROTTLE_HZ (2 Hz); every frame not
// sent, throttled or past the connection's queue (PICTURE_SEND_BUFFER),
// is counted in that connection's dropped_frames, and the console stays
// connected; only a write that does not complete within
// PICTURE_WRITE_TIMEOUT_S closes it. Status and snapshot frames never
// queue behind live frames: the newest replaces one not yet written.
//
// Status (every PICTURE_STATUS_INTERVAL_MS, 2 s): policy_version,
// stale_after_s and live_max_age_s from the active authority_policy
// (KV policy; the documented defaults as version 0 until one is read,
// said policy_default), dropped_frames, sources[] (SourceView), and the
// extras projection_age_s, cis_version, cis_age_s (the projections'
// ages on the database's clock, read every PICTURE_PROJECTION_REFRESH_S),
// dp_state, nats, nats_since and degraded_since. SourceView joins the
// adapters' last src.v1 statuses with the source-control state the
// process follows itself: a source switched off reads "disabled by
// <who>" at the next status interval, even when its adapter is silent or
// was never heard (B-11), an adapter silent for SOURCE_STATUS_STALE_S is
// stale, and every change is announced as a source/status/v1 frame.
//
// Sessions (session.go, handler.go; M20, M22). GET /v1/picture/ws is
// upgraded only from an Origin exactly on PICTURE_ALLOWED_ORIGINS (else
// 403, never upgraded); the uspace_session cookie of the upgrade is
// verified by uspace-core's verifier (this issuer's JWKS, the audiences,
// StrictSessionClaims; built in the background while api is down, every
// session refused as unavailable until then) and must be a session of
// the console or police realm; then api's GET /v1/auth/session is asked
// whether its sessions row is live. picture-ws never opens the
// relational database (B-15): the row is api's. A refused session is
// closed with 4401 (sign in again), a check that cannot be made with
// 1013. Every PICTURE_SESSION_RECHECK_S the session is checked again: a
// logout, a revocation, a disabled account or the idle expiry closes the
// stream with 4401; a session that cannot be re-checked is kept for
// PICTURE_SESSION_GRACE_S (said, session_unchecked), then closed with
// 1013; the token's exp closes it with 4401. There is no ticket and
// nothing is read from the query string. GET /v1/picture/snapshot and
// /v1/picture/sources take the same session as the bearer the BFF
// forwards or the cookie.
//
// Personal data (06 §2 T6, §5): no frame type has a name, address or
// contact member (a test walks every member name); the remote pilot or
// operator position a Display Provider flight may carry is sent to the
// console realm only and omitted for every other realm.
package picture
