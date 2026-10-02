// Package sources is source control in every process (U-15; spec 04
// §3.6; LESSONS B-09, B-10, B-11, B-16; WP-10): the published state, the
// follower each process asks before accepting anything, and the
// adapters' status as api keeps it.
//
// The judgement is uspace-core's sources: State.Query, Decision, Why and
// Follower (Apply only goes forward within an epoch, takes any state
// under a new epoch, and with no state enables everything). This package
// adds the transport and the people:
//
//   - Document is the state as it travels: the envelope of 04 §2 with
//     body source/control/v1 (schemas/source/control/v1.json), in KV
//     bucket source_control under key "state" and pushed on ctl.sources
//     after every commit. Each control carries who switched it, why and
//     when, so a refusal and a status can say "disabled by <who>"
//     (B-11).
//   - Follower wraps core's Follower: it applies documents from the KV
//     watch, the push subject and a periodic re-read (Start), counts
//     what it ignored, and answers Query and DisabledBy. Started with
//     the bucket unreachable it retries NATS_START_ATTEMPTS times with
//     backoff, then starts with every source enabled and logs that the
//     switch state is unknown (SC-08 step 8). It never fails closed.
//   - StatusStore is api's last source/status/v1 per instance, bounded
//     (E-10), and Health maps it to what the console shows: healthy,
//     stale, lagging or never heard, beside enabled or disabled by
//     whom.
//
// The writer of the state, with the database, is api's
// internal/sources/switches; no hot-path process links it (B-15).
package sources
