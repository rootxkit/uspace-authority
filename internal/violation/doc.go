// Package violation is the violation/v1 message (spec 04 §3.3; this
// repository's schema, schemas/violation/v1.json, M14): what detect
// publishes on alrt.v1.<kind>.<cell5>.<violation_id> when it raises,
// updates and clears a violation (internal/detectsvc), and what api's
// consumer persists (internal/violations). It holds the wire types, their
// validation and the subject, and nothing that judges.
//
// One violation per raise of an uspace-core alerting key: raised once,
// republished every second as updated while it holds (C-08), and
// cleared once with the reason (C-14). Each carries the policy_version
// it was judged with, the captured_at of the triggering sample, the
// evidence references (track, receiver or USSP, zone and version) and
// an excerpt of the samples (the Display Provider cache is gone in 24 h,
// 03 §1).
package violation
