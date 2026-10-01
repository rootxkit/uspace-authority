// Package policy is the versioned authority policy (INV-03,
// docs/PLAN.md §4.1, §6): every threshold, period and severity a
// judgement of this system runs with is a column of authority_policy,
// never a literal.
//
// Built by WP-1:
//
//   - The table (migration 00003_authority_policy): one row per version,
//     never edited; exactly one active (partial unique index); CHECKs
//     refuse zero, negative, NaN and infinite thresholds. Version 1 is
//     seeded active with the documented defaults, equal to the
//     predecessor's and to Defaults() (an integration test compares
//     them).
//   - Thresholds.Validate (E-15): a zero, negative, NaN or infinite
//     number, an unknown severity or an unknown height_limit_in_uspace
//     mode is refused, and the refusal names every field at fault.
//   - Service (api only): Active; Create (validated, the next version,
//     inactive, a policy_created event in the same transaction);
//     Activate (only a version newer than the active one, a
//     policy_activated event in the same transaction, then a publish to
//     the Publisher; a failed publish is counted, not undone).
//   - Publisher is the seam to KV policy and ctl.policy, which arrive
//     with the bus (WP-10). Until then api publishes to its own
//     Follower and tests use a recorder.
//   - Follower holds the policy a process judges with: it applies only a
//     higher version that validates, re-reads periodically (Run), and
//     puts policy_version on the status line (StatusAttrs) or says
//     "none". Every violation carries its Version() (spec 04 §3.3).
//   - Handler serves GET /v1/policy, POST /v1/policy and
//     POST /v1/policy/{version}/activate (role admin, behind the
//     placeholder of internal/apiserver until WP-2).
package policy
