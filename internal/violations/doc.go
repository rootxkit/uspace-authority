// Package violations is api's side of the violations (WP-12; spec 01
// A7, 03 §1 violations, 04 §3.3; 2019/947 Art. 18(k)): the consumer of
// alrt.v1 that persists what detect raises, republishes and clears, the
// job that closes what detect stopped reporting, and the inspectors'
// review. Nothing here judges an aircraft: the findings are
// internal/detectsvc's, made by uspace-core.
//
// Persistence (Service.Apply, Consumer): one transaction per message,
// acknowledged only after it committed; idempotent on violation_id, so a
// JetStream redelivery changes nothing. A raise inserts the row with
// status new; an update refreshes the numbers and appends the samples
// to evidence_excerpt up to VIOLATIONS_EXCERPT_MAX_SAMPLES
// (excerpt_truncated, counted); a clear sets closed_at and clear_reason;
// nothing reopens a violation detect cleared. An update or a clear of an unknown
// id inserts it (a raise lost on the way is repaired, never a hole).
// Every transition (violation_raised, violation_severity_changed,
// violation_cleared) is an events row in the same transaction. A message
// that does not decode is terminated and counted; a failed write is
// redelivered after a delay.
//
// Silence (RunSilent): detect republishes every open violation every
// second (C-08). A violation no message has touched for
// VIOLATIONS_SILENT_AFTER_S on the database's clock (a detect restart:
// its monitor no longer holds it) is closed detector_silent, with its
// events row, but only while the consumer is caught up, so a backlog
// after an api outage is never taken for silence. detector_silent is not
// a judgement of the aircraft. If detect still holds the violation (its
// republication was lost, e.g. in a bus outage), its next update or clear
// with newer evidence revives the row: the same violation, open again,
// with violation_revived recording the silent gap (counted
// violations_revived). After a detect restart the condition, if it
// holds, is raised as a new violation from the next live sample.
//
// Review (Handler, inspector): new or reviewed may become reviewed,
// dismissed or escalated; dismissed and escalated are final (409).
// Broadcast-only evidence is never escalated without a note (06 §2 T1).
// Escalation records incident_requested (WP-17 opens the incident from
// it). Each decision is an events row with the actor.
//
// Occurrence reports (376/2014) are never read here: no query of this
// package names them and the occurrences schema (WP-18) grants this role
// nothing; a test holds the package to it.
package violations
