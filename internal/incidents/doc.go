// Package incidents is the authority's case files and evidence packs
// (WP-17; spec 01 A10, 02 F7 and F10, 03 §1 incidents and
// evidence_packs, 05 §4, 06 §2 T6-T7, 06 §5). It runs in api only.
// docs/runbooks/incidents.md is the procedure.
//
// Case files (Service): an incident is opened from a violation an
// inspector escalated (OpenFromViolation, called by
// violations.Service.Review through its OnEscalate hook inside the
// review's transaction, with the violation row locked, so one
// escalation opens one incident), from the authority's own observation
// or from an ANSP or USSP notice (Open); never from an occurrence report
// (376/2014 Art. 15-16; a test holds the package to it). An aircraft
// keeps what identified it at the time: the serial, the operator
// registration's public part only (uspace-core regnum under the active
// policy's pattern; a secret part is dropped, never stored), the track
// ids and the identification as judged. Update changes the narrative,
// severity, status (open, assigned, closed, and a closed case can always
// be reopened), assignee and intent references, appends aircraft (at
// most MaxAircraft) and notes (append-only, at most MaxNotes); every
// change is one incident_updated events row naming each change from and
// to. RunBackfill opens the incident of an escalation recorded before
// the hook existed (WP-12's incident_requested), idempotently.
//
// Evidence packs (Builder, Packs): for an incident and a window,
// Builder reads every source on its own, so one that cannot be read is a
// section "unavailable" with the reason and never a silent gap (B-13):
// the violations, the tracks (cut by Cut into segments at every silence
// longer than the active policy's max_gap_s, every recorded writer gap
// and every sample without a position, each hole labelled with its
// causes or "no recorded cause"; nothing is interpolated), the raw
// Remote ID frames (R-15), the recorded writer gaps, the Display
// Provider's rows while still held (24 h), the zone versions named and
// in force, the policy versions, the events lines, the ground of every
// AGL number (D-05), the USSP's service record of each USSP flight
// fetched on demand (Records, scope ussp.records; absent: unavailable
// with the reason), and for a legal pack the operators' personal data
// through the registry, each read audited with the pack, case and
// purpose. A window above MaxWindow and a section above MaxRows are
// refused, never thinned. The manifest says what was observed, recorded,
// received and inferred (E-04) and holds no personal data.
//
// Sealing (Seal, Packs.Create): the manifest lists every file's SHA-256;
// the archive is a deterministic ZIP (sorted entries, fixed times), so
// the same evidence gives the same bytes; content_hash is the archive's
// SHA-256, recorded in evidence_packs (immutable by trigger) and in the
// evidence_pack_built events row with the purpose (T7). The seal
// statement (pack, incident, kind, window, hash, size, time, author) is
// signed as a detached JWS by the publication key (uspace-core auth),
// so a changed row breaks the signature as a changed archive breaks the
// hash. A legal pack's archive is sealed at rest with the PII key. The
// archive is stored under EVIDENCE_DIR (Dir: written once, never
// overwritten). Downloads and verifications re-read the stored archive
// and recompute the hash first: a mismatch is refused (409
// evidence_tampered) and audited; every download is an
// evidence_pack_downloaded events row with the purpose, committed before
// a byte is served. Oversight packs carry no personal data (frame
// payloads that may carry the remote pilot position and the Display
// Provider's details are withheld and kept by hash; USSP records are not
// even fetched);
// legal packs are built and downloaded by a personal-data role only
// (apiserver.PIIRoles).
package incidents
