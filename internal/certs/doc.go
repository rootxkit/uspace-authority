// Package certs is the authority's USSP and CISP certificates (WP-16;
// spec 01 A5, 02 F1 and F7, 03 §1 certificates, 06 §2 T9; Reg. 2021/664
// Art. 7(6), 14-16, 18(a)). It runs in api only.
// docs/runbooks/certificates.md is the procedure.
//
// A certificate's status is derived by the database from four facts
// (the holder's operations, a limitation, a suspension, an end) so that
// lifting one never clears another; Apply and Notice are the transition
// graphs and Facts.Status the same derivation in Go.
//
// Issue writes the certificate, its code (one to eight upper-case
// alphanumerics, never reused) and the holder's client in the token
// service (ussp-<code>-01 or cisp-01, with ScopesFor's least-privilege
// scopes and the audiences of this system and the CISP) in one
// transaction, copying the Art. 16(2) lapse periods of the active
// policy. Transition suspends (the client too: its next token request
// is refused; a token issued before runs to its exp, and the answer says
// until when), limits, revokes (the client revoked) and reinstates.
// RecordNotice records the holder's start, cease and restart: from its
// own client's token of this issuer (POST .../status, sub = client_id,
// 403 otherwise) or entered by an admin from a letter; a retried notice
// with the same reference is the same notice.
//
// The USSP list (cis/ussp_list/v1, the CISP's schema, M7) is built from
// the USSP certificates operating or limited whose holder operates,
// within their validity (BuildList; ussp_id = code), and queued in
// WP-6's outbox inside the transaction that changed it, after a
// certificates advisory lock, so a list is never built from a snapshot
// older than the change before it. A list that cannot be queued (no
// publication key) leaves certificate_list_state wanting one, and
// RepairList, on any replica, queues it; it also queues one when the
// certificates listed now differ from those the queued list was built
// from (a certificate expired). A suspended or expired USSP is never
// left on the list by a missed publication.
//
// After every commit, and every CERTIFICATES_REPAIR_S, Republish writes
// the certified USSPs to KV bucket certificates (internal/certkv) with
// the register's version, never replacing a higher one; dp-poller
// follows it to tell a certified Service Provider from one shown
// provider_unknown (WP-14).
//
// Lapse, daily under an advisory lock (one replica at a time,
// idempotent), lapses a certificate not used within its
// lapse_unused_after_months of issue (rule lapse_unused) and one whose
// operations ceased lapse_ceased_after_months ago (rule lapse_ceased),
// on the database clock, revoking its client; each is a
// certificate_status_changed events row naming the rule.
//
// The public register (GET /v1/certificates/register) is holder kind and
// name, code, services, status, validity and limitations only; no
// address, contact, conditions or client id (a test greps the response
// schema); cacheable for 60 s and rate-limited per client address.
//
// The holder's address and contact are the organisation's published
// ones: no person is named, so nothing here is personal data.
package certs
