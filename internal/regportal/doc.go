// Package regportal is the registry's public face (WP-20; spec 01 §1
// operators "only through the public portal for registration", 06 §5;
// plan Q-A10, Q-A11, Q-A17): the status-only public check, the
// registration applications of the portal, the registrars' review that
// registers an operator through internal/registry, and an operator's
// occurrence report through an e-mailed link into WP-18's intake. It
// runs in api only. docs/runbooks/registry-portal.md is the procedure.
//
// Public check (GET /v1/registry/check): registry.Service.CheckNumber,
// valid / suspended / revoked / unknown and valid_until, nothing else;
// rate-limited per client address behind the trusted proxies by a
// bounded in-memory limiter (E-10), a cheap read that must not write.
//
// Applications (REGISTRY_APPLICATIONS=on; off, every operation is 404):
// the applicant holds no account (Q-A17). A submission is checked whole
// by the registry's own rules before anything is stored, the client
// address's budget is spent in the database (registry_portal_hits,
// database clock, an advisory lock per key, so restarts and replicas
// neither forget nor double it), the Art. 14(2) content is sealed whole
// (AES-256-GCM, the PII key, bound to the row) and the verification
// e-mail is queued in the same transaction. The link carries a token
// signed with REGISTRY_PORTAL_KEY_FILE (HMAC-SHA-256, a purpose, the
// application id, an expiry compared with the database clock); it
// travels in the URL fragment of the portal page, never to a server
// log. Following it moves unverified to submitted within
// REGISTRY_APPLICATION_VERIFY_TTL_S; registrars take it for review,
// read its content with a purpose (registry_application_pii_viewed,
// committed first) and approve or refuse it. An approval draws the
// registration number (IssueNumber: REGISTRY_ISSUE_PREFIX and
// REGISTRY_ISSUE_RANDOM_LEN random letters and digits, checked by the
// registry against the policy's pattern and every registered number,
// never repeating) and the secret part, keeps both on the application
// (the secret sealed), registers the operator through the registry
// (source portal, source_ref the application id: a retried approval
// finds it), then approves and moves the secret into the approval
// e-mail's outbox row in one transaction. The secret part is in no
// response and, once mailed, exists only as the registry's keyed hash.
// The purge job deletes decided applications after
// REGISTRY_APPLICATIONS_RETAIN_S and unverified ones after their link
// expired; the operator stays registered.
//
// Operator reports (REGISTRY_OPERATOR_REPORTS=on): POST
// /v1/registry/operator-links answers 202 whatever the number and mails
// a single-use link only to the address the registry holds for a
// registration in good standing (budgets per address and per operator).
// POST /v1/occurrences/operator checks the body with WP-18's Normalise,
// then spends the link once in the database
// (registry_portal_links_used), then calls WP-18's Intake with
// occurrences.OperatorOrigin: reporter_org operator:<public part>, the
// mandatory channel. Nothing here reads or joins the occurrence reports.
//
// Mail: every e-mail is an outbox row written in the transaction of the
// change it reports and sent after the commit (SendDue: each message
// claimed and leased by a statement of its own, delivered outside any
// transaction and its outcome committed on its own; at least once), its
// content sealed until delivered or given up and then
// cleared; attempts are bounded, a permanent SMTP refusal (5xx) is not
// retried, and every delivery and give-up is an events row. Texts come
// from the en and ka catalogues (catalogue/*.json); a value never
// reaches a header. STARTTLS is required unless the relay is implicit
// TLS or a loopback relay.
package regportal
