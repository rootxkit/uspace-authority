-- WP-20: the registration portal (docs/PLAN.md §4.1
-- registry_applications, §5 registry rows, Q-A10, Q-A11, Q-A17; spec 01
-- §1 operators, 06 §5, 08 Q4, Q5).
--
-- registry_applications holds the portal's registration applications
-- (Q-A11, Q-A17: anonymous, verified by an e-mail link, no account).
-- The Art. 14(2) fields are one sealed JSON document (payload_enc,
-- AES-256-GCM under the PII key, bound to the row); nothing personal is
-- in clear. state: unverified (the e-mail link not yet followed) ->
-- submitted -> under_review (a registrar took it) -> approved | refused.
-- issued_number is the registration number chosen at approval (its
-- public part; the secret part is generated with it and kept sealed in
-- secret_enc only until the approval commits, when it moves into the
-- approval e-mail's outbox row: after that it exists only as the
-- registry's keyed hash). remote_ip_hash is a keyed hash of the client
-- address, for the per-address budget only. Rows are deleted by the
-- purge job: a decided application REGISTRY_APPLICATIONS_RETAIN_S after
-- its decision, an unverified one a link lifetime after its link
-- expired; each purge is an events row and nothing else deletes.
--
-- registry_portal_mail is the outbox of the portal's e-mails (the
-- verification link, the decision, an operator's occurrence link). A row
-- is written in the transaction of the change it reports and sent after
-- the commit; message_enc (the recipient and the message's values,
-- sealed) is cleared once the message is sent or has failed for good,
-- so no link, number or address outlives its delivery. Attempts are
-- bounded (REGISTRY_MAIL_MAX_ATTEMPTS).
--
-- registry_portal_hits is the portal's rate budget: one row per counted
-- request, keyed by a bucket and a keyed hash, timed by the database
-- clock, so neither a restart nor a second api replica forgets or
-- doubles a budget. The purge job deletes rows older than the longest
-- window.
--
-- registry_portal_links_used holds the id of every operator occurrence
-- link spent: a link is good for one report (replay state in the
-- database, never in memory).

-- +goose Up
CREATE TABLE registry_applications (
    id                text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    kind              text        NOT NULL CHECK (kind IN ('operator_registration')),
    state             text        NOT NULL CHECK (state IN ('unverified', 'submitted', 'under_review', 'approved', 'refused')),
    operator_type     text        NOT NULL CHECK (operator_type IN ('natural', 'legal')),
    lang              text        NOT NULL CHECK (lang IN ('en', 'ka')),
    pii_key_id        text        NOT NULL,
    payload_enc       bytea       NOT NULL,
    remote_ip_hash    text        NOT NULL CHECK (remote_ip_hash ~ '^[0-9a-f]{64}$'),
    submitted_at      timestamptz NOT NULL DEFAULT now(),
    verify_expires_at timestamptz NOT NULL,
    verified_at       timestamptz,
    registrar_id      text,
    review_started_at timestamptz,
    decided_at        timestamptz,
    refusal_reason    text        CHECK (refusal_reason <> '' AND length(refusal_reason) <= 500),
    issued_number     text        CHECK (issued_number <> '' AND strpos(issued_number, '-') = 0),
    secret_enc        bytea,
    operator_id       text        REFERENCES uas_operators (id),
    valid_until       timestamptz,
    CONSTRAINT registry_applications_verified CHECK ((state = 'unverified') = (verified_at IS NULL)),
    CONSTRAINT registry_applications_review CHECK (state NOT IN ('under_review', 'approved', 'refused') OR registrar_id IS NOT NULL),
    CONSTRAINT registry_applications_approved CHECK ((state = 'approved') = (operator_id IS NOT NULL)),
    CONSTRAINT registry_applications_refused CHECK ((state = 'refused') = (refusal_reason IS NOT NULL)),
    CONSTRAINT registry_applications_decided CHECK ((state IN ('approved', 'refused')) = (decided_at IS NOT NULL)),
    CONSTRAINT registry_applications_secret CHECK (secret_enc IS NULL OR (state = 'under_review' AND issued_number IS NOT NULL))
);
CREATE INDEX registry_applications_state ON registry_applications (state, submitted_at);
CREATE UNIQUE INDEX registry_applications_issued ON registry_applications (issued_number) WHERE issued_number IS NOT NULL;

CREATE TABLE registry_portal_mail (
    id              bigserial   PRIMARY KEY,
    kind            text        NOT NULL CHECK (kind IN ('verify_application', 'application_approved', 'application_refused', 'operator_link')),
    application_id  text        REFERENCES registry_applications (id) ON DELETE CASCADE,
    lang            text        NOT NULL CHECK (lang IN ('en', 'ka')),
    pii_key_id      text        NOT NULL,
    message_enc     bytea,
    created_at      timestamptz NOT NULL DEFAULT now(),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    failed_at       timestamptz,
    last_error      text        CHECK (length(last_error) <= 300),
    CONSTRAINT registry_portal_mail_done CHECK (sent_at IS NULL OR failed_at IS NULL),
    CONSTRAINT registry_portal_mail_cleared CHECK ((sent_at IS NULL AND failed_at IS NULL) = (message_enc IS NOT NULL))
);
CREATE INDEX registry_portal_mail_due ON registry_portal_mail (next_attempt_at) WHERE sent_at IS NULL AND failed_at IS NULL;

CREATE TABLE registry_portal_hits (
    bucket   text        NOT NULL CHECK (bucket IN ('application', 'operator_link_ip', 'operator_link_operator')),
    key_hash text        NOT NULL CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX registry_portal_hits_key_at ON registry_portal_hits (bucket, key_hash, at);
CREATE INDEX registry_portal_hits_at ON registry_portal_hits (at);

CREATE TABLE registry_portal_links_used (
    link_id    text        PRIMARY KEY CHECK (link_id ~ '^[0-9a-f]{32}$'),
    used_at    timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX registry_portal_links_used_expires ON registry_portal_links_used (expires_at);

GRANT SELECT, INSERT, DELETE ON registry_applications, registry_portal_hits, registry_portal_links_used TO authority_app;
GRANT UPDATE (state, verified_at, registrar_id, review_started_at, decided_at, refusal_reason, issued_number,
              secret_enc, operator_id, valid_until) ON registry_applications TO authority_app;
GRANT SELECT, INSERT, DELETE ON registry_portal_mail TO authority_app;
GRANT UPDATE (message_enc, attempts, next_attempt_at, sent_at, failed_at, last_error) ON registry_portal_mail TO authority_app;
GRANT USAGE ON SEQUENCE registry_portal_mail_id_seq TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS registry_portal_links_used;
DROP TABLE IF EXISTS registry_portal_hits;
DROP TABLE IF EXISTS registry_portal_mail;
DROP TABLE IF EXISTS registry_applications;
