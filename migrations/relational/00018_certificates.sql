-- WP-16: USSP and CISP certificates, their operating-status notices and
-- the state of the USSP list publication (docs/PLAN.md §4.1, spec 03 §1
-- certificates, 01 A5, 02 F1 and F7; Reg. 2021/664 Art. 7(6), 14-16,
-- 18(a)).
--
-- A certificate's status is not written: it is derived, in the database,
-- from four facts that change independently, so that lifting one never
-- clears another (a limitation survives a suspension, a cease survives a
-- limitation):
--   operations  not_started | operating | ceased   (the holder's notices)
--   limited     the authority limited the certificate
--   suspended   the authority suspended it
--   ended       revoked | lapsed, final
-- status = ended, else suspended, else ceased, else limited, else
-- operating, else issued (spec 03 §1's seven values).
--
-- code is the holder's short code (one to eight upper-case
-- alphanumerics, unique, assigned at issue and never changed; M8): the
-- ussp_id of cis/ussp_list/v1, the USSP's USSP_SYSTEM_ID, the USSP code
-- of the authorisation number (03 §6) and the <code> of its client id
-- ussp-<code>-01 (M24). A trigger refuses any change of it.
--
-- The holder's address and contact are the organisation's published
-- ones (the CIS USSP list carries the contact); no person is named, so
-- there is no personal data here (CLAUDE.md rule 6). The public
-- register (Art. 18(a)) reads only holder, holder_name, services,
-- status, validity and limitations.
--
-- lapse_unused_after_months and lapse_ceased_after_months are the
-- Art. 16(2) periods, copied from the active policy at issue
-- (authority_policy.certificate_lapse_*_months, INV-03; 6 and 12).
--
-- row_version is taken from certificates_version_seq on every write:
-- the version of the register api publishes to KV bucket certificates
-- (dp-poller follows it, WP-14), never moved backwards.
--
-- certificate_list_state is the USSP list publication's durable state:
-- every transition that changes the list raises wanted in its own
-- transaction; enqueued follows once the list is in the F1 outbox. A
-- publication that could not be queued (no key, a list the schema
-- refuses) leaves wanted > enqueued, and the repair job publishes it,
-- whichever replica runs it. listed_digest is the digest of the
-- certificates (id and row_version) the queued list was built from: the
-- job also publishes when the certificates listed now differ from it (a
-- certificate past its valid_until leaves the list without a write). A
-- suspended or expired USSP is never left on the list by a missed
-- publication.

-- +goose Up
ALTER TABLE authority_policy
    ADD COLUMN certificate_lapse_unused_months integer NOT NULL DEFAULT 6,
    ADD COLUMN certificate_lapse_ceased_months integer NOT NULL DEFAULT 12,
    ADD CONSTRAINT authority_policy_certificate_lapse CHECK (
        certificate_lapse_unused_months BETWEEN 1 AND 120 AND
        certificate_lapse_ceased_months BETWEEN 1 AND 120
    );

CREATE SEQUENCE certificates_version_seq AS bigint MINVALUE 1;

CREATE TABLE certificates (
    id                        text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    holder                    text        NOT NULL CHECK (holder IN ('ussp', 'cisp')),
    holder_name               text        NOT NULL CHECK (holder_name <> '' AND length(holder_name) <= 200),
    holder_address            text        NOT NULL DEFAULT '' CHECK (length(holder_address) <= 500),
    holder_email              text        NOT NULL DEFAULT '' CHECK (length(holder_email) <= 254),
    holder_phone              text        NOT NULL DEFAULT '' CHECK (length(holder_phone) <= 50),
    holder_url                text        NOT NULL DEFAULT '' CHECK (length(holder_url) <= 2048),
    code                      text        NOT NULL UNIQUE CHECK (code ~ '^[A-Z0-9]{1,8}$'),
    client_id                 text        NOT NULL UNIQUE,
    base_url                  text        NOT NULL DEFAULT '' CHECK (length(base_url) <= 2048),
    services                  text[]      NOT NULL CHECK (cardinality(services) BETWEEN 1 AND 7),
    conditions                text        NOT NULL DEFAULT '' CHECK (length(conditions) <= 4000),
    limitations               text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(limitations) <= 50),
    terms_url                 text        NOT NULL DEFAULT '' CHECK (length(terms_url) <= 2048),
    issued_at                 timestamptz NOT NULL,
    valid_until               timestamptz NOT NULL,
    operations                text        NOT NULL DEFAULT 'not_started'
                              CHECK (operations IN ('not_started', 'operating', 'ceased')),
    operations_started_at     timestamptz,
    operations_ceased_at      timestamptz,
    limited                   boolean     NOT NULL DEFAULT false,
    suspended                 boolean     NOT NULL DEFAULT false,
    ended                     text        CHECK (ended IN ('revoked', 'lapsed')),
    ended_at                  timestamptz,
    status                    text        NOT NULL GENERATED ALWAYS AS (
        CASE
            WHEN ended IS NOT NULL THEN ended
            WHEN suspended THEN 'suspended'
            WHEN operations = 'ceased' THEN 'ceased'
            WHEN limited THEN 'limited'
            WHEN operations = 'operating' THEN 'operating'
            ELSE 'issued'
        END) STORED,
    status_reason             text        NOT NULL DEFAULT '' CHECK (length(status_reason) <= 1000),
    status_changed_at         timestamptz NOT NULL,
    status_changed_by         text        NOT NULL CHECK (status_changed_by <> ''),
    lapse_unused_after_months integer     NOT NULL CHECK (lapse_unused_after_months BETWEEN 1 AND 120),
    lapse_ceased_after_months integer     NOT NULL CHECK (lapse_ceased_after_months BETWEEN 1 AND 120),
    row_version               bigint      NOT NULL,
    created_at                timestamptz NOT NULL,
    created_by                text        NOT NULL CHECK (created_by <> ''),
    updated_at                timestamptz NOT NULL,
    updated_by                text        NOT NULL CHECK (updated_by <> ''),
    CONSTRAINT certificates_validity CHECK (valid_until > issued_at),
    CONSTRAINT certificates_client_of_code CHECK (
        (holder = 'ussp' AND client_id = 'ussp-' || code || '-01') OR
        (holder = 'cisp' AND client_id = 'cisp-01')
    ),
    CONSTRAINT certificates_ussp_fields CHECK (holder <> 'ussp' OR (base_url <> '' AND terms_url <> '')),
    CONSTRAINT certificates_services CHECK (
        (holder = 'ussp' AND services <@ ARRAY['network_identification', 'geo_awareness', 'flight_authorisation',
            'traffic_information', 'weather', 'conformance_monitoring']::text[]) OR
        (holder = 'cisp' AND services = ARRAY['common_information']::text[])
    ),
    CONSTRAINT certificates_operations_times CHECK (
        (operations = 'not_started' AND operations_started_at IS NULL AND operations_ceased_at IS NULL) OR
        (operations = 'operating' AND operations_started_at IS NOT NULL AND operations_ceased_at IS NULL) OR
        (operations = 'ceased' AND operations_started_at IS NOT NULL AND operations_ceased_at IS NOT NULL)
    ),
    CONSTRAINT certificates_ended_at CHECK ((ended IS NULL) = (ended_at IS NULL)),
    -- The client is created in the issuing transaction, after the row.
    CONSTRAINT certificates_client_fk FOREIGN KEY (client_id) REFERENCES oauth_clients (client_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX certificates_status ON certificates (holder, status);

-- +goose StatementBegin
CREATE FUNCTION certificates_code_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.code IS DISTINCT FROM OLD.code OR NEW.client_id IS DISTINCT FROM OLD.client_id
       OR NEW.holder IS DISTINCT FROM OLD.holder OR NEW.issued_at IS DISTINCT FROM OLD.issued_at THEN
        RAISE EXCEPTION 'a certificate''s holder, code, client and issue time are never changed';
    END IF;
    IF OLD.ended IS NOT NULL AND (NEW.ended IS DISTINCT FROM OLD.ended OR NEW.suspended <> OLD.suspended
       OR NEW.limited <> OLD.limited OR NEW.operations <> OLD.operations) THEN
        RAISE EXCEPTION 'a revoked or lapsed certificate does not change status';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd

CREATE TRIGGER certificates_code_fixed BEFORE UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificates_code_fixed();

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_certificate_fk FOREIGN KEY (certificate_id) REFERENCES certificates (id);

-- The operating-status notices of Art. 7(6) (02 F7): from the holder's
-- own client (source machine) or entered by an admin from a letter
-- (source manual). A retried notice with the same reference is the same
-- notice.
CREATE TABLE certificate_notices (
    id             bigserial   PRIMARY KEY,
    certificate_id text        NOT NULL REFERENCES certificates (id),
    state          text        NOT NULL CHECK (state IN ('started', 'ceased', 'restarted')),
    at             timestamptz NOT NULL,
    reference      text        CHECK (reference <> '' AND length(reference) <= 200),
    source         text        NOT NULL CHECK (source IN ('machine', 'manual')),
    recorded_by    text        NOT NULL CHECK (recorded_by <> ''),
    received_at    timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX certificate_notices_reference ON certificate_notices (certificate_id, reference)
    WHERE reference IS NOT NULL;

CREATE TABLE certificate_list_state (
    id              boolean     PRIMARY KEY DEFAULT true CHECK (id),
    wanted          bigint      NOT NULL DEFAULT 0 CHECK (wanted >= 0),
    enqueued        bigint      NOT NULL DEFAULT 0 CHECK (enqueued >= 0),
    enqueued_at     timestamptz,
    listed_digest   text        NOT NULL DEFAULT '' CHECK (length(listed_digest) <= 128),
    last_attempt_at timestamptz,
    last_error      text        NOT NULL DEFAULT '' CHECK (length(last_error) <= 1000)
);

INSERT INTO certificate_list_state (id) VALUES (true);

GRANT SELECT, INSERT, UPDATE ON certificates TO authority_app;
GRANT SELECT, INSERT ON certificate_notices TO authority_app;
GRANT SELECT, UPDATE ON certificate_list_state TO authority_app;
GRANT USAGE ON SEQUENCE certificates_version_seq, certificate_notices_id_seq TO authority_app;

-- +goose Down
ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_certificate_fk;
DROP TABLE IF EXISTS certificate_list_state;
DROP TABLE IF EXISTS certificate_notices;
DROP TABLE IF EXISTS certificates;
DROP FUNCTION IF EXISTS certificates_code_fixed();
DROP SEQUENCE IF EXISTS certificates_version_seq;
ALTER TABLE authority_policy
    DROP CONSTRAINT IF EXISTS authority_policy_certificate_lapse,
    DROP COLUMN IF EXISTS certificate_lapse_ceased_months,
    DROP COLUMN IF EXISTS certificate_lapse_unused_months;
