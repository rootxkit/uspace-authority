-- WP-19: the police realm (spec 01 A9, 02 F10, 06 §2 T6, 06 §5;
-- docs/PLAN.md §4.1, §7, Q-A14).
--
-- users: an account of the police realm holds the one grant of that
-- realm, police.query (WP-2 table B: "police accounts, inside a
-- session"), and never a console role; a console account never holds
-- police.query. A police account names its agency and the CIDRs it may
-- sign in and query from (ip_allow); an empty list admits no address
-- (fail closed). The console realm keeps both empty.
--
-- police_queries: one row per query, export and download a police
-- session made, with who (user, agency, session), why (purpose from the
-- configured list, case_ref), what (kind, the query as sent), how much
-- (result_count), whether personal data was released (pii) and from
-- where (remote_ip). at is the database clock: the per-user and
-- per-agency rate limits count these rows over a window of the same
-- clock, so a restart or a second api replica neither forgets nor
-- doubles a budget. Append-only: the application role may SELECT and
-- INSERT, and a trigger refuses UPDATE and DELETE for every role. The
-- DPO report reads it beside events.
--
-- police_exports: which agency a legal evidence pack was built for, so
-- only that agency downloads it (the pack itself is evidence_packs,
-- WP-17). Append-only as well.
--
-- incidents.opened_from gains police_request: a police export of an
-- area and a window opens the authority's own case file for it (the
-- chain of custody of the pack starts there).
--
-- Nothing here references the occurrences schema, and the application
-- role has no grant on it (00020): occurrence reports are never
-- reachable from the police realm (376/2014 Art. 15(2), 16).

-- +goose Up
ALTER TABLE users DROP CONSTRAINT users_roles_check;
ALTER TABLE users ADD CONSTRAINT users_roles_check CHECK (
    (realm = 'console' AND roles <@ ARRAY['viewer', 'inspector', 'registrar', 'incident_officer', 'admin', 'auditor']::text[])
    OR (realm = 'police' AND roles <@ ARRAY['police.query']::text[])
);
-- 00005 admitted the police realm without an agency. An account made
-- before this migration that breaks the agency rule stops it here,
-- naming the account and the remedy, instead of with a bare constraint
-- violation; no agency is guessed and no account is changed.
-- +goose StatementBegin
DO $$
DECLARE
    bad text;
BEGIN
    SELECT string_agg(id, ', ' ORDER BY id) INTO bad FROM users
    WHERE (realm = 'police') <> (agency IS NOT NULL)
       OR (agency IS NOT NULL AND agency !~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$');
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'users_police_agency: set the agency of these police accounts (or clear it on these console accounts) before migrating: %', bad
            USING ERRCODE = 'check_violation';
    END IF;
END
$$;
-- +goose StatementEnd
ALTER TABLE users ADD CONSTRAINT users_police_agency CHECK (
    (realm = 'police') = (agency IS NOT NULL)
    AND (agency IS NULL OR (agency ~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$'))
);
ALTER TABLE users ADD CONSTRAINT users_ip_allow CHECK (
    cardinality(ip_allow) <= 32 AND (realm = 'police' OR cardinality(ip_allow) = 0)
);

CREATE TABLE police_queries (
    id           text        PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    at           timestamptz NOT NULL DEFAULT now(),
    user_id      text        NOT NULL REFERENCES users (id),
    agency       text        NOT NULL CHECK (agency <> ''),
    session_jti  text        NOT NULL,
    kind         text        NOT NULL CHECK (kind IN ('aircraft', 'operator', 'serial', 'export', 'download')),
    purpose      text        NOT NULL CHECK (purpose ~ '^[a-z][a-z0-9_]{0,63}$'),
    case_ref     text        NOT NULL CHECK (case_ref <> '' AND length(case_ref) <= 100),
    query        jsonb       NOT NULL CHECK (jsonb_typeof(query) = 'object' AND length(query::text) <= 4096),
    result_count integer     NOT NULL CHECK (result_count >= 0),
    pii          boolean     NOT NULL,
    remote_ip    text        NOT NULL DEFAULT ''
);

CREATE INDEX police_queries_user_at ON police_queries (user_id, at);
CREATE INDEX police_queries_agency_at ON police_queries (agency, at);
CREATE INDEX police_queries_at ON police_queries (at);

CREATE TABLE police_exports (
    pack_id     text        PRIMARY KEY REFERENCES evidence_packs (pack_id),
    incident_id text        NOT NULL REFERENCES incidents (incident_id),
    query_id    text        NOT NULL UNIQUE REFERENCES police_queries (id),
    agency      text        NOT NULL CHECK (agency <> ''),
    user_id     text        NOT NULL REFERENCES users (id),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
CREATE FUNCTION police_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % refused', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER police_queries_append_only BEFORE UPDATE OR DELETE ON police_queries
    FOR EACH ROW EXECUTE FUNCTION police_refuse_change();
CREATE TRIGGER police_exports_append_only BEFORE UPDATE OR DELETE ON police_exports
    FOR EACH ROW EXECUTE FUNCTION police_refuse_change();

GRANT SELECT, INSERT ON police_queries, police_exports TO authority_app;

ALTER TABLE incidents DROP CONSTRAINT incidents_opened_from_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_opened_from_check
    CHECK (opened_from IN ('violation', 'own_observation', 'ansp_notice', 'ussp_notice', 'police_request'));

-- +goose Down
ALTER TABLE incidents DROP CONSTRAINT incidents_opened_from_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_opened_from_check
    CHECK (opened_from IN ('violation', 'own_observation', 'ansp_notice', 'ussp_notice'));
DROP TABLE IF EXISTS police_exports;
DROP TABLE IF EXISTS police_queries;
DROP FUNCTION IF EXISTS police_refuse_change();
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_ip_allow;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_police_agency;
ALTER TABLE users DROP CONSTRAINT users_roles_check;
ALTER TABLE users ADD CONSTRAINT users_roles_check
    CHECK (roles <@ ARRAY['viewer', 'inspector', 'registrar', 'incident_officer', 'admin', 'auditor']::text[]);
