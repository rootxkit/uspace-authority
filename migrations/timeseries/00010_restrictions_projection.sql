-- WP-6: the dynamic restrictions projection the detectors judge with
-- (docs/PLAN.md §4.2, LESSONS Z-12). One row per feature of the CIS
-- restrictions dataset as the CISP serves it (ED-318 with reason DAR,
-- the CISP's extendedProperties.cis_restriction carrying the state and
-- the window), written whole by api from the version its CIS
-- subscriber holds, only after the publisher's signature verified.
--
-- proj_restrictions_state is the one row that says which CIS version
-- the projection holds and when it was written, so an empty
-- proj_restrictions after a version is "no restriction", and an empty
-- one without a state row is "never projected" (an empty console must
-- never look like an empty sky, E-02, SC-22). A write of an older
-- version than the state's is refused by the writer, so two api
-- replicas never move the projection backwards.
--
-- api writes both as authority_ts_projector; readers (detect, WP-12)
-- read them as authority_ts_reader. The writer role's default INSERT
-- grant (00002_roles) is revoked: tsdb-writer writes hypertables only.

-- +goose Up
CREATE TABLE proj_restrictions (
    identifier         text        PRIMARY KEY,
    feature            jsonb       NOT NULL,
    state              text        NOT NULL CHECK (state IN ('planned', 'active', 'ended', 'cancelled', 'unknown')),
    starts_at          timestamptz,
    ends_at            timestamptz,
    ansp_ref           text,
    uspace_airspace_id text,
    cis_version        bigint      NOT NULL,
    projected_at       timestamptz NOT NULL
);

CREATE TABLE proj_restrictions_state (
    id           boolean     PRIMARY KEY DEFAULT true CHECK (id),
    cis_version  bigint      NOT NULL CHECK (cis_version >= 0),
    etag         text        NOT NULL,
    projected_at timestamptz NOT NULL
);

REVOKE INSERT ON proj_restrictions FROM authority_ts_writer;
REVOKE INSERT ON proj_restrictions_state FROM authority_ts_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON proj_restrictions TO authority_ts_projector;
GRANT SELECT, INSERT, UPDATE ON proj_restrictions_state TO authority_ts_projector;
GRANT SELECT ON proj_restrictions, proj_restrictions_state TO authority_ts_reader;

-- +goose Down
DROP TABLE IF EXISTS proj_restrictions_state;
DROP TABLE IF EXISTS proj_restrictions;
