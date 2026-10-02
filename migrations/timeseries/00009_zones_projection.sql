-- WP-5: the zones projection the hot-path processes judge with (LESSONS
-- G-08, docs/PLAN.md D2 and §4.2). One row per published version of a
-- zone or a U-space airspace that is in force or will be (valid_to not
-- yet past): the ED-318 feature as published, its period of validity,
-- its type and its bounding box (a prefilter only, never a judgement).
-- Readers build a uspace-core zones.Index from the features through
-- ed318.Parse and ed318.ToZones, choosing per identifier the newest
-- version whose period holds the instant.
--
-- api writes it as authority_ts_projector: inside the publish change,
-- before the relational commit (a failed write rolls the publication
-- back), and in full at startup and every 300 s under an advisory lock.
-- A full write replaces the table's content with the relational state:
-- rows the relational database no longer projects are deleted.
--
-- authority_ts_projector may SELECT, INSERT, UPDATE and DELETE this
-- table and nothing else of it; the writer role's default INSERT grant
-- (00002_roles) is revoked: tsdb-writer writes hypertables only.

-- +goose Up
CREATE TABLE proj_zones (
    dataset          text             NOT NULL CHECK (dataset IN ('zones', 'uspace_airspace')),
    identifier       text             NOT NULL,
    zone_version     integer          NOT NULL,
    feature          jsonb            NOT NULL,
    valid_from       timestamptz      NOT NULL,
    valid_to         timestamptz      NOT NULL,
    type             text             NOT NULL,
    bbox_min_lat_deg double precision NOT NULL,
    bbox_min_lon_deg double precision NOT NULL,
    bbox_max_lat_deg double precision NOT NULL,
    bbox_max_lon_deg double precision NOT NULL,
    projected_at     timestamptz      NOT NULL,
    zones_version    bigint           NOT NULL,
    PRIMARY KEY (dataset, identifier, zone_version)
);

REVOKE INSERT ON proj_zones FROM authority_ts_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON proj_zones TO authority_ts_projector;
GRANT SELECT ON proj_zones TO authority_ts_reader;

-- +goose Down
DROP TABLE IF EXISTS proj_zones;
