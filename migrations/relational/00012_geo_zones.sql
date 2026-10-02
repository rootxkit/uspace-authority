-- WP-5: geo-zones and U-space airspace designations (spec 01 A2, A3;
-- 03 §1 geo_zones and uspace_airspaces; docs/PLAN.md §4.1).
--
-- geo_zones holds one row per version of a zone. The master copy is
-- `feature`: the ED-318 feature exactly as uspace-core ed318.Export
-- wrote it after ed318.Parse accepted it (never repaired, spec 06 T9).
-- Every other content column is derived from it in the same statement
-- by internal/zonesvc, for querying only, and a test proves the stored
-- feature round-trips through Parse and Export unchanged.
--
-- A U-space airspace is published as a USPACE zone (spec 02 F1), so its
-- versions are rows here too, with dataset = 'uspace_airspace'; its
-- designation (the 2021/664 Art. 3(4) block and the 03 §1 columns that
-- are not ED-318 members) is the matching uspace_airspaces row. An
-- identifier belongs to one dataset: the service refuses to author it
-- in the other, and (identifier, zone_version) is unique.
--
-- Geometry: a polygon (or a collection of layers) is `geom`; a circle
-- is its published `center` and `radius_m` and is judged by them
-- (LESSONS Z-11). `display_geom` is a polygon drawn for a circle by
-- PostGIS for maps and is never used to judge. Vertical limits of a
-- single-layer zone are in metres in lower_m / upper_m with their
-- reference; the original value and unit are kept in ed318_extra; a
-- zone of several layers has every layer in `layers` and NULL limits.
--
-- The period of validity is mandatory (2019/947 Art. 15(3)): valid_from
-- and valid_to, valid_to after valid_from.
--
-- States: draft -> approved -> published -> superseded. A new version
-- supersedes the identifier's unpublished versions; publishing a version
-- supersedes its older published ones. zones_version_seq numbers every
-- publication (both datasets); a published row carries it in
-- published_version, and the projection and the outbox row carry it too.
--
-- Rows are never deleted (no DELETE grant): history is the versions.

-- +goose Up
CREATE SEQUENCE zones_version_seq AS bigint MINVALUE 1;

CREATE TABLE geo_zones (
    id                     bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dataset                text        NOT NULL CHECK (dataset IN ('zones', 'uspace_airspace')),
    identifier             text        NOT NULL CHECK (identifier ~ '^[^/]{1,7}$'),
    zone_version           integer     NOT NULL CHECK (zone_version >= 1),
    state                  text        NOT NULL CHECK (state IN ('draft', 'approved', 'published', 'superseded')),
    country                text        NOT NULL CHECK (country ~ '^[A-Z]{3}$'),
    name                   jsonb,
    type                   text        NOT NULL
        CHECK (type IN ('PROHIBITED', 'REQ_AUTHORIZATION', 'CONDITIONAL', 'NO_RESTRICTION', 'USPACE')),
    variant                text        NOT NULL,
    reason                 text[]      NOT NULL DEFAULT '{}',
    other_reason_info      jsonb,
    restriction_conditions text,
    region                 integer,
    regulation_exemption   text,
    message                jsonb,
    geometry_type          text        NOT NULL CHECK (geometry_type IN ('Polygon', 'Point', 'GeometryCollection')),
    geom                   geometry(Geometry, 4326),
    center                 geometry(Point, 4326),
    radius_m               double precision CHECK (radius_m > 0),
    display_geom           geometry(Polygon, 4326),
    lower_m                double precision,
    lower_ref              text        CHECK (lower_ref IN ('AGL', 'AMSL', 'WGS84')),
    upper_m                double precision,
    upper_ref              text        CHECK (upper_ref IN ('AGL', 'AMSL', 'WGS84')),
    layers                 jsonb       NOT NULL,
    ed318_extra            jsonb       NOT NULL DEFAULT '{}',
    wgs84_fields           text[]      NOT NULL DEFAULT '{}',
    limited_applicability  jsonb,
    zone_authority         jsonb       NOT NULL,
    data_source            jsonb,
    extended_properties    jsonb,
    feature                jsonb       NOT NULL CHECK (octet_length(feature::text) <= 4194304),
    valid_from             timestamptz NOT NULL,
    valid_to               timestamptz NOT NULL,
    published_version      bigint,
    published_at           timestamptz,
    published_by           text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    created_by             text        NOT NULL,
    approved_at            timestamptz,
    approved_by            text,
    UNIQUE (identifier, zone_version),
    CHECK (valid_to > valid_from),
    CHECK ((geometry_type = 'Point') = (center IS NOT NULL AND radius_m IS NOT NULL)),
    CHECK (state <> 'draft' OR approved_at IS NULL),
    CHECK (state <> 'published' OR published_version IS NOT NULL),
    CHECK (published_version IS NULL OR state IN ('published', 'superseded'))
);

CREATE INDEX geo_zones_dataset_identifier_idx ON geo_zones (dataset, identifier, zone_version DESC);
CREATE INDEX geo_zones_published_idx ON geo_zones (dataset, valid_from, valid_to) WHERE published_version IS NOT NULL;
CREATE INDEX geo_zones_geom_idx ON geo_zones USING gist (geom);
CREATE INDEX geo_zones_center_idx ON geo_zones USING gist (center);

-- The designation of a U-space airspace version (03 §1; 2021/664 Art. 3
-- and 5). The airspace's geometry, limits, identifier and period
-- (designated_from / designated_to are the version's valid_from /
-- valid_to) are its geo_zones row; the Art. 3(4) block is written into
-- the feature's extendedProperties.uspace_requirements in the CISP's
-- cis/uspace_requirements/v1 shape (M7).
CREATE TABLE uspace_airspaces (
    geo_zone_id            bigint      PRIMARY KEY REFERENCES geo_zones (id),
    identifier             text        NOT NULL,
    zone_version           integer     NOT NULL,
    name                   text        NOT NULL CHECK (name <> '' AND length(name) <= 200),
    services_required      text[]      NOT NULL
        CHECK (services_required @> ARRAY['NID', 'GEO', 'FA', 'TI']
               AND services_required <@ ARRAY['NID', 'GEO', 'FA', 'TI', 'WX', 'CM']),
    uas_requirements       jsonb       NOT NULL,
    service_performance    jsonb       NOT NULL,
    operational_conditions jsonb       NOT NULL,
    airspace_constraints   jsonb       NOT NULL,
    adjacent_ids           text[]      NOT NULL DEFAULT '{}',
    risk_assessment_ref    text        CHECK (length(risk_assessment_ref) <= 200),
    in_controlled_airspace boolean     NOT NULL,
    ats_provider_id        text        CHECK (length(ats_provider_id) <= 64),
    cisp_id                text        CHECK (length(cisp_id) <= 64),
    designated_from        timestamptz NOT NULL,
    designated_to          timestamptz NOT NULL,
    designation_ref        text        CHECK (length(designation_ref) <= 200),
    aip_ref                text        CHECK (length(aip_ref) <= 200),
    UNIQUE (identifier, zone_version),
    CHECK (designated_to > designated_from),
    CHECK (cardinality(adjacent_ids) <= 1000)
);

GRANT USAGE ON SEQUENCE zones_version_seq TO authority_app;
GRANT SELECT, INSERT ON geo_zones, uspace_airspaces TO authority_app;
-- The content of a version never changes; only its workflow columns do.
GRANT UPDATE (state, published_version, published_at, published_by, approved_at, approved_by)
    ON geo_zones TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS uspace_airspaces;
DROP TABLE IF EXISTS geo_zones;
DROP SEQUENCE IF EXISTS zones_version_seq;
