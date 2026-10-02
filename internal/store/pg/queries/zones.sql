-- WP-5: zone and U-space airspace versions (migration 00012_geo_zones)
-- and the publication outbox (00013_publications). Geometry columns are
-- written from GeoJSON built by internal/zonesvc and never read back
-- here: the feature is the master copy.

-- name: DBNow :one
-- The database clock: every instant the zone service stores or compares
-- is the database's, never the replica's.
SELECT now()::timestamptz AS now;

-- name: NextZonesVersion :one
-- Numbers one publication of either dataset.
SELECT nextval('zones_version_seq')::bigint AS version;

-- name: InsertZoneVersion :one
INSERT INTO geo_zones (
    dataset, identifier, zone_version, state, country, name, type, variant, reason, other_reason_info,
    restriction_conditions, region, regulation_exemption, message, geometry_type, geom, center, radius_m,
    display_geom, lower_m, lower_ref, upper_m, upper_ref, layers, ed318_extra, wgs84_fields,
    limited_applicability, zone_authority, data_source, extended_properties, feature, valid_from, valid_to,
    created_by
) VALUES (
    sqlc.arg(dataset), sqlc.arg(identifier), sqlc.arg(zone_version), 'draft', sqlc.arg(country), sqlc.narg(name),
    sqlc.arg(type), sqlc.arg(variant), sqlc.arg(reason)::text[], sqlc.narg(other_reason_info),
    sqlc.narg(restriction_conditions), sqlc.narg(region), sqlc.narg(regulation_exemption), sqlc.narg(message),
    sqlc.arg(geometry_type),
    CASE WHEN sqlc.narg(geometry_geojson)::text IS NULL THEN NULL
         ELSE ST_SetSRID(ST_GeomFromGeoJSON(sqlc.narg(geometry_geojson)::text), 4326) END,
    CASE WHEN sqlc.narg(center_lon_deg)::double precision IS NULL THEN NULL
         ELSE ST_SetSRID(ST_MakePoint(sqlc.narg(center_lon_deg)::double precision, sqlc.narg(center_lat_deg)::double precision), 4326) END,
    sqlc.narg(radius_m),
    CASE WHEN sqlc.narg(center_lon_deg)::double precision IS NULL THEN NULL
         ELSE ST_Buffer(ST_SetSRID(ST_MakePoint(sqlc.narg(center_lon_deg)::double precision,
                                                sqlc.narg(center_lat_deg)::double precision), 4326)::geography,
                        sqlc.narg(radius_m)::double precision, 'quad_segs=16')::geometry END,
    sqlc.narg(lower_m), sqlc.narg(lower_ref), sqlc.narg(upper_m), sqlc.narg(upper_ref), sqlc.arg(layers),
    sqlc.arg(ed318_extra), sqlc.arg(wgs84_fields)::text[], sqlc.narg(limited_applicability), sqlc.arg(zone_authority),
    sqlc.narg(data_source), sqlc.narg(extended_properties), sqlc.arg(feature), sqlc.arg(valid_from), sqlc.arg(valid_to),
    sqlc.arg(created_by)
)
RETURNING id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
          published_version, published_at, published_by, created_at, created_by, approved_at, approved_by;

-- name: InsertUSpaceDesignation :exec
INSERT INTO uspace_airspaces (
    geo_zone_id, identifier, zone_version, name, services_required, uas_requirements, service_performance,
    operational_conditions, airspace_constraints, adjacent_ids, risk_assessment_ref, in_controlled_airspace,
    ats_provider_id, cisp_id, designated_from, designated_to, designation_ref, aip_ref
) VALUES (
    sqlc.arg(geo_zone_id), sqlc.arg(identifier), sqlc.arg(zone_version), sqlc.arg(name),
    sqlc.arg(services_required)::text[], sqlc.arg(uas_requirements), sqlc.arg(service_performance),
    sqlc.arg(operational_conditions), sqlc.arg(airspace_constraints), sqlc.arg(adjacent_ids)::text[],
    sqlc.narg(risk_assessment_ref), sqlc.arg(in_controlled_airspace), sqlc.narg(ats_provider_id), sqlc.narg(cisp_id),
    sqlc.arg(designated_from), sqlc.arg(designated_to), sqlc.narg(designation_ref), sqlc.narg(aip_ref)
);

-- name: USpaceDesignations :many
-- The designations of the given geo_zones rows.
SELECT geo_zone_id, name, services_required, uas_requirements, service_performance, operational_conditions,
       airspace_constraints, adjacent_ids, risk_assessment_ref, in_controlled_airspace, ats_provider_id, cisp_id,
       designation_ref, aip_ref
FROM uspace_airspaces WHERE geo_zone_id = ANY(sqlc.arg(ids)::bigint[]);

-- name: LatestZoneVersion :one
SELECT id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
       published_version, published_at, published_by, created_at, created_by, approved_at, approved_by
FROM geo_zones WHERE identifier = sqlc.arg(identifier) ORDER BY zone_version DESC LIMIT 1;

-- name: LatestZoneVersionForUpdate :one
-- The newest version of an identifier, locked: a change to an
-- identifier waits for any other change to it.
SELECT id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
       published_version, published_at, published_by, created_at, created_by, approved_at, approved_by
FROM geo_zones WHERE identifier = sqlc.arg(identifier) ORDER BY zone_version DESC LIMIT 1 FOR UPDATE;

-- name: ZoneVersion :one
SELECT id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
       published_version, published_at, published_by, created_at, created_by, approved_at, approved_by
FROM geo_zones WHERE identifier = sqlc.arg(identifier) AND zone_version = sqlc.arg(zone_version);

-- name: ZoneVersions :many
-- An identifier's history, newest first, below before_version.
SELECT id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
       published_version, published_at, published_by, created_at, created_by, approved_at, approved_by
FROM geo_zones
WHERE identifier = sqlc.arg(identifier) AND zone_version < sqlc.arg(before_version)
ORDER BY zone_version DESC LIMIT sqlc.arg(page_size);

-- name: ListLatestZoneVersions :many
-- The newest version of every identifier of a dataset, in identifier
-- order after after_identifier; state filters when given.
SELECT * FROM (
    SELECT DISTINCT ON (identifier) id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields,
           valid_from, valid_to, published_version, published_at, published_by, created_at, created_by, approved_at,
           approved_by
    FROM geo_zones
    WHERE dataset = sqlc.arg(dataset) AND identifier > sqlc.arg(after_identifier)
    ORDER BY identifier, zone_version DESC
) AS latest
WHERE sqlc.narg(state)::text IS NULL OR latest.state = sqlc.narg(state)
ORDER BY identifier LIMIT sqlc.arg(page_size);

-- name: SupersedeUnpublished :execrows
-- A new version supersedes the identifier's drafts and approved versions.
UPDATE geo_zones SET state = 'superseded'
WHERE identifier = sqlc.arg(identifier) AND state IN ('draft', 'approved');

-- name: ApproveZoneVersion :one
UPDATE geo_zones SET state = 'approved', approved_at = now(), approved_by = sqlc.arg(approved_by)
WHERE identifier = sqlc.arg(identifier) AND zone_version = sqlc.arg(zone_version) AND state = 'draft'
RETURNING id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
          published_version, published_at, published_by, created_at, created_by, approved_at, approved_by;

-- name: PublishApproved :many
-- Every approved version of a dataset becomes published under version.
UPDATE geo_zones SET state = 'published', published_version = sqlc.arg(version), published_at = now(),
                     published_by = sqlc.arg(published_by)
WHERE dataset = sqlc.arg(dataset) AND state = 'approved'
RETURNING id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
          published_version, published_at, published_by, created_at, created_by, approved_at, approved_by;

-- name: SupersedeOlderPublished :execrows
-- Publishing a version supersedes the identifier's older published ones.
UPDATE geo_zones SET state = 'superseded'
WHERE identifier = sqlc.arg(identifier) AND state = 'published' AND zone_version < sqlc.arg(zone_version);

-- name: ZonesInForce :many
-- Per identifier of a dataset, the newest published version whose
-- period of validity holds at (both ends included).
SELECT DISTINCT ON (identifier) id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields,
       valid_from, valid_to, published_version, published_at, published_by, created_at, created_by, approved_at,
       approved_by
FROM geo_zones
WHERE dataset = sqlc.arg(dataset) AND published_version IS NOT NULL
  AND valid_from <= sqlc.arg(at)::timestamptz AND valid_to >= sqlc.arg(at)::timestamptz
ORDER BY identifier, zone_version DESC;

-- name: ZonesProjectable :many
-- Every published version of both datasets whose period has not ended
-- at at: what the projection holds.
SELECT id, dataset, identifier, zone_version, state, type, country, feature, wgs84_fields, valid_from, valid_to,
       published_version, published_at, published_by, created_at, created_by, approved_at, approved_by
FROM geo_zones
WHERE published_version IS NOT NULL AND valid_to >= sqlc.arg(at)::timestamptz
ORDER BY dataset, identifier, zone_version;

-- name: MaxPublishedZonesVersion :one
SELECT coalesce(max(published_version), 0)::bigint AS version FROM geo_zones;

-- name: SupersedePendingPublications :execrows
-- One pending snapshot per dataset (E-10): a new one supersedes it.
UPDATE publications SET state = 'superseded' WHERE dataset = sqlc.arg(dataset) AND state = 'pending';

-- name: InsertPublication :one
INSERT INTO publications (dataset, version, payload, payload_hash, feature_count, created_by)
VALUES (sqlc.arg(dataset), sqlc.arg(version), sqlc.arg(payload), sqlc.arg(payload_hash), sqlc.arg(feature_count),
        sqlc.arg(created_by))
RETURNING id, dataset, version, payload_hash, feature_count, signature, state, created_at;
