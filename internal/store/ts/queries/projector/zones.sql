-- The zones projection written by api as authority_ts_projector (WP-5,
-- migration 00009_zones_projection), always whole: the rows of the
-- relational state are upserted and every other row is deleted, under
-- the zones advisory lock, so a write never replaces a newer state.

-- name: UpsertProjectedZones :execrows
INSERT INTO proj_zones (dataset, identifier, zone_version, feature, valid_from, valid_to, type,
                        bbox_min_lat_deg, bbox_min_lon_deg, bbox_max_lat_deg, bbox_max_lon_deg,
                        projected_at, zones_version)
SELECT z.dataset, z.identifier, z.zone_version, z.feature, z.valid_from, z.valid_to, z.type,
       z.min_lat, z.min_lon, z.max_lat, z.max_lon, sqlc.arg(projected_at)::timestamptz, sqlc.arg(zones_version)::bigint
FROM (SELECT unnest(sqlc.arg(datasets)::text[]) AS dataset, unnest(sqlc.arg(identifiers)::text[]) AS identifier,
             unnest(sqlc.arg(zone_versions)::integer[]) AS zone_version, (unnest(sqlc.arg(features)::text[]))::jsonb AS feature,
             unnest(sqlc.arg(valid_froms)::timestamptz[]) AS valid_from,
             unnest(sqlc.arg(valid_tos)::timestamptz[]) AS valid_to, unnest(sqlc.arg(types)::text[]) AS type,
             unnest(sqlc.arg(min_lats)::double precision[]) AS min_lat,
             unnest(sqlc.arg(min_lons)::double precision[]) AS min_lon,
             unnest(sqlc.arg(max_lats)::double precision[]) AS max_lat,
             unnest(sqlc.arg(max_lons)::double precision[]) AS max_lon) AS z
ON CONFLICT (dataset, identifier, zone_version) DO UPDATE SET
    feature = EXCLUDED.feature,
    valid_from = EXCLUDED.valid_from,
    valid_to = EXCLUDED.valid_to,
    type = EXCLUDED.type,
    bbox_min_lat_deg = EXCLUDED.bbox_min_lat_deg,
    bbox_min_lon_deg = EXCLUDED.bbox_min_lon_deg,
    bbox_max_lat_deg = EXCLUDED.bbox_max_lat_deg,
    bbox_max_lon_deg = EXCLUDED.bbox_max_lon_deg,
    projected_at = EXCLUDED.projected_at,
    zones_version = EXCLUDED.zones_version;

-- name: DeleteProjectedZonesExcept :execrows
-- Rows the relational state no longer projects (a period that ended, a
-- change rolled back after its projection committed).
DELETE FROM proj_zones
WHERE (dataset || '/' || identifier || '/' || zone_version::text) <> ALL(sqlc.arg(keys)::text[]);
