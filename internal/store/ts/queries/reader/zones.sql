-- name: ProjectedZones :many
-- The zones projection (WP-5): every published version in force or
-- ahead, read whole by the zone readers into a zones.Index.
SELECT dataset, identifier, zone_version, feature, valid_from, valid_to, type,
       bbox_min_lat_deg, bbox_min_lon_deg, bbox_max_lat_deg, bbox_max_lon_deg, projected_at, zones_version
FROM proj_zones ORDER BY dataset, identifier, zone_version;
