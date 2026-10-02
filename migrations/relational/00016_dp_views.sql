-- WP-14: the Display Provider's oversight areas (docs/PLAN.md §4.1,
-- §5 "DP administration"; POST /v1/dp/views, admin, audited). Each is a
-- WGS84 box the F3411 Display Provider shows whether or not a console
-- is looking. api writes a row and its events row in one transaction,
-- then publishes every area to KV bucket dp_oversight (key "views")
-- with dp_views_version, never moving the bucket backwards
-- (internal/dpviews.PutOversight), and republishes periodically.
-- dp-poller reads the bucket; it never opens this database (B-15).
-- An area never crosses the antimeridian (west < east).

-- +goose Up
CREATE TABLE dp_views (
    id         bigserial        PRIMARY KEY,
    label      text             NOT NULL CHECK (label <> '' AND length(label) <= 200),
    west_deg   double precision NOT NULL CHECK (west_deg >= -180 AND west_deg <= 180),
    south_deg  double precision NOT NULL CHECK (south_deg >= -90 AND south_deg <= 90),
    east_deg   double precision NOT NULL CHECK (east_deg >= -180 AND east_deg <= 180),
    north_deg  double precision NOT NULL CHECK (north_deg >= -90 AND north_deg <= 90),
    created_by text             NOT NULL CHECK (created_by <> ''),
    created_at timestamptz      NOT NULL DEFAULT now(),
    CHECK (west_deg < east_deg AND south_deg < north_deg)
);

GRANT SELECT, INSERT ON dp_views TO authority_app;
GRANT USAGE ON SEQUENCE dp_views_id_seq TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS dp_views;
