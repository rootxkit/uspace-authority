-- WP-8: the Remote ID pipeline's columns and the tracks hypertable
-- (spec 03 §1, docs/PLAN.md §4.2). Written by tsdb-writer only (WP-9);
-- 00002's default privileges give the writer INSERT and the readers
-- SELECT on the new table, and no application role holds UPDATE or
-- DELETE on a hypertable.
--
-- rid_observations gains the decoded columns rid-ingest's pipeline
-- fills from each raw frame (internal/ridpipe.Row). Every one is null
-- when the frame did not carry the value (LESSONS R-01: an unknown is
-- never a number) or could not be decoded (decode_error says why):
--
--   serial          the Basic ID of ID type 1 as broadcast, case kept
--                   (G-05); null for any other ID type
--   operator_reg    the Operator ID as broadcast
--   id_type         the Basic ID's ID type (the serial's in a pack of two)
--   lat_deg, lon_deg, alt_wgs84_m (HAE), alt_pressure_m (ISA 1013.25 hPa,
--                   not AMSL, R-08), height_m with height_ref
--                   (TakeoffLocation / GroundLevel, R-12), speed_ms,
--                   track_deg, vspeed_ms (up), status (F3411 names)
--   ts_broadcast    the Location's broadcast time in its hour (T-07)
--   captured_at     where the row is placed on this system's clock (T-01)
--   time_source     the rule that placed it (04 §2)
--   decode_error    the decoder's refusal (R-03), the raw frame is kept
--
-- No AMSL column: the AMSL altitude is a judgement on the frame (geoid,
-- pressure hold) and lives in tracks. No AGL column anywhere (D-02).
--
-- tracks: the authority's picture as published (track/telemetry/v1),
-- one row per published track message. The hypertable's time column is
-- captured_at. Spec 03 names a `geom` column; this database has no
-- PostGIS, so the position is lat_deg/lon_deg (WGS84). The identification
-- block is flattened (ident_*). dedupe_key makes a redelivered batch
-- write a track once (B-05): "direct_rid:<frame_id>" of the frame that
-- carried the Location. alt_amsl_m is the geodetic altitude through the
-- geoid only; a pressure altitude is in alt_pressure_m with alt_source
-- 'pressure' (R-08). Compressed after 7 days, segmented by track_id; the
-- 90-day retention waits for the archive (WP-27), as for rid_observations.

-- +goose Up
ALTER TABLE rid_observations
    ADD COLUMN serial         text,
    ADD COLUMN operator_reg   text,
    ADD COLUMN id_type        smallint,
    ADD COLUMN lat_deg        double precision,
    ADD COLUMN lon_deg        double precision,
    ADD COLUMN alt_wgs84_m    double precision,
    ADD COLUMN alt_pressure_m double precision,
    ADD COLUMN height_m       double precision,
    ADD COLUMN height_ref     text,
    ADD COLUMN speed_ms       double precision,
    ADD COLUMN track_deg      double precision,
    ADD COLUMN vspeed_ms      double precision,
    ADD COLUMN status         text,
    ADD COLUMN ts_broadcast   timestamptz,
    ADD COLUMN captured_at    timestamptz,
    ADD COLUMN time_source    text,
    ADD COLUMN decode_error   text;

CREATE TABLE tracks (
    captured_at             timestamptz      NOT NULL,
    track_id                text             NOT NULL,
    dedupe_key              text             NOT NULL,
    msg_id                  text             NOT NULL,
    ts                      timestamptz,
    rx_ts                   timestamptz      NOT NULL,
    time_source             text             NOT NULL
        CHECK (time_source IN ('source_clock', 'broadcast', 'receiver', 'provider', 'system')),
    backlog                 boolean          NOT NULL,
    source                  text             NOT NULL
        CHECK (source IN ('operator_ws', 'network_rid', 'direct_rid', 'ansp_feed', 'adsb_rx')),
    source_instance         text             NOT NULL,
    trust                   text             NOT NULL
        CHECK (trust IN ('authenticated', 'provider', 'surveillance', 'broadcast', 'sensor')),
    lat_deg                 double precision NOT NULL CHECK (lat_deg BETWEEN -90 AND 90),
    lon_deg                 double precision NOT NULL CHECK (lon_deg BETWEEN -180 AND 180),
    alt_wgs84_m             double precision,
    alt_amsl_m              double precision,
    alt_source              text             NOT NULL CHECK (alt_source IN ('geodetic', 'pressure', 'network', 'none')),
    alt_pressure_m          double precision,
    height_m                double precision,
    height_ref              text             CHECK (height_ref IN ('TakeoffLocation', 'GroundLevel')),
    speed_ms                double precision CHECK (speed_ms >= 0),
    track_deg               double precision CHECK (track_deg >= 0 AND track_deg < 360),
    vspeed_ms               double precision,
    accuracy_h_m            double precision,
    accuracy_v_m            double precision,
    status                  text,
    emergency               boolean          NOT NULL,
    airborne                boolean,
    ident_status            text             NOT NULL
        CHECK (ident_status IN ('registered', 'suspended', 'unknown_operator', 'unidentified')),
    ident_reason            text             NOT NULL,
    ident_mismatch          boolean          NOT NULL,
    ident_basis             text             NOT NULL CHECK (ident_basis IN ('authenticated', 'as_broadcast', 'provider')),
    serial                  text,
    operator_reg            text,
    registered_operator_reg text,
    registry_uas_id         text,
    flight_id               text,
    ussp_id                 text,
    cell5                   text,
    -- A pressure altitude is never an AMSL value (R-08): alt_amsl_m only
    -- with a geodetic or network source.
    CHECK (alt_amsl_m IS NULL OR alt_source IN ('geodetic', 'network')),
    CHECK (height_m IS NULL OR height_ref IS NOT NULL)
);

SELECT create_hypertable('tracks', by_range('captured_at', INTERVAL '1 day'));

CREATE UNIQUE INDEX tracks_dedupe_idx ON tracks (dedupe_key, captured_at DESC);
CREATE INDEX tracks_track_idx ON tracks (track_id, captured_at DESC);

REVOKE ALL ON tracks FROM authority_ts_projector;

SELECT authority_hypertable_policies('tracks', 'track_id', 'captured_at DESC, dedupe_key', INTERVAL '7 days', NULL);

-- +goose Down
SELECT remove_compression_policy('tracks', if_exists => true);
DROP TABLE IF EXISTS tracks;
-- +goose StatementBegin
DO $$
BEGIN
  -- Dropping a column of a compressed hypertable needs its chunks
  -- decompressed first; a Down never drops a row.
  PERFORM decompress_chunk(c, if_compressed => true) FROM show_chunks('rid_observations') c;
END
$$;
-- +goose StatementEnd
ALTER TABLE rid_observations
    DROP COLUMN IF EXISTS serial,
    DROP COLUMN IF EXISTS operator_reg,
    DROP COLUMN IF EXISTS id_type,
    DROP COLUMN IF EXISTS lat_deg,
    DROP COLUMN IF EXISTS lon_deg,
    DROP COLUMN IF EXISTS alt_wgs84_m,
    DROP COLUMN IF EXISTS alt_pressure_m,
    DROP COLUMN IF EXISTS height_m,
    DROP COLUMN IF EXISTS height_ref,
    DROP COLUMN IF EXISTS speed_ms,
    DROP COLUMN IF EXISTS track_deg,
    DROP COLUMN IF EXISTS vspeed_ms,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS ts_broadcast,
    DROP COLUMN IF EXISTS captured_at,
    DROP COLUMN IF EXISTS time_source,
    DROP COLUMN IF EXISTS decode_error;
