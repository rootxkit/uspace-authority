-- WP-15: the manned traffic the ANSP hands to U-space (spec 02 F4,
-- 04 §3.1 track/manned/v1, 05 §4; docs/PLAN.md §4.2). One row per
-- track/manned/v1 message manned-ingest published on man.v1, written by
-- tsdb-writer only (internal/manned.Row on tsw.v1.manned_tracks); 00002's
-- default privileges give the writer INSERT and the readers SELECT, and
-- no application role holds UPDATE or DELETE on a hypertable.
--
-- The body's members are the ANSP's (uspace-ansp
-- schemas/track/manned/v1.json, pinned in api/clients/ansp-schemas):
-- this system names nothing of its own in them. The position is
-- lat_deg/lon_deg (position.lat/lng, WGS84). alt_pressure_m is pressure
-- altitude (ISA 1013.25 hPa) and is never an AMSL value; alt_wgs84_m is
-- the geometric altitude above the ellipsoid when the source gives one
-- (D-03: ADS-B carries both, and they stay apart). No AMSL and no AGL
-- column (D-02, R-08).
--
--   source_captured_at the sample's captured_at on the ANSP's clock (its
--                      rx_ts, or this system's arrival, when it carried
--                      none: T-12). It names the sample across
--                      reconnections and restarts, so it is the
--                      hypertable's time and part of the dedupe key
--   captured_at        where this system placed the sample on its own
--                      clock (T-01, T-02: arrival minus the ANSP's age_s)
--   rx_ts              when this system received the frame
--   ts                 the source's own time as the ANSP carried it, null
--                      when it carried none (T-12)
--   time_source        provider, or system when placed at arrival
--   dedupe_key         "ansp_feed:<source_instance>:<icao24>:<source
--                      captured_at>:<state>": a redelivered batch, the
--                      snapshot after a reconnection and the one after a
--                      restart write a sample once (B-05, E-02); a state
--                      change of the same sample (stale, source_disabled)
--                      is a row of its own
--   source_msg_id      the ANSP's msg_id; msg_id this system's
--   state              live, stale or source_disabled as published: an
--                      aircraft whose source stopped ages, it is never
--                      removed (CLAUDE.md rule 8)
--
-- Compressed after 7 days, segmented by icao24. The 90-day retention
-- waits for the archive (WP-27), as for tracks and rid_observations.

-- +goose Up
CREATE TABLE manned_tracks (
    source_captured_at timestamptz      NOT NULL,
    captured_at        timestamptz      NOT NULL,
    dedupe_key         text             NOT NULL,
    msg_id             text             NOT NULL,
    source_msg_id      text,
    ts                 timestamptz,
    rx_ts              timestamptz      NOT NULL,
    time_source        text             NOT NULL CHECK (time_source IN ('provider', 'system')),
    backlog            boolean          NOT NULL,
    icao24             text             NOT NULL CHECK (icao24 ~ '^[0-9a-f]{6}$'),
    callsign           text,
    lat_deg            double precision NOT NULL CHECK (lat_deg BETWEEN -90 AND 90),
    lon_deg            double precision NOT NULL CHECK (lon_deg BETWEEN -180 AND 180),
    alt_pressure_m     double precision,
    alt_wgs84_m        double precision,
    gs_ms              double precision,
    track_deg          double precision,
    vrate_ms           double precision,
    emergency          boolean,
    spi                boolean,
    squawk             text,
    source_class       text             NOT NULL,
    quality            jsonb            CHECK (quality IS NULL OR jsonb_typeof(quality) = 'object'),
    trust              text             NOT NULL CHECK (trust = 'surveillance'),
    source             text             NOT NULL CHECK (source = 'ansp_feed'),
    source_instance    text             NOT NULL,
    state              text             NOT NULL CHECK (state IN ('live', 'stale', 'source_disabled')),
    relevant           boolean,
    policy_version     text,
    cell5              text
);

COMMENT ON COLUMN manned_tracks.alt_pressure_m IS 'pressure altitude, ISA 1013.25 hPa; never AMSL (D-03, R-08)';
COMMENT ON COLUMN manned_tracks.alt_wgs84_m IS 'geometric altitude above the WGS84 ellipsoid; null when the source gives none';

SELECT create_hypertable('manned_tracks', by_range('source_captured_at', INTERVAL '1 day'));

CREATE UNIQUE INDEX manned_tracks_dedupe_idx ON manned_tracks (dedupe_key, source_captured_at DESC);
CREATE INDEX manned_tracks_captured_idx ON manned_tracks (captured_at DESC);
CREATE INDEX manned_tracks_icao24_idx ON manned_tracks (icao24, source_captured_at DESC);

REVOKE ALL ON manned_tracks FROM authority_ts_projector;

SELECT authority_hypertable_policies('manned_tracks', 'icao24', 'source_captured_at DESC, dedupe_key', INTERVAL '7 days', NULL);

-- +goose Down
SELECT remove_compression_policy('manned_tracks', if_exists => true);
DROP TABLE IF EXISTS manned_tracks;
