-- WP-7: rid_observations, every raw Remote ID frame a receiver reported
-- (spec 03 §1, LESSONS R-15, B-12: keep every raw frame, filter nothing
-- at the edge). One row per accepted observation, written once, by
-- tsdb-writer only (WP-9; this tree's 00002_roles grants it INSERT and
-- the readers SELECT; no role may UPDATE or DELETE).
--
-- The columns here are the raw side rid-ingest fills: who heard what,
-- when, on which clock. The times map onto LESSONS T-01's three:
--
--   T-01 `ts` (the source's own clock)   -> receiver_ts (the receiver's
--                                           clock; F9's wire field rx_ts)
--   T-01 `rx_ts` (when we received it)   -> ingest_ts (rid-ingest's clock)
--   T-01 `captured_at` (placed, our clock) -> WP-8's column, not here
--
-- WP-8 places each row on the ingest's clock by T-02/T-11: within one
-- batch,
--     captured_at = ingest_ts - (newest receiver_ts in the batch - receiver_ts)
-- so the receiver's clock error cancels and the rows keep their true
-- spacing; a row without receiver_ts is placed at ingest_ts (T-12). The
-- receiver's clock is never compared with another clock directly.
--
--   ingest_ts       rid-ingest's clock when it accepted the batch (T-01).
--                   The hypertable's time column: always present and
--                   never a judgement. docs/PLAN.md §4.2 names
--                   captured_at, which is time placement (WP-8,
--                   timeplace.PlaceBroadcast) and so cannot be the
--                   partition key of a row that exists before it is
--                   placed; recorded as a deviation in the WP-7 PR.
--   receiver_ts     the receiver's clock; null when it sent none (T-12:
--                   such a row is placed at arrival by WP-8, not dropped).
--   frame_id        hex of the first 16 bytes of SHA-256 over the dedupe
--                   key (receiver, transmitter, receiver_ts, payload hash);
--                   for a row without it the batch nonce and position are
--                   in the key instead, so repeats are never merged.
--   payload         the ODID message or pack exactly as received (bytea).
--   payload_sha256  SHA-256 of payload (the dedupe key, B-05).
--   msg_type        the type nibble of the first byte (odid.TypeOf), for
--                   routing and filtering only; decoding is WP-8's.
--   backlog         the batch said it was history (receiver replay, T-04).
--   sent_at_ms,     the signed batch's own fields, so a row traces back to
--   nonce           the exact request that carried it.
--
-- WP-8 adds the decoded columns (serial, operator_reg, lat_deg, lon_deg,
-- alt_wgs84_m, alt_pressure_m, ..., captured_at) in its own migration;
-- WP-9 adds chunk compression and retention policies.

-- +goose Up
CREATE TABLE rid_observations (
    ingest_ts          timestamptz      NOT NULL,
    frame_id           text             NOT NULL CHECK (frame_id ~ '^[0-9a-f]{32}$'),
    receiver_id        text             NOT NULL,
    transmitter        text             NOT NULL,
    receiver_ts        timestamptz,
    msg_type           smallint         CHECK (msg_type BETWEEN 0 AND 15),
    payload            bytea            NOT NULL,
    payload_sha256     bytea            NOT NULL CHECK (length(payload_sha256) = 32),
    rssi_dbm           real,
    backlog            boolean          NOT NULL,
    receiver_lat_deg   double precision,
    receiver_lon_deg   double precision,
    receiver_alt_hae_m double precision,
    sent_at_ms         bigint           NOT NULL,
    nonce              text             NOT NULL
);

SELECT create_hypertable('rid_observations', by_range('ingest_ts', INTERVAL '1 day'));

CREATE INDEX rid_observations_frame_idx ON rid_observations (frame_id, ingest_ts DESC);
CREATE INDEX rid_observations_transmitter_idx ON rid_observations (transmitter, ingest_ts DESC);
CREATE INDEX rid_observations_receiver_idx ON rid_observations (receiver_id, ingest_ts DESC);

-- The projector role writes projection tables only.
REVOKE ALL ON rid_observations FROM authority_ts_projector;

-- +goose Down
DROP TABLE IF EXISTS rid_observations;
