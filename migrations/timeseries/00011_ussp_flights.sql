-- WP-14: the F3411 Display Provider's cache (docs/PLAN.md §4.2, spec
-- 02 F7, 05 §4; CLAUDE.md rule 7). One row per flight state dp-poller
-- published, written by tsdb-writer only (internal/dp.FlightRow on
-- tsw.v1.ussp_flights):
--
--   rx_ts            when the response carrying the state was received
--                    (this system's clock): the hypertable's time and the
--                    clock of the disposal
--   dedupe_key       "network_rid:<ussp_id>:<flight_id>:<state time>": a
--                    redelivered message writes the state once (B-05)
--   ussp_id          the Service Provider (the owner of the ISA that named
--                    it; the source instance of its tracks)
--   uss_base_url     where it was polled
--   isa_id           the ISA that named it for the tile
--   flight_id        the F3411 flight id; track_id the picture's
--   state_ts         the state's own time (the Service Provider's clock)
--   provider_unknown the Service Provider matches no operating certificate
--   flight           RIDFlight as received
--   details          RIDFlightDetails as received, when fetched. PII
--                    class: it may carry operator_location, the remote
--                    pilot's position (06 §5); only the console realm is
--                    shown it, and it leaves with the row within 24 h.
--
-- Retention (F3411 NetDpMaxDataRetentionPeriodSeconds, 24 h): nothing
-- older than 24 h may remain. A retention policy drops whole chunks
-- once their newest row is older than its interval, so the cache keeps
-- at most interval + chunk + schedule. With one-hour chunks, a 22-hour
-- interval and the policy run every 15 minutes, the oldest row is at
-- most 23 h 15 min old. The policy is added with WP-9's helper
-- (authority_hypertable_policies, timeseries 00005), then the chunk
-- interval and the job's schedule are narrowed. tsdb-writer checks at
-- start and hourly that nothing older than 24 h remains and says so
-- loudly when something does (internal/tswriter.RetentionChecks). Not
-- compressed: nothing is kept long enough to gain from it.

-- +goose Up
CREATE TABLE ussp_flights (
    rx_ts            timestamptz NOT NULL,
    dedupe_key       text        NOT NULL,
    ussp_id          text        NOT NULL,
    uss_base_url     text        NOT NULL,
    isa_id           text,
    flight_id        text        NOT NULL,
    track_id         text        NOT NULL,
    state_ts         timestamptz NOT NULL,
    provider_unknown boolean     NOT NULL,
    flight           jsonb       NOT NULL CHECK (jsonb_typeof(flight) = 'object'),
    details          jsonb       CHECK (details IS NULL OR jsonb_typeof(details) = 'object')
);

COMMENT ON COLUMN ussp_flights.details IS 'PII class: may carry the remote pilot position (F3411 operator_location); disposed of within 24 h';

SELECT create_hypertable('ussp_flights', by_range('rx_ts', INTERVAL '1 hour'));
CREATE UNIQUE INDEX ussp_flights_dedupe_idx ON ussp_flights (dedupe_key, rx_ts DESC);
CREATE INDEX ussp_flights_flight_idx ON ussp_flights (ussp_id, flight_id, rx_ts DESC);

SELECT authority_hypertable_policies('ussp_flights', NULL, NULL, NULL, INTERVAL '22 hours');
SELECT set_chunk_time_interval('ussp_flights', INTERVAL '1 hour');
SELECT alter_job(job_id, schedule_interval => INTERVAL '15 minutes')
  FROM timescaledb_information.jobs
 WHERE hypertable_name = 'ussp_flights' AND proc_name = 'policy_retention';

-- +goose Down
SELECT remove_retention_policy('ussp_flights', if_exists => true);
DROP TABLE IF EXISTS ussp_flights;
