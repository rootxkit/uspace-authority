-- WP-1: authority_policy, the versioned thresholds every judgement of
-- this system runs with (INV-03, docs/PLAN.md §4.1). A version is never
-- edited: a change is a new row, and activating it is audited. Exactly
-- one row is active (partial unique index); its version travels as
-- policy_version on every violation (spec 04 §3.3).
--
-- The column defaults are the documented defaults, equal to the
-- predecessor's: height limit 120 m AGL, pressure uncertainty 250 m,
-- spoof distance 300 m, identity TTL 15 s, max gap 3 s, identify within
-- 4 s, broadcast tolerance 1 s, max latency 5 s, live max age 10 s,
-- clear after 3 s, stale after 15 s, DP view diagonal 7 km, DP poll
-- 1 Hz, CIS stale bound 300 s, height_limit_in_uspace evaluate; zone
-- severities as uspace-core's defaults (CONDITIONAL warning,
-- identification mismatch warning, unidentified critical). Version 1
-- is seeded with them and active. internal/policy.Defaults holds the
-- same values and an integration test compares the two.
--
-- Every threshold is finite and positive (E-15): a CHECK refuses zero,
-- negative, NaN and infinity ('NaN' sorts above 'Infinity' in
-- PostgreSQL, so "< 'Infinity'" refuses both).

-- +goose Up
CREATE TABLE authority_policy (
    version                   bigint           PRIMARY KEY CHECK (version > 0),
    height_limit_agl_m        double precision NOT NULL DEFAULT 120,
    pressure_uncertainty_m    double precision NOT NULL DEFAULT 250,
    zone_conditional_severity text             NOT NULL DEFAULT 'warning',
    mismatch_severity         text             NOT NULL DEFAULT 'warning',
    identification_severity   text             NOT NULL DEFAULT 'critical',
    spoof_distance_m          double precision NOT NULL DEFAULT 300,
    identity_ttl_s            double precision NOT NULL DEFAULT 15,
    max_gap_s                 double precision NOT NULL DEFAULT 3,
    identify_within_s         double precision NOT NULL DEFAULT 4,
    broadcast_tolerance_s     double precision NOT NULL DEFAULT 1,
    max_latency_s             double precision NOT NULL DEFAULT 5,
    live_max_age_s            double precision NOT NULL DEFAULT 10,
    clear_after_s             double precision NOT NULL DEFAULT 3,
    stale_after_s             double precision NOT NULL DEFAULT 15,
    dp_view_diagonal_km       double precision NOT NULL DEFAULT 7,
    dp_poll_hz                double precision NOT NULL DEFAULT 1,
    cis_stale_bound_s         double precision NOT NULL DEFAULT 300,
    height_limit_in_uspace    text             NOT NULL DEFAULT 'evaluate',
    note                      text             NOT NULL DEFAULT '',
    active                    boolean          NOT NULL DEFAULT false,
    created_at                timestamptz      NOT NULL DEFAULT now(),
    created_by                text             NOT NULL,
    activated_at              timestamptz,
    activated_by              text,
    CONSTRAINT authority_policy_finite_positive CHECK (
        height_limit_agl_m     > 0 AND height_limit_agl_m     < 'Infinity' AND
        pressure_uncertainty_m > 0 AND pressure_uncertainty_m < 'Infinity' AND
        spoof_distance_m       > 0 AND spoof_distance_m       < 'Infinity' AND
        identity_ttl_s         > 0 AND identity_ttl_s         < 'Infinity' AND
        max_gap_s              > 0 AND max_gap_s              < 'Infinity' AND
        identify_within_s      > 0 AND identify_within_s      < 'Infinity' AND
        broadcast_tolerance_s  > 0 AND broadcast_tolerance_s  < 'Infinity' AND
        max_latency_s          > 0 AND max_latency_s          < 'Infinity' AND
        live_max_age_s         > 0 AND live_max_age_s         < 'Infinity' AND
        clear_after_s          > 0 AND clear_after_s          < 'Infinity' AND
        stale_after_s          > 0 AND stale_after_s          < 'Infinity' AND
        dp_view_diagonal_km    > 0 AND dp_view_diagonal_km    < 'Infinity' AND
        dp_poll_hz             > 0 AND dp_poll_hz             < 'Infinity' AND
        cis_stale_bound_s      > 0 AND cis_stale_bound_s      < 'Infinity'
    ),
    CONSTRAINT authority_policy_severities CHECK (
        zone_conditional_severity IN ('info', 'warning', 'critical') AND
        mismatch_severity         IN ('info', 'warning', 'critical') AND
        identification_severity   IN ('info', 'warning', 'critical')
    ),
    CONSTRAINT authority_policy_height_in_uspace CHECK (
        height_limit_in_uspace IN ('evaluate', 'skip_when_authorised')
    ),
    CONSTRAINT authority_policy_activation CHECK (
        NOT active OR (activated_at IS NOT NULL AND activated_by IS NOT NULL)
    )
);

CREATE UNIQUE INDEX authority_policy_one_active ON authority_policy (active) WHERE active;

INSERT INTO authority_policy (version, created_by, active, activated_at, activated_by, note)
VALUES (1, 'migration', true, now(), 'migration', 'documented defaults');

GRANT SELECT, INSERT ON authority_policy TO authority_app;
GRANT UPDATE (active, activated_at, activated_by) ON authority_policy TO authority_app;

-- +goose Down
DROP TABLE IF EXISTS authority_policy;
