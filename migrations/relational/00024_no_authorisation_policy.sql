-- WP-26: the thresholds of the no_authorisation detector (spec 04 §3.3,
-- Art. 6(4); docs/PLAN.md §14 Q-A5) as authority_policy columns
-- (INV-03), beside height_limit_in_uspace (WP-1), which the same work
-- package gives its effect:
--
--   no_authorisation_grace_s   how long an aircraft inside a U-space
--                              airspace may show no matching operational
--                              intent before no_authorisation is raised
--                              (default 10 s, the brief's demo value);
--   no_authorisation_severity  the severity it is raised at (default
--                              warning).
--
-- Both defaults are pending GCAA (spec 08 Q2: no U-space airspace is
-- designated yet). Existing versions, version 1 included, take the
-- defaults; internal/policy.Defaults holds the same values and an
-- integration test compares the two. The grace is finite and positive
-- (E-15): zero would raise on the first sample, before any intent could
-- be read.

-- +goose Up
ALTER TABLE authority_policy
    ADD COLUMN no_authorisation_grace_s  double precision NOT NULL DEFAULT 10,
    ADD COLUMN no_authorisation_severity text             NOT NULL DEFAULT 'warning',
    ADD CONSTRAINT authority_policy_no_authorisation CHECK (
        no_authorisation_grace_s > 0 AND no_authorisation_grace_s < 'Infinity' AND
        no_authorisation_severity IN ('info', 'warning', 'critical')
    );

-- +goose Down
ALTER TABLE authority_policy
    DROP CONSTRAINT IF EXISTS authority_policy_no_authorisation,
    DROP COLUMN IF EXISTS no_authorisation_severity,
    DROP COLUMN IF EXISTS no_authorisation_grace_s;
