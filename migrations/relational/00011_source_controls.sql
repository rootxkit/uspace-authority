-- WP-10: source control (U-15; spec 04 §3.6 source/control; LESSONS
-- B-09, B-10, B-11; docs/PLAN.md §4.1).
--
-- source_controls holds the current switch of each source type
-- (instance_id NULL) and of each instance, with who switched it, why
-- and when. Every switch is an events row in the same transaction
-- (internal/sources/switches), and a switch to the state a row already
-- holds writes nothing.
--
-- version is drawn from source_control_version_seq, so it only rises,
-- whatever any clock does. The state as a whole is (epoch, version) of
-- the one row of source_control_epoch: version is the last value drawn
-- for a change, epoch is random and made here, at table creation. A
-- follower takes a state only when its version is higher within the
-- same epoch, and any state under another epoch. A database restored
-- from a backup holds an older version under the same epoch than the
-- one the followers hold; api finds the bucket ahead of the database
-- and starts a new epoch (audited), so the followers take the restored
-- state rather than ignore it (B-09). A downgrade drops both tables and
-- the upgrade after it makes a new epoch.

-- +goose Up
CREATE SEQUENCE source_control_version_seq AS bigint MINVALUE 1;

CREATE TABLE source_control_epoch (
    singleton  boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch      text        NOT NULL CHECK (epoch ~ '^[0-9a-f-]{8,64}$'),
    version    bigint      NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO source_control_epoch (epoch) VALUES (gen_random_uuid()::text);

CREATE TABLE source_controls (
    source_type text        NOT NULL CHECK (source_type ~ '^[a-z][a-z0-9_]{0,31}$'),
    instance_id text        CHECK (instance_id IS NULL OR instance_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$'),
    enabled     boolean     NOT NULL,
    reason      text        NOT NULL CHECK (reason <> '' AND length(reason) <= 500),
    actor       text        NOT NULL CHECK (actor <> ''),
    changed_at  timestamptz NOT NULL,
    version     bigint      NOT NULL CHECK (version > 0),
    epoch       text        NOT NULL
);
-- One row per type and per instance; '' is never a valid instance id.
CREATE UNIQUE INDEX source_controls_key ON source_controls (source_type, COALESCE(instance_id, ''));

GRANT SELECT, INSERT, UPDATE ON source_controls TO authority_app;
GRANT SELECT, UPDATE (epoch, version) ON source_control_epoch TO authority_app;
GRANT USAGE ON SEQUENCE source_control_version_seq TO authority_app;

-- +goose Down
DROP TABLE source_controls;
DROP TABLE source_control_epoch;
DROP SEQUENCE source_control_version_seq;
