-- WP-12: violations found from the authority's own evidence (spec 01
-- A7; 03 §1 violations; 04 §3.3 violation/v1; docs/PLAN.md §4.1).
--
-- One row per violation_id: detect raises it, republishes it every
-- second while it holds and clears it with a reason; api's consumer of
-- alrt.v1 (internal/violations) applies each message idempotently
-- (JetStream redelivers), and every transition (raised, severity
-- changed, cleared, reviewed) is an events row in the same transaction.
--
-- evidence_excerpt is the track samples copied at detection, because
-- the Display Provider cache is disposed of within 24 h (03 §1, CLAUDE.md
-- rule 7); updates append to it up to a bound (excerpt_truncated says
-- when samples were left out). first_position is the excerpt's first
-- position, for the bbox filter (PostGIS, SRID 4326).
--
-- There is no AGL column (D-02): the height a height_120m violation
-- rested on is peak_value with peak_name height_agl_m, with the DEM it
-- was taken from in terrain_source (D-05).
--
-- last_message_at is the database's clock when a message for the row
-- was last applied: a violation detect no longer republishes (a detect
-- restart) is closed as detector_silent by api's job, never left open
-- and never called resolved.
--
-- Never populated from occurrence reports and no key to them (376/2014
-- Art. 15-16): the occurrences schema (WP-18) has no grant for this
-- role and no column here names it.

-- +goose Up
CREATE TABLE violations (
    violation_id       text             PRIMARY KEY CHECK (violation_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    kind               text             NOT NULL CHECK (kind IN ('height_120m', 'zone_incursion', 'unregistered',
                                                                 'no_authorisation', 'identification_mismatch', 'rid_absent')),
    severity           text             NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    alert_key          text             NOT NULL CHECK (alert_key <> '' AND length(alert_key) <= 1024),
    track_id           text             NOT NULL CHECK (track_id <> '' AND length(track_id) <= 256),
    serial             text             CHECK (length(serial) <= 64),
    operator_reg       text             CHECK (length(operator_reg) <= 64),
    registry_uas_id    text             CHECK (length(registry_uas_id) <= 64),
    zone_id            text             CHECK (length(zone_id) <= 256),
    zone_version       bigint,
    zone_type          text             CHECK (length(zone_type) <= 32),
    detector_state     text             NOT NULL CHECK (detector_state IN ('raised', 'updated', 'cleared')),
    opened_at          timestamptz      NOT NULL,
    closed_at          timestamptz,
    clear_reason       text             CHECK (length(clear_reason) <= 64),
    last_captured_at   timestamptz      NOT NULL,
    policy_version     bigint           NOT NULL CHECK (policy_version >= 0),
    peak_name          text             CHECK (length(peak_name) <= 64),
    peak_value         double precision CHECK (peak_value IS NULL OR (peak_value > '-Infinity' AND peak_value < 'Infinity')),
    detail             jsonb            NOT NULL DEFAULT '{}',
    clearing_detail    jsonb,
    terrain_source     jsonb,
    in_uspace          boolean          NOT NULL DEFAULT false,
    evidence_trust     text             NOT NULL CHECK (evidence_trust IN ('authenticated', 'provider', 'surveillance', 'broadcast', 'sensor')),
    evidence_refs      jsonb            NOT NULL DEFAULT '[]',
    evidence_track_ids text[]           NOT NULL DEFAULT '{}',
    evidence_excerpt   jsonb            NOT NULL DEFAULT '[]',
    excerpt_samples    integer          NOT NULL DEFAULT 0 CHECK (excerpt_samples >= 0),
    excerpt_truncated  boolean          NOT NULL DEFAULT false,
    first_position     geometry(Point, 4326),
    cell5              text             NOT NULL CHECK (cell5 ~ '^c5:[0-9]{1,4}:[0-9]{1,4}$'),
    status             text             NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'reviewed', 'dismissed', 'escalated')),
    reviewed_by        text,
    reviewed_at        timestamptz,
    review_note        text             CHECK (length(review_note) <= 4000),
    incident_requested boolean          NOT NULL DEFAULT false,
    last_message_at    timestamptz      NOT NULL DEFAULT now(),
    created_at         timestamptz      NOT NULL DEFAULT now(),
    CHECK ((closed_at IS NULL) = (clear_reason IS NULL)),
    CHECK ((closed_at IS NULL) = (detector_state <> 'cleared'))
);

CREATE INDEX violations_opened ON violations (opened_at DESC, violation_id DESC);
CREATE INDEX violations_status ON violations (status, opened_at DESC);
CREATE INDEX violations_kind ON violations (kind, opened_at DESC);
CREATE INDEX violations_open ON violations (last_message_at) WHERE closed_at IS NULL;
CREATE INDEX violations_position ON violations USING gist (first_position);

GRANT SELECT, INSERT, UPDATE ON violations TO authority_app;

-- +goose Down
DROP TABLE violations;
