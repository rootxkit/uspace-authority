-- WP-6, WP-13: when the CISP last confirmed the restrictions version the
-- projection holds. picture-ws's cis_age_s is the age of that
-- confirmation (spec 02 F3: subscribers keep their cache with
-- cis_age_s, stale beyond the configured bound), never the age of the
-- last write: projected_at moves only when the version or the direct
-- overlay changes, so a dataset the CISP confirms every 60 s without a
-- change, the never-published restrictions dataset included (404
-- no_version, projected as version 0), aged past cis_stale_bound_s and
-- the console showed cis_stale while the subscriber held it current.
--
-- api writes confirmed_at with every projection (the subscriber's own
-- confirmation time) and on every confirmation of the version held
-- (HEAD 304, or 404 no_version for the empty dataset). NULL is a
-- projection the CISP has not confirmed yet (a direct restriction before
-- the first read); readers then fall back to projected_at.

-- +goose Up
ALTER TABLE proj_restrictions_state ADD COLUMN confirmed_at timestamptz;
UPDATE proj_restrictions_state SET confirmed_at = projected_at;

-- +goose Down
ALTER TABLE proj_restrictions_state DROP COLUMN IF EXISTS confirmed_at;
