-- The overview's counts (GET /v1/overview/*, internal/overview): the
-- indexes that keep each count off a full scan of its table.
--
-- events is the hot table: every audited read and write appends a row,
-- and a month partition has no index that leads with ts (its primary
-- key is (id, ts)). The audit figure counts the rows of a window that
-- ends at the database clock, so events_ts_idx bounds that count to the
-- window's rows (an index-only scan of the newest one or two monthly
-- partitions) instead of a scan of the month. On the partitioned
-- parent the index is created on every partition and on every
-- partition events_ensure_partition creates later.
--
-- The registry figures count every operator, UAS and pilot by status.
-- uas_operators already has uas_operators_status_idx (status,
-- valid_until); uas and remote_pilots get one on status, so each count
-- is an index-only scan rather than a read of the rows with their
-- encrypted columns.

-- +goose Up
CREATE INDEX events_ts_idx ON events (ts);
CREATE INDEX uas_status_idx ON uas (status);
CREATE INDEX remote_pilots_status_idx ON remote_pilots (status);

-- +goose Down
DROP INDEX IF EXISTS remote_pilots_status_idx;
DROP INDEX IF EXISTS uas_status_idx;
DROP INDEX IF EXISTS events_ts_idx;
