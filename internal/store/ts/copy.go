package ts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rootxkit/uspace-authority/internal/store"
)

// Part is the rows of one table in a Write, each in the table's column
// order (Table.DecodeRow, Gap.Row).
type Part struct {
	Table Table
	Rows  [][]any
}

// Written is what a Write did with one part: the rows inserted and the
// rows the table's dedupe key already held (B-05: a redelivered batch
// writes nothing twice).
type Written struct {
	Inserted   int64
	Duplicates int64
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() } //nolint:misspell // pgx API name

// stageName is the session's staging table of a hypertable.
func stageName(table string) string { return "tsw_stage_" + table }

// Write stores every part in one transaction (spec 05 §5): each part is
// copied (COPY) into a temporary staging table shaped like its target
// and inserted from there with ON CONFLICT DO NOTHING, so a row whose
// dedupe key is already stored is counted, not written twice. Nothing is
// stored unless everything is; the caller acknowledges its messages only
// after Write returns nil (B-05).
func (w *WriterPool) Write(ctx context.Context, parts ...Part) ([]Written, error) {
	out := make([]Written, len(parts))
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("telemetry write: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	for i, p := range parts {
		if len(p.Rows) == 0 {
			continue
		}
		stage, target, cols := ident(stageName(p.Table.Name)), ident(p.Table.Name), p.Table.ColumnNames()
		quoted := make([]string, len(cols))
		for j, c := range cols {
			quoted[j] = ident(c)
		}
		list := strings.Join(quoted, ", ")
		// pg_temp: the staging table lives in this session, never beside
		// the hypertables; ON COMMIT DELETE ROWS empties it at commit and a
		// rollback discards what was copied.
		if _, err := tx.Exec(ctx, "CREATE TEMP TABLE IF NOT EXISTS "+stage+" (LIKE "+target+" INCLUDING DEFAULTS) ON COMMIT DELETE ROWS"); err != nil {
			return nil, fmt.Errorf("telemetry write %s: staging table: %w", p.Table.Name, err)
		}
		copied, err := tx.CopyFrom(ctx, pgx.Identifier{stageName(p.Table.Name)}, cols, pgx.CopyFromRows(p.Rows))
		if err != nil {
			return nil, fmt.Errorf("telemetry write %s: copy: %w", p.Table.Name, err)
		}
		tag, err := tx.Exec(ctx, "INSERT INTO "+target+" ("+list+") SELECT "+list+" FROM "+stage+" ON CONFLICT DO NOTHING")
		if err != nil {
			return nil, fmt.Errorf("telemetry write %s: insert: %w", p.Table.Name, err)
		}
		// A second part of the same table in this transaction starts
		// from an empty stage.
		if _, err := tx.Exec(ctx, "TRUNCATE "+stage); err != nil {
			return nil, fmt.Errorf("telemetry write %s: clear staging table: %w", p.Table.Name, err)
		}
		out[i] = Written{Inserted: tag.RowsAffected(), Duplicates: copied - tag.RowsAffected()}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("telemetry write: commit: %w", err)
	}
	return out, nil
}

// IsDataError reports whether err is the database refusing the data
// itself (SQLSTATE class 22, data exception, or 23, integrity
// constraint): retrying the same rows cannot succeed. Every other
// failure (connection, timeout, a missing table or privilege) is
// retried.
func IsDataError(err error) bool {
	s := store.SQLState(err)
	return strings.HasPrefix(s, "22") || strings.HasPrefix(s, "23")
}

// OlderThanLimit bounds OlderThan's count: it answers "none" or "at
// least n", never scans a whole table.
const OlderThanLimit = 1000

// OlderThan counts, up to OlderThanLimit, the rows of table whose
// column is older than age on the database's clock: the hourly check
// that a table with a retention period (ussp_flights, 24 h) holds
// nothing beyond it.
func (w *WriterPool) OlderThan(ctx context.Context, table, column string, age time.Duration) (int64, error) {
	q := fmt.Sprintf("SELECT count(*) FROM (SELECT 1 FROM %s WHERE %s < now() - make_interval(secs => $1) LIMIT %d) s",
		ident(table), ident(column), OlderThanLimit)
	var n int64
	if err := w.pool.QueryRow(ctx, q, age.Seconds()).Scan(&n); err != nil {
		return 0, fmt.Errorf("retention check %s.%s: %w", table, column, err)
	}
	return n, nil
}
