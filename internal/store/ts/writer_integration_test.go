package ts_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

func openWriter(t *testing.T, u string) *ts.WriterPool {
	t.Helper()
	w, err := ts.OpenWriterPool(context.Background(), store.PoolOptions{URL: u, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}

// ridRow is one rid_observations row in RIDObservations' column order.
func ridRow(i int, at time.Time) []any {
	payload := []byte{0x12, byte(i >> 8), byte(i)}
	sum := sha256.Sum256(payload)
	frame := sha256.Sum256(fmt.Appendf(nil, "rx-1|TEST%d|%d", i, i))
	return []any{at, hex.EncodeToString(frame[:16]), "rx-1", fmt.Sprintf("TEST%d", i), at.Add(-time.Second), int64(1),
		payload, sum[:], -70.0, false, 41.7, 44.8, nil, int64(1), "n",
		// The decoded columns of WP-8 (timeseries 00006), none decoded.
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil}
}

// Each registered table is the migrated table: same columns, in the
// columns the migrations created (a WP that adds a column adds it to
// both, or this fails).
func TestIntegrationRegisteredTablesMatchTheMigratedColumns(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	db := storetest.Open(t, u)
	tables := []ts.Table{ts.WriterGaps}
	for _, tb := range ts.Tables {
		tables = append(tables, tb)
	}
	for _, tb := range tables {
		rows, err := db.Query(`SELECT column_name FROM information_schema.columns WHERE table_name = $1 AND column_default IS NULL ORDER BY ordinal_position`, tb.Name)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		_ = rows.Close()
		if !slices.Equal(cols, tb.ColumnNames()) {
			t.Errorf("%s: migrated %v, registered %v", tb.Name, cols, tb.ColumnNames())
		}
	}
}

// B-05: a batch is written and read back; the same batch again writes
// nothing and is counted as duplicates; a gap part commits with it.
func TestIntegrationWriteIsIdempotentAndReadBack(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	w := openWriter(t, u)
	db := storetest.Open(t, u)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Microsecond)
	var rows [][]any
	for i := range 3 {
		rows = append(rows, ridRow(i, at))
	}
	gap := ts.Gap{DedupeKey: "k1", Table: "rid_observations", Stream: "TSW", FromSeq: 4, ToSeq: 6, Cause: "stream_retention",
		Count: 3, CountUnit: ts.UnitMessages, At: at}
	got, err := w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: rows}, ts.Part{Table: ts.WriterGaps, Rows: [][]any{gap.Row()}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != (ts.Written{Inserted: 3}) || got[1] != (ts.Written{Inserted: 1}) {
		t.Fatalf("first write %+v", got)
	}
	// Redelivery: the same rows and the same gap.
	got, err = w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: rows}, ts.Part{Table: ts.WriterGaps, Rows: [][]any{gap.Row()}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != (ts.Written{Duplicates: 3}) || got[1] != (ts.Written{Duplicates: 1}) {
		t.Fatalf("redelivery %+v", got)
	}
	// Two parts of one table in one transaction start from an empty stage.
	got, err = w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(10, at)}}, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(11, at)}})
	if err != nil || got[0].Inserted != 1 || got[1].Inserted != 1 {
		t.Fatalf("two parts %+v %v", got, err)
	}
	var n int
	var payload []byte
	if err := db.QueryRow(`SELECT count(*) FROM rid_observations`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("rows %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT payload FROM rid_observations WHERE transmitter = 'TEST2'`).Scan(&payload); err != nil || hex.EncodeToString(payload) != "120002" {
		t.Fatalf("read back %x %v", payload, err)
	}
	var cause, unit string
	var count int64
	if err := db.QueryRow(`SELECT cause, count, count_unit FROM writer_gaps WHERE dedupe_key = 'k1'`).Scan(&cause, &count, &unit); err != nil ||
		cause != "stream_retention" || count != 3 || unit != "messages" {
		t.Fatalf("gap %s %d %s %v", cause, count, unit, err)
	}
	// Nothing is left in the session's staging table after a commit.
	if _, err := w.Write(ctx); err != nil {
		t.Fatal(err)
	}
}

// A failed transaction stores nothing: the rows before the refused one
// are rolled back with it, and the refusal is a data error (not retried
// as is); a missing table is not a data error (retried).
func TestIntegrationRefusedRowRollsBackItsBatch(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	w := openWriter(t, u)
	db := storetest.Open(t, u)
	ctx := context.Background()
	at := time.Now().UTC()
	bad := ridRow(2, at)
	bad[1] = "not-hex" // frame_id CHECK
	_, err := w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(1, at), bad}})
	if err == nil || !ts.IsDataError(err) {
		t.Fatalf("got %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM rid_observations`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows %d %v", n, err)
	}
	// E-01 twin: the good row alone is written.
	if got, err := w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(1, at)}}); err != nil || got[0].Inserted != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	missing := ts.Table{Name: "no_such_hypertable", Columns: []ts.Column{{Name: "x", Kind: ts.KindText}}}
	if _, err := w.Write(ctx, ts.Part{Table: missing, Rows: [][]any{{"a"}}}); err == nil || ts.IsDataError(err) {
		t.Fatalf("missing table: %v", err)
	}
}

// Spec 06 T7: the writer role inserts into the hypertables and
// writer_gaps and may neither change nor remove a row; the reader may
// read and not write.
func TestIntegrationWriterRoleInsertsAndCannotUpdateOrDelete(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	w := openWriter(t, u)
	ctx := context.Background()
	if _, err := w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(1, time.Now().UTC())}}); err != nil {
		t.Fatalf("writer insert: %v", err)
	}
	if n, err := w.Exec(ctx, `INSERT INTO writer_gaps (dedupe_key, table_name, stream, from_seq, to_seq, cause, count, count_unit, at)
		VALUES ('k', 't', 'TSW', 0, 0, 'c', 1, 'rows', now())`); err != nil || n != 1 {
		t.Fatalf("writer gap insert: %d %v", n, err)
	}
	for _, sql := range []string{
		`UPDATE rid_observations SET backlog = true`, `DELETE FROM rid_observations`,
		`UPDATE writer_gaps SET count = 0`, `DELETE FROM writer_gaps`,
	} {
		if _, err := w.Exec(ctx, sql); store.SQLState(err) != store.StateInsufficientPrivilege {
			t.Errorf("writer %s: %v", sql, err)
		}
	}
	r, err := ts.OpenReader(ctx, store.PoolOptions{URL: u})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if n, err := r.Exec(ctx, `SELECT * FROM writer_gaps`); err != nil || n != 1 {
		t.Fatalf("reader select: %d %v", n, err)
	}
	if _, err := r.Exec(ctx, `INSERT INTO writer_gaps (dedupe_key, table_name, stream, from_seq, to_seq, cause, count, count_unit, at)
		VALUES ('k2', 't', 'TSW', 0, 0, 'c', 1, 'rows', now())`); store.SQLState(err) != store.StateInsufficientPrivilege {
		t.Fatalf("reader insert: %v", err)
	}
}

// Spec 05 §4: 1-day chunks and a compression policy after 7 days; the
// policy's job compresses a backdated chunk, and the rows read back.
func TestIntegrationCompressionJobRunsOnABackdatedChunk(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	w := openWriter(t, u)
	db := storetest.Open(t, u)
	ctx := context.Background()
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	recent := time.Now().UTC()
	var interval string
	if err := db.QueryRow(`SELECT time_interval::text FROM timescaledb_information.dimensions WHERE hypertable_name = 'rid_observations'`).Scan(&interval); err != nil || interval != "1 day" {
		t.Fatalf("chunk interval %q %v", interval, err)
	}
	var job int
	var after, segment string
	if err := db.QueryRow(`SELECT job_id, config->>'compress_after' FROM timescaledb_information.jobs WHERE hypertable_name = 'rid_observations' AND proc_name = 'policy_compression'`).Scan(&job, &after); err != nil || after != "7 days" {
		t.Fatalf("compression job %d %q %v", job, after, err)
	}
	if err := db.QueryRow(`SELECT attname FROM timescaledb_information.compression_settings WHERE hypertable_name = 'rid_observations' AND segmentby_column_index = 1`).Scan(&segment); err != nil || segment != "transmitter" {
		t.Fatalf("segmentby %q %v", segment, err)
	}
	// No retention policy on rid_observations until WP-27's archive.
	var retention int
	if err := db.QueryRow(`SELECT count(*) FROM timescaledb_information.jobs WHERE hypertable_name = 'rid_observations' AND proc_name = 'policy_retention'`).Scan(&retention); err != nil || retention != 0 {
		t.Fatalf("retention policies %d %v", retention, err)
	}
	// TimescaleDB runs a new policy once at the scheduler's first pass,
	// about half a second after the scratch database's scheduler starts:
	// during this test, not during the migrations. A scheduled run beside
	// the CALL below makes one of the two fail with "chunk is already
	// compressed". Wait for that first run to finish before the
	// backdated row exists, so the CALL below is the only run that can
	// compress it; the next scheduled run is 12 hours away.
	firstRun := time.Now().Add(30 * time.Second)
	for {
		var runs int
		var status string
		if err := db.QueryRow(`SELECT total_runs, job_status || '/' || coalesce(last_run_status, '') FROM timescaledb_information.job_stats WHERE job_id = $1`, job).Scan(&runs, &status); err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		if runs >= 1 && status == "Scheduled/Success" {
			break
		}
		if time.Now().After(firstRun) {
			t.Fatalf("the scheduler's first run of job %d: %d runs, %q", job, runs, status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(1, old), ridRow(2, recent)}}); err != nil {
		t.Fatal(err)
	}
	compressed := func() (int, int) {
		var yes, no int
		if err := db.QueryRow(`SELECT count(*) FILTER (WHERE is_compressed), count(*) FILTER (WHERE NOT is_compressed) FROM timescaledb_information.chunks WHERE hypertable_name = 'rid_observations'`).Scan(&yes, &no); err != nil {
			t.Fatal(err)
		}
		return yes, no
	}
	if yes, _ := compressed(); yes != 0 {
		t.Fatalf("compressed before the job ran: %d", yes)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf(`CALL run_job(%d)`, job)); err != nil {
		t.Fatal(err)
	}
	if yes, no := compressed(); yes != 1 || no != 1 {
		t.Fatalf("after the job: %d compressed, %d not", yes, no)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM rid_observations`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows after compression %d %v", n, err)
	}
	// A redelivered row of the compressed chunk is still not written twice.
	got, err := w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(1, old)}})
	if err != nil || got[0] != (ts.Written{Duplicates: 1}) {
		t.Fatalf("into a compressed chunk: %+v %v", got, err)
	}
}

// The 24 h helper and check on a stand-in for ussp_flights (WP-14): the
// retention policy is added, the check reports nothing on a clean table
// and the rows after a backdated insert (E-01).
func TestIntegrationRetentionHelperAndCheck(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	db := storetest.Open(t, u)
	ctx := context.Background()
	for _, sql := range []string{
		`CREATE TABLE wp9_dp_probe (rx_ts timestamptz NOT NULL, flight text NOT NULL)`,
		`SELECT create_hypertable('wp9_dp_probe', by_range('rx_ts'))`,
		`SELECT authority_hypertable_policies('wp9_dp_probe', 'flight', 'rx_ts DESC', NULL, INTERVAL '24 hours')`,
		// Idempotent: a second call changes nothing and does not fail.
		`SELECT authority_hypertable_policies('wp9_dp_probe', 'flight', 'rx_ts DESC', NULL, INTERVAL '24 hours')`,
	} {
		if _, err := db.ExecContext(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var drop string
	if err := db.QueryRow(`SELECT config->>'drop_after' FROM timescaledb_information.jobs WHERE hypertable_name = 'wp9_dp_probe' AND proc_name = 'policy_retention'`).Scan(&drop); err != nil || drop != "24:00:00" && drop != "1 day" && drop != "24 hours" {
		t.Fatalf("retention policy %q %v", drop, err)
	}
	var compression int
	if err := db.QueryRow(`SELECT count(*) FROM timescaledb_information.jobs WHERE hypertable_name = 'wp9_dp_probe' AND proc_name = 'policy_compression'`).Scan(&compression); err != nil || compression != 0 {
		t.Fatalf("compression on the DP cache: %d %v", compression, err)
	}
	w := openWriter(t, u)
	if n, err := w.OlderThan(ctx, "wp9_dp_probe", "rx_ts", 24*time.Hour); err != nil || n != 0 {
		t.Fatalf("clean table: %d %v", n, err)
	}
	if _, err := w.Exec(ctx, `INSERT INTO wp9_dp_probe VALUES (now() - interval '1 hour', 'f1')`); err != nil {
		t.Fatal(err)
	}
	if n, err := w.OlderThan(ctx, "wp9_dp_probe", "rx_ts", 24*time.Hour); err != nil || n != 0 {
		t.Fatalf("recent row: %d %v", n, err)
	}
	if _, err := w.Exec(ctx, `INSERT INTO wp9_dp_probe VALUES (now() - interval '25 hours', 'f2'), (now() - interval '30 hours', 'f3')`); err != nil {
		t.Fatal(err)
	}
	if n, err := w.OlderThan(ctx, "wp9_dp_probe", "rx_ts", 24*time.Hour); err != nil || n != 2 {
		t.Fatalf("backdated rows: %d %v", n, err)
	}
	if _, err := w.OlderThan(ctx, "no_such_table", "rx_ts", time.Hour); err == nil {
		t.Fatal("a missing table checked clean")
	}
}
