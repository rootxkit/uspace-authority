package ts_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Scratch: the test before the fix, to count its failures on CI.
func TestIntegrationScratchOldCompression(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	w := openWriter(t, u)
	db := storetest.Open(t, u)
	ctx := context.Background()
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	recent := time.Now().UTC()
	if _, err := w.Write(ctx, ts.Part{Table: ts.RIDObservations, Rows: [][]any{ridRow(1, old), ridRow(2, recent)}}); err != nil {
		t.Fatal(err)
	}
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
