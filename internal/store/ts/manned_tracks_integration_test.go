package ts_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// mannedRow is one manned_tracks row as manned-ingest hands it over
// (internal/manned.Row's JSON), decoded by the registration.
func mannedRow(t *testing.T, sourceAt, placed time.Time, state string, wgs84 any) []any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"source_captured_at": sourceAt, "captured_at": placed,
		"dedupe_key": "ansp_feed:adsb-tbs:4ca7b5:" + sourceAt.Format(time.RFC3339Nano) + ":" + state,
		"msg_id": "01K6N5SXS5AA819X9YP981068V", "source_msg_id": nil, "ts": nil, "rx_ts": placed, "time_source": "provider",
		"backlog": false, "icao24": "4ca7b5", "callsign": "TST123", "lat_deg": 41.721, "lon_deg": 44.793,
		"alt_pressure_m": 1524, "alt_wgs84_m": wgs84, "gs_ms": 72.5, "track_deg": 134, "vrate_ms": -2.5,
		"emergency": false, "spi": nil, "squawk": "4521", "source_class": "ads_b", "quality": map[string]any{"nic": 8},
		"trust": "surveillance", "source": "ansp_feed", "source_instance": "adsb-tbs", "state": state,
		"relevant": true, "policy_version": "1", "cell5": nil,
	})
	row, err := ts.MannedTracks.DecodeRow(raw)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// A-M4, E-02, B-05: manned_tracks (timeseries 00012) takes a sample
// once however often it is delivered, even when this system placed it
// at another instant (the snapshot after a reconnection or a restart);
// the same sample in another state (stale) is a row of its own; the two
// altitudes stay apart, the geometric one null when the source gave
// none; the table is compressed after 7 days, segmented by icao24.
func TestIntegrationMannedTracksDedupeAndPolicies(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	db := storetest.Open(t, u)
	w := openWriter(t, u)
	ctx := context.Background()
	sourceAt := time.Now().UTC().Truncate(time.Millisecond)
	placed := sourceAt.Add(300 * time.Millisecond)

	first := ts.Part{Table: ts.MannedTracks, Rows: [][]any{mannedRow(t, sourceAt, placed, "live", 1561)}}
	if got, err := w.Write(ctx, first); err != nil || got[0] != (ts.Written{Inserted: 1}) {
		t.Fatalf("write: %+v %v", got, err)
	}
	// The same sample placed 40 ms later after a reconnection.
	again := ts.Part{Table: ts.MannedTracks, Rows: [][]any{mannedRow(t, sourceAt, placed.Add(40*time.Millisecond), "live", 1561)}}
	if got, err := w.Write(ctx, again); err != nil || got[0] != (ts.Written{Duplicates: 1}) {
		t.Fatalf("the same sample placed again: %+v %v", got, err)
	}
	stale := ts.Part{Table: ts.MannedTracks, Rows: [][]any{mannedRow(t, sourceAt, placed, "stale", nil)}}
	if got, err := w.Write(ctx, stale); err != nil || got[0] != (ts.Written{Inserted: 1}) {
		t.Fatalf("the sample's stale state: %+v %v", got, err)
	}
	var n, nullWGS int
	var pressure float64
	if err := db.QueryRow(`SELECT count(*), count(*) FILTER (WHERE alt_wgs84_m IS NULL), max(alt_pressure_m) FROM manned_tracks`).Scan(&n, &nullWGS, &pressure); err != nil {
		t.Fatal(err)
	}
	if n != 2 || nullWGS != 1 || pressure != 1524 {
		t.Fatalf("rows %d, without a geometric altitude %d, pressure %v", n, nullWGS, pressure)
	}
	var segment string
	if err := db.QueryRow(`SELECT attname FROM timescaledb_information.compression_settings
		WHERE hypertable_name = 'manned_tracks' AND segmentby_column_index = 1`).Scan(&segment); err != nil || segment != "icao24" {
		t.Fatalf("segmentby %q %v", segment, err)
	}
	var policies int
	if err := db.QueryRow(`SELECT count(*) FROM timescaledb_information.jobs
		WHERE hypertable_name = 'manned_tracks' AND proc_name = 'policy_retention'`).Scan(&policies); err != nil || policies != 0 {
		t.Fatalf("a retention policy before the archive (WP-27): %d %v", policies, err)
	}
	// A row the table's checks refuse: the state is a closed list.
	bad := ts.Part{Table: ts.MannedTracks, Rows: [][]any{mannedRow(t, sourceAt.Add(time.Second), placed, "lost", nil)}}
	if _, err := w.Write(ctx, bad); err == nil || !ts.IsDataError(err) {
		t.Fatalf("state lost written: %v", err)
	}
}
