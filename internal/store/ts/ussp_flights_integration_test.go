package ts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/tswriter"
)

// flightRow is one ussp_flights row as dp-poller hands it over
// (internal/dp.FlightRow's JSON), decoded by the registration.
func flightRow(t *testing.T, rx time.Time, flight string) []any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"rx_ts": rx, "dedupe_key": "network_rid:ussp-lab-01:" + flight + ":" + rx.Format(time.RFC3339Nano),
		"ussp_id": "ussp-lab-01", "uss_base_url": "https://sp.example.test", "isa_id": "isa-1", "flight_id": flight,
		"track_id": "t-" + flight, "state_ts": rx.Add(-time.Second), "provider_unknown": false,
		"flight": map[string]any{"id": flight}, "details": map[string]any{"id": flight, "operator_location": map[string]any{"position": map[string]any{"lat": 41.7, "lng": 44.8}}},
	})
	row, err := ts.USSPFlights.DecodeRow(raw)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// A-M4, CLAUDE.md rule 7, E-01: ussp_flights (timeseries 00011) takes
// dp-poller's rows once (a redelivery writes nothing twice); its
// retention policy drops one-hour chunks past 22 h every 15 minutes, so
// nothing reaches 24 h; tsdb-writer's check says clean on a clean table
// and violated, at error level and counted, on a backdated row.
func TestIntegrationUSSPFlightsDisposalAndTheTwentyFourHourCheck(t *testing.T) {
	u := storetest.Migrated(t, migrate.Timeseries)
	db := storetest.Open(t, u)
	ctx := context.Background()
	var drop, every string
	if err := db.QueryRow(`SELECT config->>'drop_after', schedule_interval::text FROM timescaledb_information.jobs
		WHERE hypertable_name = 'ussp_flights' AND proc_name = 'policy_retention'`).Scan(&drop, &every); err != nil {
		t.Fatal(err)
	}
	if drop != "22:00:00" || every != "00:15:00" {
		t.Fatalf("retention policy drop_after %q every %q", drop, every)
	}
	var chunk string
	if err := db.QueryRow(`SELECT time_interval::text FROM timescaledb_information.dimensions WHERE hypertable_name = 'ussp_flights'`).Scan(&chunk); err != nil || chunk != "01:00:00" {
		t.Fatalf("chunk interval %q %v", chunk, err)
	}

	w := openWriter(t, u)
	now := time.Now().UTC().Truncate(time.Microsecond)
	part := ts.Part{Table: ts.USSPFlights, Rows: [][]any{flightRow(t, now, "fl-1")}}
	if got, err := w.Write(ctx, part); err != nil || got[0] != (ts.Written{Inserted: 1}) {
		t.Fatalf("write: %+v %v", got, err)
	}
	if got, err := w.Write(ctx, part); err != nil || got[0] != (ts.Written{Duplicates: 1}) {
		t.Fatalf("redelivery: %+v %v", got, err)
	}
	var lat float64
	if err := db.QueryRow(`SELECT (details->'operator_location'->'position'->>'lat')::float FROM ussp_flights`).Scan(&lat); err != nil || lat != 41.7 {
		t.Fatalf("details as received: %v %v", lat, err)
	}

	var logs bytes.Buffer
	cnt := &core.Counters{}
	r := &tswriter.Retention{Store: w, Checks: tswriter.RetentionChecks, Counters: cnt, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	if got := r.Check(ctx); got["ussp_flights"] != tswriter.RetentionClean {
		t.Fatalf("clean table: %v\n%s", got, logs.String())
	}
	if _, err := w.Write(ctx, ts.Part{Table: ts.USSPFlights, Rows: [][]any{flightRow(t, now.Add(-25*time.Hour), "fl-old")}}); err != nil {
		t.Fatal(err)
	}
	if got := r.Check(ctx); got["ussp_flights"] != tswriter.RetentionViolated || cnt.Snapshot()[tswriter.CounterRetentionViolations] != 1 {
		t.Fatalf("backdated row: %v %v", got, cnt.Snapshot())
	}
	if !strings.Contains(logs.String(), `"level":"ERROR","msg":"retention violated`) {
		t.Fatalf("not said loudly:\n%s", logs.String())
	}
}
