package ridpipe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

// The stand-in Sink decodes nothing and says so in a counter, row by row
// (E-02: the build without WP-8 does not look like an empty sky).
func TestUndecodedCountsEveryRow(t *testing.T) {
	c := &core.Counters{}
	b := &Batch{Rows: make([]Row, 3)}
	if err := (Undecoded{Counters: c}).Observe(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if c.Get(CounterNotDecoded) != 3 {
		t.Fatalf("counted %d", c.Get(CounterNotDecoded))
	}
	if err := (Undecoded{}).Observe(context.Background(), b); err != nil {
		t.Fatal("nil counters must not fail")
	}
}

// The row's JSON names are the rid_observations columns, so tsdb-writer
// maps them one to one.
func TestRowJSONNamesAreTheColumns(t *testing.T) {
	raw, err := json.Marshal(Row{Payload: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"ingest_ts", "frame_id", "receiver_id", "transmitter", "rx_ts", "msg_type", "payload",
		"payload_sha256", "rssi_dbm", "backlog", "receiver_lat_deg", "receiver_lon_deg", "receiver_alt_hae_m", "sent_at_ms", "nonce"} {
		if !strings.Contains(string(raw), `"`+col+`":`) {
			t.Errorf("column %s missing from %s", col, raw)
		}
	}
}
