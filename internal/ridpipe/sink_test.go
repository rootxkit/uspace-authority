package ridpipe

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/track"
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

// The row's JSON names are the rid_observations columns (WP-7's and
// WP-8's), so tsdb-writer maps them one to one; the tracks rows never go
// into the queued batch.
func TestRowJSONNamesAreTheColumns(t *testing.T) {
	raw, err := json.Marshal(Row{Payload: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got))
	for k := range got {
		names = append(names, k)
	}
	slices.Sort(names)
	want := ts.RIDObservations.ColumnNames()
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("row %v, columns %v", names, want)
	}
	b, _ := json.Marshal(Batch{Tracks: make([]track.Row, 1)})
	if strings.Contains(string(b), "track") {
		t.Fatalf("tracks rows in the queued batch: %s", b)
	}
}
