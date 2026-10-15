package dp_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
)

// TestIntegrationViewReaderConsoles reads the console viewports from a
// real JetStream KV bucket, as dp-poller does. The deployed reader
// refused every complete listing (it stopped the key lister a second
// time, nats: invalid subscription), so no console viewport was ever
// polled; a fake bucket could not show it.
func TestIntegrationViewReaderConsoles(t *testing.T) {
	_, js := bustest.Connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := dpviews.ConsoleBucketConfig(bustest.Name("dp_views_it"))
	kv, err := js.CreateKeyValue(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), cfg.Bucket) })
	open := func(context.Context) (jetstream.KeyValue, error) { return kv, nil }

	// An empty bucket is a complete listing of no viewport, not a failure.
	counters := &core.Counters{}
	v := &dp.ViewReader{Consoles: open, Timeout: 5 * time.Second, Counters: counters}
	v.Refresh(ctx)
	if n := counters.Get(dp.CounterViewsReadFailed); n != 0 {
		t.Fatalf("an empty bucket counted %d failed reads, want 0", n)
	}
	if _, consoles := v.Counts(); consoles != 0 {
		t.Fatalf("an empty bucket holds %d viewports", consoles)
	}

	// Presence: two consoles reported, both listed and read.
	for i, inst := range []string{"picture-ws a", "picture-ws b"} {
		c := dpviews.Console{Instance: inst, At: time.Now().UTC(),
			BBoxes: []dpviews.BBox{{44.7 + float64(i)/100, 41.6, 44.8 + float64(i)/100, 41.7}}}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kv.Put(ctx, dpviews.ConsoleKey(inst), raw); err != nil {
			t.Fatal(err)
		}
	}
	// A key without the console prefix is not a viewport.
	if _, err := kv.Put(ctx, "other", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	v.Refresh(ctx)
	if n := counters.Get(dp.CounterViewsReadFailed); n != 0 {
		t.Fatalf("a complete listing counted %d failed reads, want 0", n)
	}
	if _, consoles := v.Counts(); consoles != 2 {
		t.Fatalf("the reader holds %d viewports, want the 2 reported", consoles)
	}
	if b := v.Boxes(); len(b) != 2 {
		t.Fatalf("%d boxes to display, want 2", len(b))
	}

	// A listing cut short is a failure and keeps the viewports held.
	done, stop := context.WithCancel(ctx)
	stop()
	v.Refresh(done)
	if n := counters.Get(dp.CounterViewsReadFailed); n == 0 {
		t.Fatal("a listing under an ended context was not counted as failed")
	}
	if _, consoles := v.Counts(); consoles != 2 {
		t.Fatalf("a failed listing dropped the viewports held: %d, want 2", consoles)
	}

	// An unreachable bucket is a failure too, the viewports kept.
	before := counters.Get(dp.CounterViewsReadFailed)
	v.Consoles = func(context.Context) (jetstream.KeyValue, error) { return nil, errors.New("bus down") }
	v.Refresh(ctx)
	if counters.Get(dp.CounterViewsReadFailed) != before+1 {
		t.Fatal("an unreachable bucket was not counted as a failed read")
	}
	if _, consoles := v.Counts(); consoles != 2 {
		t.Fatalf("an unreachable bucket dropped the viewports held: %d", consoles)
	}
}
