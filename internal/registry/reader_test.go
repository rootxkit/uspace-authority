package registry

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

func attrs(r *ProjectionReader) map[string]slog.Value {
	out := map[string]slog.Value{}
	for _, a := range r.StatusAttrs() {
		out[a.Key] = a.Value
	}
	return out
}

// G-08, SC-17 step 6, E-02: before the first good read the reader has no
// lookup (registry_unavailable, never unidentified); a good read gives
// one; a failed read keeps the snapshot held, so no aircraft turns
// unknown; the next good read replaces it.
func TestReaderKeepsItsSnapshotThroughAFailedRead(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := newReader(f)
	if r.Lookup() != nil || attrs(r)["projection_loaded"].Bool() {
		t.Fatal("a lookup before any read")
	}
	if id := resolve(t, r, serialC1, numberA); id.Reason != core.ReasonRegistryUnavailable {
		t.Fatalf("no snapshot resolves as %+v", id)
	}
	op := f.operator(t, naturalOperator(numberA))
	f.uas(t, op.ID, serialC1, "C1")
	if err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if id := resolve(t, r, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("after the read: %+v", id)
	}
	f.proj.failBegin = true // the projection is unreadable for one refresh
	if err := r.Refresh(ctx); err == nil {
		t.Fatal("a failed read reported success")
	}
	if id := resolve(t, r, serialC1, numberA); id.Status != core.IdentRegistered {
		t.Fatalf("the failed read dropped the snapshot: %+v", id)
	}
	if r.Counters.Get(CounterReaderReadFailed) != 1 || r.Counters.Get(CounterReaderLoaded) != 1 {
		t.Errorf("counters %v", r.Counters.Snapshot())
	}
	f.proj.failBegin = false
	f.now = f.now.Add(3 * time.Second)
	a := attrs(r)
	if a["projection_age_s"].Float64() != 3 || a["projection_rows"].Int64() != 2 || a["registry_version"].Int64() != r.Version() {
		t.Fatalf("status %v", a)
	}
	if err := r.Refresh(ctx); err != nil || attrs(r)["projection_age_s"].Float64() != 0 {
		t.Fatal("the next good read did not replace the snapshot")
	}
}

// Run refreshes at once, on Notify (the push) and every period, keeps
// going through failures, and stops with its context.
func TestReaderRunRefreshesOnPushAndPeriod(t *testing.T) {
	f := newFixture(t)
	r := &ProjectionReader{Source: f.proj, Counters: &core.Counters{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx, time.Hour) }()
	waitFor(t, func() bool { return r.Counters.Get(CounterReaderLoaded) == 1 })
	r.Notify()
	waitFor(t, func() bool { return r.Counters.Get(CounterReaderLoaded) == 2 })
	cancel()
	<-done

	f.proj.failBegin = true
	r2 := &ProjectionReader{Source: f.proj, Counters: &core.Counters{}}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() { defer close(done2); r2.Run(ctx2, 10*time.Millisecond) }()
	waitFor(t, func() bool { return r2.Counters.Get(CounterReaderReadFailed) >= 2 })
	f.proj.mu.Lock()
	f.proj.failBegin = false
	f.proj.mu.Unlock()
	waitFor(t, func() bool { return r2.Lookup() != nil })
	cancel2()
	<-done2
}
