package cisp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The heartbeat posts sent_at with a cis.publish:* scope every period;
// the CISP's answer is the state. With the CISP down every beat fails,
// counted and shown, never a crash; the fake CISP then marks the
// authority stale after 60 s of silence, and fresh again on the next
// beat (E-01 pair).
func TestHeartbeatStateAndTheCISPStaleness(t *testing.T) {
	w := newWorld(t)
	hb := &Heartbeat{CISP: w.client, Counters: w.outbox.Counters}
	if !hb.Beat(context.Background()) {
		t.Fatal("not sent")
	}
	st := hb.State()
	if st.LastSuccessAt == nil || st.LastStatus == nil || *st.LastStatus != http.StatusNoContent || st.ConsecutiveFailures != 0 || st.IntervalS != 15 {
		t.Fatalf("%+v", st)
	}
	var scope string
	for _, r := range w.fake.Requests() {
		if r.Path == "/v1/publishers/heartbeat" {
			scope = r.Scope
		}
	}
	if !strings.Contains(scope, "cis.publish:") {
		t.Fatalf("scope %q", scope)
	}
	beat := w.fake.Heartbeats()[0]
	if w.fake.PublisherStale(beat.Add(59 * time.Second)) {
		t.Fatal("stale before 60 s of silence")
	}
	if !w.fake.PublisherStale(beat.Add(61 * time.Second)) {
		t.Fatal("not stale after 60 s of silence")
	}
	w.fake.SetDown(true)
	for range 3 {
		hb.Beat(context.Background())
	}
	st = hb.State()
	if st.ConsecutiveFailures != 3 || st.LastStatus == nil || *st.LastStatus != http.StatusServiceUnavailable || st.LastError == "" {
		t.Fatalf("%+v", st)
	}
	if w.count(CounterHeartbeatsFailed) != 3 || w.count(CounterHeartbeats) != 1 {
		t.Fatalf("failed %d ok %d", w.count(CounterHeartbeatsFailed), w.count(CounterHeartbeats))
	}
	w.fake.SetDown(false)
	hb.Beat(context.Background())
	if st := hb.State(); st.ConsecutiveFailures != 0 || st.LastError != "" {
		t.Fatalf("%+v", st)
	}
	if last := w.fake.Heartbeats(); w.fake.PublisherStale(last[len(last)-1].Add(time.Second)) {
		t.Fatal("still stale after a beat")
	}
}

// Run beats every Interval: observed at the scaled period (the default
// is 15 s, M3); another replica holding the lock skips, counted.
func TestHeartbeatRunsEveryPeriod(t *testing.T) {
	w := newWorld(t)
	hb := &Heartbeat{CISP: w.client, Counters: w.outbox.Counters, Interval: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { hb.Run(ctx); close(done) }()
	waitFor(t, 3*time.Second, "four heartbeats", func() bool { return len(w.fake.Heartbeats()) >= 4 })
	cancel()
	<-done
	beats := w.fake.Heartbeats()
	for i := 1; i < len(beats); i++ {
		if gap := beats[i].Sub(beats[i-1]); gap < 30*time.Millisecond || gap > time.Second {
			t.Fatalf("gap %s between beats", gap)
		}
	}
	skip := &Heartbeat{CISP: w.client, Counters: w.outbox.Counters,
		Lock: func(context.Context) (func(), bool, error) { return func() {}, false, nil }}
	if skip.Beat(context.Background()) || w.count(CounterHeartbeatSkipped) != 1 {
		t.Fatal("a beat was sent without the lock")
	}
}
