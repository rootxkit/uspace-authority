package cisp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func (w *world) enqueueZones(t *testing.T, features ...string) Row {
	t.Helper()
	r, err := w.outbox.Enqueue(context.Background(), DatasetZones, zoneCollection(features...), admin)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (w *world) putIfMatches() []string {
	var out []string
	for _, r := range w.fake.Requests() {
		if r.Method == http.MethodPut {
			out = append(out, r.Scope)
		}
	}
	return out
}

// 2xx: the first publication is sent against "zones:0" with the zones
// publish scope and acknowledged with the CISP's version; the next is
// sent against the acknowledged version.
func TestSenderPublishesInOrderWithIfMatchAndAcknowledges(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	r1 := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s1 := w.store.state(r1.ID)
	if s1.State != StateAcknowledged || s1.cispVersion == nil || *s1.cispVersion != 1 || s1.Attempts != 1 {
		t.Fatalf("%+v", s1)
	}
	if got := w.putIfMatches(); len(got) != 1 || got[0] != "scope:[cis.publish:zones]" {
		t.Fatalf("scopes %v", got)
	}
	r2 := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"), zoneFeature("TST002", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := w.store.state(r2.ID); s.State != StateAcknowledged || *s.cispVersion != 2 {
		t.Fatalf("%+v", s)
	}
	if v := w.fake.Current("zones"); v == nil || v.Number != 2 || len(v.Order) != 2 {
		t.Fatalf("%+v", v)
	}
	// The same bytes again: the CISP answers 200 unchanged; acknowledged
	// with the version it holds.
	r3 := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"), zoneFeature("TST002", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := w.store.state(r3.ID); s.State != StateAcknowledged || *s.cispVersion != 2 || s.lastStatus != http.StatusOK {
		t.Fatalf("%+v", s)
	}
	if w.count(CounterPublicationsAcknowledged) != 3 {
		t.Fatalf("acknowledged %d", w.count(CounterPublicationsAcknowledged))
	}
}

// 412 with another publisher's version current: a conflict, the CISP's
// version recorded, nothing overwritten, and the dataset stops there;
// the operator's next publication is sent against the version the
// conflict showed and acknowledged (E-01 pair).
func TestSenderStopsOnAConflictAndTheNextPublicationResolvesIt(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if _, err := w.fake.Publish("zones", []json.RawMessage{json.RawMessage(zoneFeature("OTH001", "SENSITIVE"))},
		zoneCollection(zoneFeature("OTH001", "SENSITIVE")), nil, "publication"); err != nil {
		t.Fatal(err)
	}
	r := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s := w.store.state(r.ID)
	if s.State != StateConflict || s.conflictVersion == nil || *s.conflictVersion != 1 || s.lastStatus != http.StatusPreconditionFailed {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(s.lastError, `"zones:0"`) || !strings.Contains(s.lastError, `"zones:1"`) {
		t.Fatalf("reason %q", s.lastError)
	}
	if v := w.fake.Current("zones"); v.Number != 1 || v.Order[0] != "OTH001" {
		t.Fatal("the CISP's version was overwritten")
	}
	// Nothing more is sent for the dataset by itself.
	puts := len(w.putIfMatches())
	if _, err := w.sender.RunOnce(ctx); err != nil || len(w.putIfMatches()) != puts {
		t.Fatalf("%v: a conflict was sent again", err)
	}
	next := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := w.store.state(next.ID); s.State != StateAcknowledged || *s.cispVersion != 2 {
		t.Fatalf("%+v", s)
	}
	if w.count(CounterPublicationsConflict) != 1 {
		t.Fatal("the conflict was not counted")
	}
}

// 412 whose current version holds this row's own bytes (an attempt that
// landed but whose answer was lost): acknowledged, not a conflict.
func TestSenderAcknowledgesA412ThatHoldsItsOwnBytes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	payload := zoneCollection(zoneFeature("TST001", "SENSITIVE"))
	if _, err := w.fake.Publish("zones", []json.RawMessage{json.RawMessage(zoneFeature("TST001", "SENSITIVE"))}, payload, nil, "publication"); err != nil {
		t.Fatal(err)
	}
	r, err := w.outbox.Enqueue(ctx, DatasetZones, payload, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := w.store.state(r.ID); s.State != StateAcknowledged || *s.cispVersion != 1 {
		t.Fatalf("%+v", s)
	}
	if w.count(CounterPublicationsAckAfter412) != 1 || w.count(CounterPublicationsConflict) != 0 {
		t.Fatal("counted wrongly")
	}
}

// 5xx and no answer: back to pending with an exponential backoff; the
// row is sent again only when due, then acknowledged; a refusal (400)
// fails at once with the CISP's problem.
func TestSenderRetriesA5xxAndFailsARefusal(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Now()
	w.sender.Now = func() time.Time { return now }
	w.sender.BackoffMin, w.sender.BackoffMax = 2*time.Second, 5*time.Minute
	w.fake.FailPuts(http.StatusInternalServerError, http.StatusBadGateway)
	r := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	_, _ = w.sender.RunOnce(ctx)
	s := w.store.state(r.ID)
	if s.State != StatePending || s.NextRetryAt == nil || !s.NextRetryAt.Equal(now.Add(2*time.Second)) || s.lastStatus != 500 {
		t.Fatalf("%+v", s)
	}
	// Not due yet: nothing is sent.
	puts := len(w.putIfMatches())
	_, _ = w.sender.RunOnce(ctx)
	if len(w.putIfMatches()) != puts {
		t.Fatal("sent before its retry time")
	}
	now = now.Add(2 * time.Second)
	_, _ = w.sender.RunOnce(ctx)
	if s := w.store.state(r.ID); s.State != StatePending || !s.NextRetryAt.Equal(now.Add(4*time.Second)) {
		t.Fatalf("second backoff %+v", s)
	}
	now = now.Add(4 * time.Second)
	_, _ = w.sender.RunOnce(ctx)
	if s := w.store.state(r.ID); s.State != StateAcknowledged || s.Attempts != 3 {
		t.Fatalf("%+v", s)
	}
	if w.count(CounterPublicationsRetried) != 2 {
		t.Fatalf("retried %d", w.count(CounterPublicationsRetried))
	}
	w.fake.FailPuts(http.StatusBadRequest)
	bad := w.enqueueZones(t, zoneFeature("TST009", "SENSITIVE"))
	_, _ = w.sender.RunOnce(ctx)
	if s := w.store.state(bad.ID); s.State != StateFailed || s.lastStatus != 400 || !strings.Contains(s.lastError, "forced") {
		t.Fatalf("%+v", s)
	}
}

// No answer at all (the CISP's host refuses connections) is retried.
func TestSenderRetriesWhenTheCISPIsUnreachable(t *testing.T) {
	w := newWorld(t)
	w.fake.Close()
	r := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	_, _ = w.sender.RunOnce(context.Background())
	if s := w.store.state(r.ID); s.State != StatePending || s.lastStatus != 0 || !strings.Contains(s.lastError, "no answer") {
		t.Fatalf("%+v", s)
	}
}

// The backoff doubles from its minimum and never exceeds 5 min; a row
// older than the give-up period is failed with its reason instead of
// sent.
func TestSenderBackoffBoundsAndGiveUp(t *testing.T) {
	s := &Sender{}
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	for i, d := range want {
		if got := s.Backoff(i + 1); got != d {
			t.Fatalf("attempt %d: %s", i+1, got)
		}
	}
	if got := s.Backoff(8); got != 256*time.Second {
		t.Fatalf("attempt 8: %s", got)
	}
	for _, n := range []int{9, 50, 1000} {
		if got := s.Backoff(n); got != 5*time.Minute {
			t.Fatalf("attempt %d: %s, the cap is 5 min", n, got)
		}
	}
	w := newWorld(t)
	r := w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	w.sender.Now = func() time.Time { return time.Now().Add(DefaultGiveUp + time.Minute) }
	_, _ = w.sender.RunOnce(context.Background())
	st := w.store.state(r.ID)
	if st.State != StateFailed || !strings.Contains(st.lastError, "not acknowledged within 24h0m0s") {
		t.Fatalf("%+v", st)
	}
	if len(w.putIfMatches()) != 0 {
		t.Fatal("a row past its give-up period was sent")
	}
	// A retry is never scheduled past the give-up period.
	w2 := newWorld(t)
	w2.fake.FailPuts(http.StatusServiceUnavailable)
	r2 := w2.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	base := time.Now()
	w2.sender.Now = func() time.Time { return base.Add(DefaultGiveUp - time.Second) }
	_, _ = w2.sender.RunOnce(context.Background())
	if s := w2.store.state(r2.ID); s.NextRetryAt == nil || s.NextRetryAt.Sub(s.CreatedAt) > DefaultGiveUp+time.Second {
		t.Fatalf("%+v", s)
	}
}

// Another replica holds the lock: nothing is sent and it is counted;
// the outbox unreadable is the sender's own error, counted.
func TestSenderSkipsWithoutTheLockAndCountsItsOwnFailure(t *testing.T) {
	w := newWorld(t)
	w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	w.sender.Lock = func(context.Context) (func(), bool, error) { return func() {}, false, nil }
	ran, err := w.sender.RunOnce(context.Background())
	if ran || err != nil || len(w.putIfMatches()) != 0 || w.count(CounterSenderSkipped) != 1 {
		t.Fatalf("%v %v", ran, err)
	}
	w.sender.Lock = nil
	w.store.failAt = "due"
	if _, err := w.sender.RunOnce(context.Background()); err == nil || w.count(CounterSenderErrors) != 1 || w.sender.LastError() == "" {
		t.Fatalf("%v", err)
	}
}
