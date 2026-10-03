package cisp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func zoneFeatures(ids ...string) ([]json.RawMessage, []byte) {
	var fs []json.RawMessage
	var raw []string
	for _, id := range ids {
		f := zoneFeature(id, "SENSITIVE")
		fs = append(fs, json.RawMessage(f))
		raw = append(raw, f)
	}
	return fs, zoneCollection(raw...)
}

func (w *world) publishZones(t *testing.T, signed bool, ids ...string) {
	t.Helper()
	authority, _ := rings(t)
	fs, body := zoneFeatures(ids...)
	ring := authority
	if !signed {
		ring = nil
	}
	if _, err := w.fake.Publish("zones", fs, body, ring, "publication"); err != nil {
		t.Fatal(err)
	}
}

func (w *world) gets(path string) int {
	n := 0
	for _, r := range w.fake.Requests() {
		if r.Method == "GET" && r.Path == path {
			n++
		}
	}
	return n
}

// A version is installed only when its publisher's signature verifies:
// unsigned (a version the CISP made) and signed by another publisher's
// key are held, counted and shown, the previous version kept; signed by
// the authority's key it is installed, cached and announced (E-01).
func TestPullVerifiesThePublisherSignatureOfEveryVersion(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.publishZones(t, true, "TST001")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	if v := w.sub.Current(DatasetZones); v == nil || v.Number != 1 || len(v.Features) != 1 {
		t.Fatalf("%+v", v)
	}
	if c, ok := w.cache.get(DatasetZones); !ok || c.Version != 1 || c.PublisherKID != "authority-publication-1" {
		t.Fatalf("%+v", c)
	}
	w.publishZones(t, false, "TST001", "TST002")
	err := w.sub.Pull(ctx, DatasetZones, nil)
	var ue *UntrustedError
	if !asUntrusted(err, &ue) || ue.Version != 2 || !strings.Contains(ue.Reason, "no X-Publisher-Signature") {
		t.Fatalf("%v", err)
	}
	if v := w.sub.Current(DatasetZones); v.Number != 1 {
		t.Fatal("an unsigned version was used")
	}
	st := stateOf(w.sub, DatasetZones)
	if st.HeldVersion == nil || *st.HeldVersion != 2 || st.HeldReason == "" {
		t.Fatalf("%+v", st)
	}
	_, ansp := rings(t)
	fs, body := zoneFeatures("TST001", "TST003")
	if _, err := w.fake.Publish("zones", fs, body, ansp, "publication"); err != nil {
		t.Fatal(err)
	}
	if err := w.sub.Pull(ctx, DatasetZones, nil); !asUntrusted(err, &ue) || !strings.Contains(ue.Reason, "does not verify") {
		t.Fatalf("%v", err)
	}
	w.publishZones(t, true, "TST001", "TST004")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	if v := w.sub.Current(DatasetZones); v.Number != 4 {
		t.Fatalf("version %d", v.Number)
	}
	if st := stateOf(w.sub, DatasetZones); st.HeldVersion != nil {
		t.Fatal("the held version is still shown after a trusted newer one")
	}
	if w.count(CounterUntrusted) != 2 {
		t.Fatalf("untrusted %d", w.count(CounterUntrusted))
	}
	if strings.Join(w.announcer.seen, ",") != "zones:1,zones:4" {
		t.Fatalf("announced %v", w.announcer.seen)
	}
}

func asUntrusted(err error, ue **UntrustedError) bool {
	return errors.As(err, ue)
}

func stateOf(s *Subscriber, d Dataset) CacheState {
	states := s.State()
	for i := range states {
		if states[i].Dataset == d {
			return states[i]
		}
	}
	return CacheState{}
}

// The reconciliation asks HEAD with the held ETag: unchanged is a 304
// and a confirmation; a change found there is read as the delta from
// the version held, installed and counted as a catch-up.
func TestReconcileHeadsThenReadsTheDelta(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.publishZones(t, true, "TST001", "TST002")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	gets := w.gets("/v1/zones")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	if w.count(CounterNotModified) != 1 || w.gets("/v1/zones") != gets || w.cache.touches != 1 {
		t.Fatalf("not modified %d, gets %d", w.count(CounterNotModified), w.gets("/v1/zones"))
	}
	w.publishZones(t, true, "TST002", "TST003")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	v := w.sub.Current(DatasetZones)
	if v.Number != 2 || !v.Delta || len(v.Features) != 2 || v.Features[0].Identifier != "TST002" || v.Features[1].Identifier != "TST003" {
		t.Fatalf("%+v", v)
	}
	if w.count(CounterReconcileCatchups) != 1 || w.count(CounterDeltaPulls) != 1 {
		t.Fatalf("catch-ups %d, deltas %d", w.count(CounterReconcileCatchups), w.count(CounterDeltaPulls))
	}
	var since bool
	for _, r := range w.fake.Requests() {
		if r.Path == "/v1/zones" && r.Query == "since_version=1" {
			since = true
		}
	}
	if !since {
		t.Fatal("the delta was not read with since_version")
	}
}

// A restrictions version is projected for the detectors with every
// feature's state and window; a version that fails ed318.Parse, or
// whose features lack the CISP's restriction block, is refused whole,
// counted and shown, and the projection keeps the previous version
// (T9; E-01 beside the accepted one).
func TestRestrictionsAreProjectedAndAMalformedVersionIsRefusedWhole(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	_, ansp := rings(t)
	// Before any version the CISP says no_version: a known empty set,
	// projected as version 0 with no rows.
	if err := w.sub.Pull(ctx, DatasetRestrictions, nil); err != nil {
		t.Fatal(err)
	}
	if v, rows, writes := w.projector.get(); v != 0 || len(rows) != 0 || writes != 1 {
		t.Fatalf("%d %d %d", v, len(rows), writes)
	}
	if st := stateOf(w.sub, DatasetRestrictions); st.Version == nil || *st.Version != 0 || st.Stale {
		t.Fatalf("%+v", st)
	}
	f := restrictionFeature("DAR0001", "active")
	if _, err := w.fake.Publish("restrictions", []json.RawMessage{f}, f, ansp, "restriction_created"); err != nil {
		t.Fatal(err)
	}
	if err := w.sub.Pull(ctx, DatasetRestrictions, nil); err != nil {
		t.Fatal(err)
	}
	v, rows, _ := w.projector.get()
	if v != 1 || len(rows) != 1 || rows[0].State != "active" || rows[0].ANSPRef != "TEST-DAR-1" || rows[0].USpaceAirspaceID != "TSU001" ||
		!rows[0].StartsAt.Equal(time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("%d %+v", v, rows)
	}
	cases := map[string]json.RawMessage{
		"no geometry":   json.RawMessage(`{"type":"Feature","properties":{"identifier":"BAD0001"}}`),
		"no CISP block": json.RawMessage(zoneFeature("BAD0002", "DAR")),
		"unknown block": json.RawMessage(strings.Replace(string(restrictionFeature("BAD0003", "active")), `"state":"active"`, `"state":""`, 1)),
	}
	n := uint64(0)
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := w.fake.Publish("restrictions", []json.RawMessage{f, bad}, bad, ansp, "restriction_created"); err != nil {
				t.Fatal(err)
			}
			err := w.sub.Pull(ctx, DatasetRestrictions, nil)
			var rf *RefusalError
			if !errors.As(err, &rf) {
				t.Fatalf("%v", err)
			}
			n++
			if w.count(CounterRejectedPublication) != n {
				t.Fatalf("rejected %d", w.count(CounterRejectedPublication))
			}
			if v, rows, _ := w.projector.get(); v != 1 || len(rows) != 1 {
				t.Fatal("the projection moved to a refused version")
			}
			if st := stateOf(w.sub, DatasetRestrictions); st.RefusedVersion == nil || st.RefusedReason == "" || *st.Version != 1 {
				t.Fatalf("%+v", st)
			}
		})
	}
}

// E-02: the CISP down for the whole run. Nothing held: the dataset is
// stale with no age (never an empty sky). A version held: it is served,
// its age rises past the bound and it is shown stale with the pull's
// error; the CISP back, a 304 makes it fresh again.
func TestStaleCacheIsVisibleAndRecovers(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	now := time.Now()
	w.sub.cfg.Now = func() time.Time { return now }
	w.sub.cfg.StaleBoundS = func() float64 { return 300 }
	if st := stateOf(w.sub, DatasetZones); !st.Stale || st.AgeS != nil || st.Version != nil {
		t.Fatalf("nothing pulled yet must say stale: %+v", st)
	}
	w.publishZones(t, true, "TST001")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(w.sub, DatasetZones); st.Stale || st.AgeS == nil || *st.AgeS != 0 {
		t.Fatalf("%+v", st)
	}
	w.fake.SetDown(true)
	for _, dt := range []time.Duration{time.Minute, 4 * time.Minute, 2 * time.Minute} {
		now = now.Add(dt)
		if err := w.sub.Pull(ctx, DatasetZones, nil); err == nil {
			t.Fatal("a pull from a down CISP succeeded")
		}
		w.sub.checkStale(ctx)
	}
	st := stateOf(w.sub, DatasetZones)
	if !st.Stale || st.AgeS == nil || *st.AgeS != 420 || *st.Version != 1 || !strings.Contains(st.LastError, "503") {
		t.Fatalf("%+v", st)
	}
	// The three datasets never pulled turned stale at the first check, then zones.
	if w.count(CounterStaleTransitions) != 4 || w.count(CounterPullFailed) != 3 {
		t.Fatalf("stale %d, failed %d", w.count(CounterStaleTransitions), w.count(CounterPullFailed))
	}
	w.fake.SetDown(false)
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	w.sub.checkStale(ctx)
	if st := stateOf(w.sub, DatasetZones); st.Stale || *st.AgeS != 0 || st.LastError != "" {
		t.Fatalf("%+v", st)
	}
}

// A restart serves the cached versions with their age on the database
// clock instead of none, before the first pull answers.
func TestWarmStartServesTheCachedVersionsWithTheirAge(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.publishZones(t, true, "TST001")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	c, _ := w.cache.get(DatasetZones)
	c.AgeS = 1000
	w.cache.cached[DatasetZones] = c
	fresh := NewSubscriber(SubscriberConfig{Schemas: schemas(t), Store: w.cache, Projector: w.projector})
	fresh.Warm(ctx)
	st := stateOf(fresh, DatasetZones)
	if st.Version == nil || *st.Version != 1 || st.AgeS == nil || *st.AgeS < 999 || !st.Stale {
		t.Fatalf("%+v", st)
	}
	// Without a CISP every pull fails and says why.
	if err := fresh.Pull(ctx, DatasetZones, nil); err == nil || !strings.Contains(err.Error(), "CISP_BASE_URL") {
		t.Fatalf("%v", err)
	}
}

// A notified version at or below the one held is a replay: no read.
func TestPullSkipsANotificationOfAVersionHeld(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.publishZones(t, true, "TST001")
	if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	gets := w.gets("/v1/zones")
	if err := w.sub.Pull(ctx, DatasetZones, &Hint{Version: 1}); err != nil {
		t.Fatal(err)
	}
	if w.gets("/v1/zones") != gets || w.count(CounterVersionReplays) != 1 {
		t.Fatal("a replayed notification was pulled")
	}
}

// The USSP list is read back and validated against the pinned schema in
// its served form.
func TestUSSPListIsCached(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if _, err := w.outbox.Enqueue(ctx, DatasetUSSPList, usspExample(t), admin); err != nil {
		t.Fatal(err)
	}
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.sub.Pull(ctx, DatasetUSSPList, nil); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(w.sub, DatasetUSSPList); st.Version == nil || *st.Version != 1 || st.FeatureCount == nil || *st.FeatureCount < 1 {
		t.Fatalf("%+v", st)
	}
}

// Audit A-B2, E-01: what is installed is what the publisher signed. A
// delta (or a whole served body) whose features differ from the signed
// version's is held, counted and never used, the version before kept; a
// version whose served features are the signed ones is installed (also
// through the delta).
func TestServedContentMustBeTheSignedContent(t *testing.T) {
	for _, delta := range []bool{true, false} {
		name := "whole"
		if delta {
			name = "delta"
		}
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			ctx := context.Background()
			authority, _ := rings(t)
			w.publishZones(t, true, "TST001", "TST002")
			if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
				t.Fatal(err)
			}
			if !delta {
				// Forget the version held so the next pull reads the
				// dataset whole.
				w.sub.mu.Lock()
				w.sub.st[DatasetZones].cur = nil
				w.sub.mu.Unlock()
			}
			signed := zoneCollection(zoneFeature("TST002", "SENSITIVE"), zoneFeature("TST003", "SENSITIVE"))
			served := []json.RawMessage{json.RawMessage(zoneFeature("TST002", "SENSITIVE")), json.RawMessage(zoneFeature("TST003", "DAR"))}
			if _, err := w.fake.Publish("zones", served, signed, authority, "publication"); err != nil {
				t.Fatal(err)
			}
			err := w.sub.Pull(ctx, DatasetZones, nil)
			var ue *UntrustedError
			if !asUntrusted(err, &ue) || ue.Version != 2 || !strings.Contains(ue.Reason, "TST003") {
				t.Fatalf("a served version unlike the signed one: %v", err)
			}
			if w.count(CounterSignedMismatch) != 1 || w.count(CounterUntrusted) != 1 {
				t.Fatalf("mismatch %d untrusted %d", w.count(CounterSignedMismatch), w.count(CounterUntrusted))
			}
			if v := w.sub.Current(DatasetZones); delta && (v == nil || v.Number != 1) {
				t.Fatalf("the held version moved: %+v", v)
			}
			if c, _ := w.cache.get(DatasetZones); c.Version != 1 {
				t.Fatalf("cached %d", c.Version)
			}
			// The twin: served as signed, installed.
			w.publishZones(t, true, "TST002", "TST004")
			if err := w.sub.Pull(ctx, DatasetZones, nil); err != nil {
				t.Fatal(err)
			}
			if v := w.sub.Current(DatasetZones); v == nil || v.Number != 3 || v.Delta != delta {
				t.Fatalf("the signed version was not installed: %+v", v)
			}
		})
	}
}

// Audit A-S3, E-02: the push subscription is not trusted from start-up
// for ever. The CISP losing it (a restore, a delete) is found by the
// re-check, the subscription is made again and the status shows the new
// one; while it is unchanged the re-check says nothing changed.
func TestSubscriptionIsRecheckedAndRecreated(t *testing.T) {
	w := newWorld(t)
	w.sub.cfg.CallbackURL = w.rx.URL + NotificationsPath
	w.sub.cfg.SubscriptionRecheck = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.sub.subscribeLoop(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, 5*time.Second, "the first subscription", func() bool { return w.sub.Subscription().ID != "" })
	first := w.sub.Subscription().ID
	waitFor(t, 5*time.Second, "a re-check", func() bool { return w.count(CounterSubscriptionRechecks) >= 2 })
	if w.count(CounterSubscriptionChanged) != 0 || len(w.fake.Subscriptions()) != 1 {
		t.Fatalf("an unchanged subscription: changed %d, %d at the CISP", w.count(CounterSubscriptionChanged), len(w.fake.Subscriptions()))
	}
	w.fake.DropSubscriptions()
	waitFor(t, 5*time.Second, "the subscription made again", func() bool {
		return len(w.fake.Subscriptions()) == 1 && w.sub.Subscription().ID != first
	})
	if w.count(CounterSubscriptionChanged) == 0 {
		t.Fatal("the change was not counted")
	}
	if st := w.sub.Subscription(); st.ID != w.fake.Subscriptions()[0].ID || st.Status != "active" {
		t.Fatalf("status %+v", st)
	}
}
