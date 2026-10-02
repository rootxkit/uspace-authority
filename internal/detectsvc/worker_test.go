package detectsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/alerting"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

func groundAt(m float64) func(core.LatLon) zones.Env {
	return func(core.LatLon) zones.Env { return zones.Env{Ground: zones.GroundKnown, GroundM: m} }
}

// INV-03: a new zone set rebuilds the monitor; a condition the last
// sample still shows is carried on under its violation id (updated), one
// the new set does not raise is cleared reconfigured, never resolved and
// never left open.
func TestRebuildCarriesWhatHoldsAndClearsWhatDoesNotAsReconfigured(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	a := zoneOf(t, zoneSpec{id: "KEEP", lat: zLat, lon: zLon, upper: 1500}.feature())
	b := zoneOf(t, zoneSpec{id: "GONE", lat: zLat, lon: zLon, upper: 1500}.feature())
	r.in.setZones(append(a, b...)...)
	r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(500)})
	raised := transitions(r.pub.take(), false)
	if len(raised) != 2 {
		t.Fatalf("raised %s", describe(raised))
	}
	idOf := map[string]string{}
	for _, m := range raised {
		idOf[*m.Body.ZoneID] = m.Body.ViolationID
	}
	r.in.setZones(a...)
	r.tick(0.5)
	got := r.pub.take()
	var carried, gone *violation.Message
	for _, m := range got {
		switch {
		case *m.Body.ZoneID == "GEO/KEEP" && m.Body.State == violation.StateUpdated && carried == nil:
			carried = m
		case *m.Body.ZoneID == "GEO/GONE":
			gone = m
		}
	}
	if carried == nil || carried.Body.ViolationID != idOf["GEO/KEEP"] {
		t.Fatalf("not carried: %s", describe(got))
	}
	if gone == nil || gone.Body.State != violation.StateCleared || *gone.Body.ClearReason != violation.ClearReasonReconfigured || gone.Body.ViolationID != idOf["GEO/GONE"] {
		t.Fatalf("not cleared reconfigured: %s", describe(got))
	}
	// Two rebuilds: the policy and zones set before the first sample, then
	// the zone withdrawn.
	if r.w.Counters.Get(CounterMonitorRebuilt) != 2 || r.w.Counters.Get(CounterClearedReconfigured) != 1 {
		t.Fatal(r.w.Counters.Snapshot())
	}
	// The carried violation still clears resolved under the new monitor.
	for i := 1; i <= 5; i++ {
		r.at(float64(i), sample{id: "A", lat: outLat, lon: zLon, altAMSL: f64(500)})
	}
	got = transitions(r.pub.take(), false)
	if len(got) != 1 || got[0].Body.ViolationID != idOf["GEO/KEEP"] || *got[0].Body.ClearReason != "resolved" {
		t.Fatalf("carried clear %s", describe(got))
	}
}

// INV-03: the thresholds are the active policy's. A lower height limit
// activated while flying raises at once under the new policy_version; a
// re-read of the same version rebuilds nothing.
func TestPolicyActivationRebuildsWithItsThresholds(t *testing.T) {
	r := newRig(t, nil)
	r.in.env = groundAt(500)
	r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(600)})
	if got := transitions(r.pub.take(), false); len(got) != 0 {
		t.Fatalf("100 m under the default 120 m: %s", describe(got))
	}
	r.in.setPolicy(2, func(t *policy.Thresholds) { t.HeightLimitAGLM = 90 })
	r.tick(0.5)
	got := transitions(r.pub.take(), false)
	if len(got) != 1 || got[0].Body.Kind != violation.KindHeight120m || got[0].Body.PolicyVersion != 2 || got[0].Body.Detail["max_height_agl_m"] != 90.0 {
		t.Fatalf("under policy 2: %s %+v", describe(got), got)
	}
	r.tick(1)
	if n := r.w.Counters.Get(CounterMonitorRebuilt); n != 1 {
		t.Fatalf("rebuilt %d times", n)
	}
}

// E-02: with no zones and no terrain configured, nothing is judged
// wrongly as clear: the height limit is not evaluated (counted), and the
// shared inputs say on every line what is not judged. With terrain the
// same sample raises (E-01).
func TestNoZonesNoTerrainJudgesNothingAsClearAndSaysSo(t *testing.T) {
	r := newRig(t, nil)
	r.in.zs = ZoneSet{}
	r.at(0, sample{id: "HIGH", lat: zLat, lon: zLon, altAMSL: f64(5000)})
	if got := transitions(r.pub.take(), false); len(got) != 0 {
		t.Fatalf("raised without terrain: %s", describe(got))
	}
	r.w.fold()
	if r.w.MonitorCounters.Get(zones.CounterHeightNotEvaluated) != 1 {
		t.Fatal(r.w.MonitorCounters.Snapshot())
	}
	p := problems(r.in.Zones(), nil, nil, true, true)
	if len(p) != 3 {
		t.Fatalf("problems %v", p)
	}
	s := &Shared{}
	if s.Level().String() != "ERROR" || len(s.Problems()) != 3 {
		t.Fatalf("an empty Shared: %v %v", s.Level(), s.Problems())
	}
	r.in.env = groundAt(500)
	r.at(1, sample{id: "HIGH", lat: zLat, lon: zLon, altAMSL: f64(5000)})
	if got := transitions(r.pub.take(), false); len(got) != 1 || got[0].Body.Kind != violation.KindHeight120m {
		t.Fatalf("with terrain: %s", describe(got))
	}
	if p := problems(r.in.Zones(), nil, nil, false, false); len(p) != 2 {
		t.Fatalf("projections not loaded are still said: %v", p)
	}
	if p := problems(ZoneSet{ZonesLoaded: true, RestrictionsLoaded: true}, nil, nil, false, false); len(p) != 0 {
		t.Fatalf("everything judged: %v", p)
	}
}

// E-10, C-18: a flood of spoofed ids cannot clear a real violation: past
// the cap the aircraft without one are evicted, and alert holders from
// one receiver stop at its share, refused, counted and logged.
func TestCapacityFloodLeavesARealViolationOpen(t *testing.T) {
	r := newRig(t, func(s *Settings) { s.MaxAircraft = 10 })
	r.in.setPolicy(1, nil)
	r.in.setZones(zoneOf(t, zoneSpec{id: "CAP", lat: zLat, lon: zLon, upper: 1500}.feature())...)
	genuine := sample{id: "REAL", lat: zLat, lon: zLon, altAMSL: f64(500), inst: "rx-real"}
	r.at(0, genuine)
	raised := transitions(r.pub.take(), false)
	if len(raised) != 1 {
		t.Fatalf("raised %s", describe(raised))
	}
	for i := range 100 {
		r.at(0.5, sample{id: fmt.Sprintf("SPOOF-OUT-%d", i), lat: outLat, lon: zLon, altAMSL: f64(500), inst: "rx-spoof"})
	}
	for i := range 100 {
		r.at(0.6, sample{id: fmt.Sprintf("SPOOF-IN-%d", i), lat: zLat, lon: zLon, altAMSL: f64(500), inst: "rx-spoof"})
	}
	r.tick(1)
	r.w.fold()
	if r.w.MonitorCounters.Get("aircraft_evicted") == 0 || r.w.Counters.Get(CounterAircraftRefused) == 0 {
		t.Fatalf("no eviction or refusal: %v %v", r.w.MonitorCounters.Snapshot(), r.w.Counters.Snapshot())
	}
	for _, m := range r.pub.take() {
		if m.Body.TrackRef == "REAL" && m.Body.State == violation.StateCleared {
			t.Fatalf("the flood cleared the real violation: %+v", m.Body)
		}
	}
	r.at(1.5, genuine)
	r.tick(2)
	open := 0
	for _, m := range r.pub.take() {
		if m.Body.TrackRef == "REAL" && m.Body.State == violation.StateUpdated && m.Body.ViolationID == raised[0].Body.ViolationID {
			open++
		}
	}
	if open == 0 {
		t.Fatal("the real violation is no longer republished")
	}
}

// E-10: the outbox past its bound drops the oldest, counted; until then a
// failed publish keeps raises and clears in order and the next tick sends
// them (E-01: kept, then sent).
func TestOutboxKeepsOrderRetriesAndIsBounded(t *testing.T) {
	r := newRig(t, func(s *Settings) { s.OutboxMax = 2 })
	r.in.setPolicy(1, nil)
	r.in.env = groundAt(0)
	r.pub.setFail(true)
	r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(500)})
	if len(r.w.outbox) != 1 || r.w.Counters.Get(CounterPublishFailed) == 0 {
		t.Fatalf("not kept: %d %v", len(r.w.outbox), r.w.Counters.Snapshot())
	}
	r.pub.setFail(false)
	r.tick(0.5)
	got := transitions(r.pub.take(), false)
	if len(got) != 1 || got[0].Body.State != violation.StateRaised || len(r.w.outbox) != 0 {
		t.Fatalf("not sent on the tick: %s", describe(got))
	}
	r.pub.setFail(true)
	for i, id := range []string{"B", "C", "D"} {
		r.at(1+float64(i), sample{id: id, lat: zLat, lon: zLon, altAMSL: f64(500)})
	}
	if len(r.w.outbox) != 2 || r.w.Counters.Get(CounterOutboxDropped) != 1 || r.w.outbox[0].Body.TrackRef != "C" {
		t.Fatalf("bound: %d %v", len(r.w.outbox), r.w.Counters.Snapshot())
	}
}

// E-10: the excerpt keeps at most MaxSamples per aircraft and MaxAircraft
// in all, each past its bound counted; within them nothing is dropped.
func TestExcerptsAreBounded(t *testing.T) {
	c := &core.Counters{}
	e := NewExcerpts(10, 3, 2, c)
	for i := range 3 {
		e.Add("A", float64(i), violation.Sample{MsgID: fmt.Sprint(i)})
	}
	if len(e.Window("A", -1, 100)) != 3 || c.Get(CounterExcerptSamplesDropped) != 0 {
		t.Fatal("dropped within the bound")
	}
	e.Add("A", 3, violation.Sample{MsgID: "3"})
	if w := e.Window("A", -1, 100); len(w) != 3 || w[0].MsgID != "1" || c.Get(CounterExcerptSamplesDropped) != 1 {
		t.Fatalf("per aircraft %v %v", w, c.Snapshot())
	}
	e.Add("A", 30, violation.Sample{MsgID: "30"})
	if w := e.Window("A", -1, 100); len(w) != 1 {
		t.Fatalf("the window did not move: %v", w)
	}
	e.Add("B", 0, violation.Sample{})
	e.Add("C", 0, violation.Sample{})
	if e.Len() != 2 || c.Get(CounterExcerptAircraftEvicted) != 1 || len(e.Window("A", -1, 100)) != 0 {
		t.Fatalf("aircraft bound %d %v", e.Len(), c.Snapshot())
	}
}

// D5, Q-A9: a conflict is never a violation; it is counted. With
// SkipConflicts the monitor raises none, so the branch is driven with a
// synthetic event, beside a zone raise that is published (E-01).
func TestConflictEventsAreCountedAndDropped(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	r.in.env = groundAt(0)
	r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(500)})
	if got := transitions(r.pub.take(), false); len(got) != 1 {
		t.Fatalf("height raise %s", describe(got))
	}
	conflict := alerting.Alert{Key: "conflict:A:B", Kind: alerting.KindConflict, Severity: core.SeverityCritical, Aircraft: []string{"A", "B"}}
	r.w.handle(alerting.Events{Raised: []alerting.Alert{conflict}, Cleared: []alerting.Cleared{{Alert: conflict, Reason: alerting.ClearResolved}}})
	if got := r.pub.take(); len(got) != 0 || r.w.Counters.Get(CounterConflictIgnored) != 2 {
		t.Fatalf("conflict published %s %v", describe(got), r.w.Counters.Snapshot())
	}
	if !r.w.mon.Config().SkipConflicts {
		t.Fatal("conflicts are judged")
	}
}

// A U-space airspace is presence, not a violation: a USPACE zone raises
// none, and a height violation inside it says in_uspace.
func TestUSpacePresenceIsRecordedOnViolationsNotRaised(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	r.in.env = groundAt(0)
	r.in.setZones(zoneOf(t, zoneSpec{id: "US1", typ: "USPACE", lat: zLat, lon: zLon, upper: 5000}.feature())...)
	r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(100)})
	if got := transitions(r.pub.take(), false); len(got) != 0 || r.w.Counters.Get(CounterUSpacePresence) != 1 {
		t.Fatalf("U-space presence raised %s", describe(got))
	}
	r.at(1, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(200)})
	got := transitions(r.pub.take(), false)
	if len(got) != 1 || got[0].Body.Kind != violation.KindHeight120m || !got[0].Body.InUSpace {
		t.Fatalf("height in U-space %s %+v", describe(got), got)
	}
	r.at(2, sample{id: "B", lat: outLat, lon: zLon, altAMSL: f64(200)})
	got = transitions(r.pub.take(), false)
	if len(got) != 1 || got[0].Body.InUSpace {
		t.Fatalf("height outside U-space %+v", got)
	}
}

// T11, E-01: a malformed or refused trk.v1 message is never judged and
// is counted; a valid one is.
func TestHandleDataRefusesWhatTheSchemaRefuses(t *testing.T) {
	r := newRig(t, nil)
	if r.w.HandleData([]byte("{")) || r.w.Counters.Get(CounterTrackMalformed) != 1 {
		t.Fatal("malformed accepted")
	}
	m := message(t, sample{id: "A", lat: zLat, lon: zLon}, t0)
	m.Body.Source = track.SourceSITL
	raw, _ := json.Marshal(m)
	if r.w.HandleData(raw) || r.w.Counters.Get(CounterTrackRefused) != 1 {
		t.Fatal("sitl accepted")
	}
	m.Body.Source = track.SourceDirectRID
	raw, _ = json.Marshal(m)
	if !r.w.HandleData(raw) || r.w.Counters.Get(CounterTrackObserved) != 1 {
		t.Fatal("a valid track refused")
	}
}

// C-08: an active violation is republished every tick with its current
// numbers and only the samples since its last publication.
func TestRepublishCarriesCurrentNumbersAndNewSamplesOnly(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	r.in.env = groundAt(0)
	r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(150)})
	raised := r.pub.take()
	if len(raised) != 1 || len(raised[0].Body.EvidenceExcerpt) != 1 {
		t.Fatalf("raise %s", describe(raised))
	}
	r.at(0.5, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(170)})
	r.tick(0.6)
	up := r.pub.take()
	if len(up) != 1 || up[0].Body.State != violation.StateUpdated || len(up[0].Body.EvidenceExcerpt) != 1 ||
		up[0].Body.EvidenceExcerpt[0].AltAMSLM == nil || *up[0].Body.EvidenceExcerpt[0].AltAMSLM != 170 ||
		up[0].Body.Peak.Value != 170 || up[0].Body.ViolationID != raised[0].Body.ViolationID {
		t.Fatalf("update %+v", up)
	}
	r.tick(1.6)
	if again := r.pub.take(); len(again) != 1 || len(again[0].Body.EvidenceExcerpt) != 0 {
		t.Fatalf("second update repeated samples: %+v", again)
	}
}

// R-09: a pressure altitude is judged as indicated with the pressure
// margin, flagged vertical_known false; a track without a status is
// judged as Undeclared, airborne.
func TestMappingPressureAltitudeAndAbsentStatus(t *testing.T) {
	c := &core.Counters{}
	m := message(t, sample{id: "P", lat: zLat, lon: zLon, altSrc: core.AltPressure, press: f64(700)}, t0)
	m.Body.Status = nil
	tm, err := TimesOf(m)
	if err != nil {
		t.Fatal(err)
	}
	tr := ToTrack(m, tm, zones.Env{}, c)
	if tr.AltAMSLM == nil || *tr.AltAMSLM != 700 || tr.AltSource != core.AltPressure || tr.Flying == nil || !*tr.Flying ||
		c.Get(CounterPressureAltitude) != 1 || c.Get(CounterStatusAbsent) != 1 || tr.Station != "rx-1" || tr.Source != "direct_rid" {
		t.Fatalf("%+v %v", tr, c.Snapshot())
	}
	g := message(t, sample{id: "G", lat: zLat, lon: zLon, altAMSL: f64(1), status: onGround()}, t0)
	if tr := ToTrack(g, tm, zones.Env{}, c); *tr.Flying || tr.SourceTS == nil || tr.AltSource != core.AltGeodetic {
		t.Fatalf("on the ground %+v", tr)
	}
	n := message(t, sample{id: "N", lat: zLat, lon: zLon, altSrc: core.AltNone, altAMSL: f64(1)}, t0)
	if tr := ToTrack(n, tm, zones.Env{}, c); tr.AltAMSLM != nil {
		t.Fatalf("alt_source none carried an altitude %+v", tr)
	}
}

// The message is refused by its own validation when it breaks the
// schema's rules (E-01: each refusal beside the accepted message).
func TestValidateRefusesAndAccepts(t *testing.T) {
	ok := func() *violation.Message {
		b := violation.Body{ViolationID: "01KAAAAAAAAAAAAAAAAAAAAAAA", Kind: violation.KindZoneIncursion, State: violation.StateRaised, Severity: core.SeverityCritical,
			AlertKey: "zone:GEO:Z:A", TrackRef: "A", Cell5: "c5:1317:2248", Detail: map[string]any{}}
		env := violation.Message{Schema: violation.Schema, MsgID: "01KAAAAAAAAAAAAAAAAAAAAAAA", Body: b}
		return &env
	}
	if err := violation.Validate(ok()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*violation.Message){
		"schema":       func(m *violation.Message) { m.Schema = "x" },
		"msg_id":       func(m *violation.Message) { m.MsgID = "x" },
		"violation_id": func(m *violation.Message) { m.Body.ViolationID = "x" },
		"kind":         func(m *violation.Message) { m.Body.Kind = "no_authorisation" },
		"state":        func(m *violation.Message) { m.Body.State = "x" },
		"severity":     func(m *violation.Message) { m.Body.Severity = "x" },
		"track_ref":    func(m *violation.Message) { m.Body.TrackRef = "" },
		"clear":        func(m *violation.Message) { m.Body.State = violation.StateCleared },
		"reason":       func(m *violation.Message) { m.Body.ClearReason = strp("resolved") },
		"policy":       func(m *violation.Message) { m.Body.PolicyVersion = -1 },
	}
	for name, mutate := range cases {
		m := ok()
		mutate(m)
		if violation.Validate(m) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	m := ok()
	m.Body.State, m.Body.ClearReason, m.Body.ClosedAt = violation.StateCleared, strp("stale"), strp("2026-10-01T00:00:00.000Z")
	if err := violation.Validate(m); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(m)
	if d, err := violation.Decode(raw); err != nil || d.Body.ViolationID != m.Body.ViolationID {
		t.Fatal(err)
	}
	if _, err := violation.Decode([]byte("[")); err == nil {
		t.Fatal("decoded garbage")
	}
}

// T-01: the monitor's clock never goes back with the process clock.
func TestWallClockNeverGoesBack(t *testing.T) {
	r := newRig(t, nil)
	r.clk.set(t0.Add(10 * time.Second))
	a := r.w.wallS()
	r.clk.set(t0)
	if b := r.w.wallS(); b != a {
		t.Fatalf("went back: %v -> %v", a, b)
	}
}

// hangPub is a bus that does not answer: every publish waits for its
// context (a NATS outage as JetStream's publish sees it).
type hangPub struct{ calls int }

func (p *hangPub) PublishViolation(ctx context.Context, _ *violation.Message) error {
	p.calls++
	<-ctx.Done()
	return ctx.Err()
}

// C-08, B-08: a bus outage never stalls the tick. With many active
// violations and a bus that does not answer, one tick costs at most one
// publish timeout, not one per violation; when the bus answers again
// every violation is republished, none starved (E-01).
func TestRepublishDuringABusOutageNeverStallsTheTick(t *testing.T) {
	const n = 12
	timeout := 100 * time.Millisecond
	r := newRig(t, func(s *Settings) { s.PublishTimeout = timeout })
	r.in.setPolicy(1, nil)
	r.in.env = groundAt(0)
	var ss []sample
	for i := range n {
		ss = append(ss, sample{id: fmt.Sprintf("H%02d", i), lat: zLat, lon: zLon + float64(i)*0.01, altAMSL: f64(300)})
	}
	r.at(0, ss...)
	if got := transitions(r.pub.take(), false); len(got) != n {
		t.Fatalf("raised %s", describe(got))
	}
	hang := &hangPub{}
	r.w.pub = hang
	start := time.Now()
	r.tick(1)
	if d := time.Since(start); d > 3*timeout {
		t.Fatalf("one tick with the bus down took %v for %d violations (publish timeout %v)", d, n, timeout)
	}
	if r.w.Counters.Get(CounterRepublishDeferred) == 0 {
		t.Fatal(r.w.Counters.Snapshot())
	}
	r.w.pub = r.pub
	r.tick(2)
	seen := map[string]bool{}
	for _, m := range r.pub.take() {
		if m.Body.State == violation.StateUpdated {
			seen[m.Body.TrackRef] = true
		}
	}
	if len(seen) != n {
		t.Fatalf("republished %d of %d after the outage", len(seen), n)
	}
}

// INV-03, T-05, T-10: a rebuild re-observes each aircraft's last sample
// at the wall time it was first observed, never at the rebuild's. An
// aircraft quiet for longer than live_max_age_s but not yet stale keeps
// its violation (carried, then cleared stale when its time comes, not
// reconfigured); one whose last sample the store no longer holds
// (evicted) is closed stale, since nothing says the new configuration
// would not raise it. An aircraft heard recently is carried as before.
func TestRebuildReobservesAtPlacedTimeAndClosesQuietAircraftStale(t *testing.T) {
	t.Run("quiet", func(t *testing.T) {
		r := newRig(t, nil)
		r.in.setPolicy(1, nil)
		keep := zoneOf(t, zoneSpec{id: "KEEP", lat: zLat, lon: zLon, upper: 1500}.feature())
		r.in.setZones(keep...)
		r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(500)}, sample{id: "B", lat: zLat, lon: zLon, altAMSL: f64(500)})
		raised := transitions(r.pub.take(), false)
		if len(raised) != 2 {
			t.Fatalf("raised %s", describe(raised))
		}
		r.at(11, sample{id: "B", lat: zLat, lon: zLon, altAMSL: f64(500)})
		other := zoneOf(t, zoneSpec{id: "OTHER", lat: outLat + 1, lon: zLon, upper: 1500}.feature())
		r.in.setZones(append(keep, other...)...)
		r.tick(12)
		if got := transitions(r.pub.take(), false); len(got) != 0 {
			t.Fatalf("rebuild closed what still holds: %s", describe(got))
		}
		if n := r.w.Counters.Get(CounterClearedReconfigured); n != 0 {
			t.Fatalf("cleared reconfigured %d", n)
		}
		r.tick(16)
		got := transitions(r.pub.take(), false)
		if len(got) != 1 || got[0].Body.TrackRef != "A" || *got[0].Body.ClearReason != string(alerting.ClearStale) {
			t.Fatalf("A not cleared stale: %s", describe(got))
		}
	})
	t.Run("evicted", func(t *testing.T) {
		r := newRig(t, func(s *Settings) { s.MaxAircraft = 2 })
		r.in.setPolicy(1, nil)
		keep := zoneOf(t, zoneSpec{id: "KEEP", lat: zLat, lon: zLon, upper: 1500}.feature())
		r.in.setZones(keep...)
		r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(500)})
		r.at(1, sample{id: "C", lat: outLat, lon: zLon, altAMSL: f64(500)}, sample{id: "D", lat: outLat, lon: zLon, altAMSL: f64(500)})
		if r.w.Counters.Get(CounterExcerptAircraftEvicted) == 0 {
			t.Fatal(r.w.Counters.Snapshot())
		}
		r.pub.take()
		r.in.setPolicy(2, nil)
		r.tick(2)
		got := transitions(r.pub.take(), false)
		if len(got) != 1 || got[0].Body.TrackRef != "A" || *got[0].Body.ClearReason != string(alerting.ClearStale) {
			t.Fatalf("evicted A not cleared stale: %s", describe(got))
		}
		if n := r.w.Counters.Get(CounterClearedReconfigured); n != 0 {
			t.Fatalf("cleared reconfigured %d", n)
		}
	})
}

// G-04, 06 §5: an operator number is kept and published as its public
// part only. A broadcast carrying the secret part (under the policy's
// registration-number pattern) never reaches violation/v1, neither on the
// violation nor in its evidence excerpt; a number without one is kept
// as broadcast (E-01).
func TestOperatorNumberIsPublishedAsItsPublicPartOnly(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, func(t *policy.Thresholds) { t.RegistrationNumberPattern = `^GEO-TEST-[A-Z0-9]{3}$` })
	r.in.setZones(zoneOf(t, zoneSpec{id: "Z", lat: zLat, lon: zLon, upper: 1500}.feature())...)
	withSecret := registered("TESTS1")
	withSecret.OperatorReg = strp("GEO-TEST-OP1-X7Q")
	withSecret.RegisteredOperatorReg = strp("GEO-TEST-OP1-X7Q")
	r.at(0, sample{id: "S", lat: zLat, lon: zLon, altAMSL: f64(500), ident: withSecret},
		sample{id: "P", lat: zLat, lon: zLon, altAMSL: f64(500)})
	r.at(0.5, sample{id: "S", lat: zLat, lon: zLon, altAMSL: f64(500), ident: withSecret})
	r.tick(1)
	ms := r.pub.take()
	if len(byKind(ms, violation.KindZoneIncursion, "S")) == 0 || len(byKind(ms, violation.KindZoneIncursion, "P")) == 0 {
		t.Fatalf("published %s", describe(ms))
	}
	for _, m := range ms {
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "X7Q") {
			t.Fatalf("the secret part was published: %s", raw)
		}
		if m.Body.State == violation.StateRaised && (m.Body.OperatorReg == nil || *m.Body.OperatorReg != "GEO-TEST-OP1") {
			t.Fatalf("operator_reg %v of %s", m.Body.OperatorReg, m.Body.TrackRef)
		}
		for _, s := range m.Body.EvidenceExcerpt {
			if s.Identification.OperatorReg == nil || *s.Identification.OperatorReg != "GEO-TEST-OP1" {
				t.Fatalf("excerpt operator_reg %v of %s", s.Identification.OperatorReg, m.Body.TrackRef)
			}
		}
	}
}

// E-02, D-04: without a DEM the height limit over the ground is not
// evaluated for any aircraft, so the status is never at info level even
// with every projection loaded and no zone needing terrain; with terrain
// nothing is said of it (E-01).
func TestNoTerrainMakesTheStatusErrorEvenWithNothingElseUnjudged(t *testing.T) {
	loaded := ZoneSet{ZonesLoaded: true, RestrictionsLoaded: true}
	p := problems(loaded, nil, nil, true, false)
	if len(p) != 1 || !strings.Contains(p[0], "height limit") || !strings.Contains(p[0], "terrain") {
		t.Fatalf("no terrain: %v", p)
	}
	if lvl := levelOf(p); lvl < slog.LevelWarn {
		t.Fatalf("status level %v without terrain", lvl)
	}
	p = problems(loaded, nil, nil, false, true)
	if len(p) != 0 {
		t.Fatalf("with terrain, no geoid and no zone needing one: %v", p)
	}
	if lvl := levelOf(p); lvl != slog.LevelInfo {
		t.Fatalf("status level %v with everything judged", lvl)
	}
}
