package detectsvc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/geodesy"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/intents"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// The no_authorisation detector and the U-space gating of height_120m
// (WP-26), in process on the simulated clock: the worker, the board
// over an in-memory DSS that places an intent wherever its box holds
// the position asked. Each raise is paired with its clear, and each
// absence with the presence beside it (INV-02, E-01). The same flow
// through NATS, TimescaleDB, PostgreSQL and the HTTP fake DSS is
// internal/violations' TestIntegrationNoAuthorisationThroughTheStack.

// memDSS is an in-memory DSS.
type memDSS struct {
	mu    sync.Mutex
	refs  map[string]f3548.OperationalIntentReference
	boxes map[string]geodesy.BBox
	err   error
}

func newMemDSS() *memDSS {
	return &memDSS{refs: map[string]f3548.OperationalIntentReference{}, boxes: map[string]geodesy.BBox{}}
}

func (d *memDSS) Query(_ context.Context, aoi f3548.Volume4D) ([]f3548.OperationalIntentReference, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	var out []f3548.OperationalIntentReference
	for id := range d.refs {
		if c := aoi.Volume.OutlineCircle; c != nil && !d.boxes[id].Contains(c.Center.LatLon()) {
			continue
		}
		out = append(out, d.refs[id])
	}
	return out, nil
}

func (d *memDSS) activate(id string, lat, lon float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refs[id] = f3548.OperationalIntentReference{Id: id, Manager: "ussp-lab-01", UssBaseUrl: "https://ussp.example.test",
		State: f3548.Activated, Version: 1, UssAvailability: f3548.Normal,
		TimeStart: f3548.Time{Format: f3548.RFC3339, Value: t0.Add(-time.Hour)}, TimeEnd: f3548.Time{Format: f3548.RFC3339, Value: t0.Add(time.Hour)}}
	d.boxes[id] = geodesy.BBox{MinLat: lat - 0.0005, MinLon: lon - 0.0005, MaxLat: lat + 0.0005, MaxLon: lon + 0.0005}
}

func (d *memDSS) end(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.refs, id)
}

func (d *memDSS) setErr(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err = err
}

// naRig is a rig with a U-space airspace around (zLat, zLon), a board
// over a memDSS on the rig's clock, and the policy given.
type naRig struct {
	*rig
	dss   *memDSS
	board *intents.Board
}

func newNARig(t *testing.T, mutate func(*policy.Thresholds)) *naRig {
	t.Helper()
	dss := newMemDSS()
	in := &fakeInputs{}
	s := intents.DefaultSettings()
	s.Recheck = time.Second
	r := &naRig{dss: dss}
	r.board = intents.NewBoard(s, dss, func() []*zones.Zone { return in.Zones().Zones }, nil)
	in.board = r.board
	base := newRig(t, nil)
	in.zs = base.in.zs
	base.in = in
	base.w = NewWorker("c3:131:224", in, func() Settings { st := DefaultSettings(); st.Now = base.clk.Now; return st }(), base.pub, nil, nil)
	r.rig = base
	r.board.Now = base.clk.Now
	in.setPolicy(1, mutate)
	in.env = groundAt(0)
	in.setZones(zoneOf(t, zoneSpec{id: "US1", typ: "USPACE", lat: zLat, lon: zLon, halfDeg: 0.01, upper: 5000}.feature())...)
	return r
}

// second is one second of the flight: the samples at t0 + sec, a board
// step, a worker tick.
func (r *naRig) second(sec float64, ss ...sample) {
	r.t.Helper()
	r.at(sec, ss...)
	r.board.Step(context.Background())
	r.tick(sec)
}

// fly runs second for every whole second in [from, to].
func (r *naRig) fly(from, to int, s func(sec int) sample) {
	r.t.Helper()
	for sec := from; sec <= to; sec++ {
		r.second(float64(sec), s(sec))
	}
}

func inUSpace(int) sample {
	return sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(100), wgs84: f64(118)}
}

func outOfUSpace(int) sample {
	return sample{id: "A", lat: zLat + 0.05, lon: zLon, altAMSL: f64(100), wgs84: f64(118)}
}

func kinds(ms []*violation.Message, kind violation.Kind) []*violation.Message {
	var out []*violation.Message
	for _, m := range ms {
		if m.Body.Kind == kind {
			out = append(out, m)
		}
	}
	return out
}

func candidateReasons(t *testing.T, b violation.Body) map[string]intents.Reason {
	t.Helper()
	cs, ok := b.Detail["candidates"].([]intents.Candidate)
	if !ok {
		t.Fatalf("candidates %T", b.Detail["candidates"])
	}
	out := map[string]intents.Reason{}
	for _, c := range cs {
		out[c.ID] = c.Reason
	}
	return out
}

// Spec 04 §3.3 (Art. 6(4)): an aircraft inside a U-space airspace with
// an Activated intent the DSS places at it raises nothing; its intent
// ended, no_authorisation is raised after the policy's grace with the
// intent considered and why it failed; leaving the airspace clears it
// resolved.
func TestNoAuthorisationRaisedAfterTheGraceAndClearedOnExit(t *testing.T) {
	r := newNARig(t, nil)
	r.dss.activate("oi-1", zLat, zLon)
	r.fly(0, 12, inUSpace)
	if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) != 0 {
		t.Fatalf("authorised flight raised %s", describe(got))
	}
	if st := r.w.noAuthStats(); st.cases != 1 || st.matched != 1 {
		t.Fatalf("matched %+v", st)
	}

	// The USSP ended it: the next position read (t=13) no longer finds it,
	// and the next airspace read (t=15) withdraws it.
	r.dss.end("oi-1")
	var raisedAt = -1
	for sec := 13; sec <= 40 && raisedAt < 0; sec++ {
		r.second(float64(sec), inUSpace(sec))
		if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) > 0 {
			raisedAt = sec
			b := got[0].Body
			if len(got) != 1 || b.State != violation.StateRaised || b.Severity != core.SeverityWarning || b.ZoneID == nil || *b.ZoneID != "GEO/US1" ||
				b.ZoneType == nil || *b.ZoneType != "USPACE" || !b.InUSpace || b.AlertKey != "no_authorisation:GEO:US1:A" || b.TrackRef != "A" ||
				b.Serial == nil || len(b.EvidenceExcerpt) == 0 || b.Detail["identity"] != intents.IdentityNotExposed || b.Detail["grace_s"] != 10.0 ||
				b.Detail["vertical_checked"] != true || b.Detail["dss_state"] != "available" {
				t.Fatalf("raise %s %+v", describe(got), b)
			}
			if rs := candidateReasons(t, b); rs["oi-1"] != intents.ReasonWithdrawn {
				t.Fatalf("reasons %v", rs)
			}
			if opened, _ := time.Parse(time.RFC3339Nano, b.OpenedAt); !opened.Equal(t0.Add(13 * time.Second)) {
				t.Fatalf("opened_at %s, want the first unmatched sample (t=13)", b.OpenedAt)
			}
		}
	}
	// Unmatched from 13; raised once unmatched for 10 s.
	if raisedAt != 23 {
		t.Fatalf("raised at %d, want 23", raisedAt)
	}

	r.fly(24, 26, inUSpace)
	if upd := kinds(r.pub.take(), violation.KindNoAuthorisation); len(upd) != 3 || upd[2].Body.State != violation.StateUpdated {
		t.Fatalf("republished %s", describe(upd))
	}
	var clearedAt = -1
	for sec := 27; sec <= 40 && clearedAt < 0; sec++ {
		r.second(float64(sec), outOfUSpace(sec))
		if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) > 0 {
			clearedAt = sec
			b := got[0].Body
			if len(got) != 1 || b.State != violation.StateCleared || *b.ClearReason != "resolved" || b.ClearingDetail["left_uspace"] != true {
				t.Fatalf("clear %s %+v", describe(got), b)
			}
		}
	}
	// Last inside at 26; the presence clears resolved after 3 s shown
	// false: at 30.
	if clearedAt != 30 {
		t.Fatalf("cleared at %d", clearedAt)
	}
	if st := r.w.noAuthStats(); st.cases != 0 {
		t.Fatalf("a case outlived the presence %+v", st)
	}
}

// A no_authorisation clears resolved once the aircraft is matched for
// clear_after_s (an intent activated late, its USSP's decision reaching
// the DSS); a match shorter than that keeps it open (hysteresis).
func TestNoAuthorisationClearedResolvedWhenAnIntentMatches(t *testing.T) {
	r := newNARig(t, nil)
	r.fly(0, 11, inUSpace)
	raised := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation)
	if len(raised) != 1 || len(candidateReasons(t, raised[0].Body)) != 0 {
		t.Fatalf("no intent at all: %s", describe(raised))
	}
	r.dss.activate("oi-late", zLat, zLon)
	var clearedAt = -1
	for sec := 12; sec <= 30 && clearedAt < 0; sec++ {
		r.second(float64(sec), inUSpace(sec))
		if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) > 0 {
			clearedAt = sec
			b := got[0].Body
			m, _ := b.ClearingDetail["matched_intent"].(intents.Candidate)
			if *b.ClearReason != "resolved" || m.ID != "oi-late" || b.ClearingDetail["off_nominal"] != false || b.ViolationID != raised[0].Body.ViolationID {
				t.Fatalf("clear %+v", b)
			}
		}
	}
	// Read at 15, matched from 15, held 3 s: 18.
	if clearedAt != 18 {
		t.Fatalf("cleared at %d", clearedAt)
	}
}

// E-02: with the DSS down the detector is suspended: it raises nothing
// however long the aircraft stays, every status says so, and when the
// DSS answers again the grace starts over and no_authorisation follows.
func TestNoAuthorisationSuspendedWhileTheDSSIsDownThenResumes(t *testing.T) {
	r := newNARig(t, nil)
	r.dss.setErr(errors.New("connection refused"))
	r.fly(0, 30, inUSpace)
	if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) != 0 {
		t.Fatalf("raised while the DSS was down: %s", describe(got))
	}
	if st := r.w.noAuthStats(); st.unknown != 1 || st.open != 0 {
		t.Fatalf("stats %+v", st)
	}
	sh := &Shared{Intents: r.board}
	if p := sh.Problems(); !slices.ContainsFunc(p, func(s string) bool { return strings.Contains(s, "no_authorisation suspended") }) || levelOf(p).String() != "ERROR" {
		t.Fatalf("problems %v", p)
	}
	r.dss.setErr(nil)
	var raisedAt = -1
	for sec := 31; sec <= 60 && raisedAt < 0; sec++ {
		r.second(float64(sec), inUSpace(sec))
		if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) > 0 {
			raisedAt = sec
		}
	}
	// The airspace re-read at 35 (Requery 5 s after the last attempt at
	// 30), unmatched from 35, raised at 45.
	if raisedAt != 45 {
		t.Fatalf("raised at %d after resuming", raisedAt)
	}
	// Down again with it open: kept open (never cleared because the DSS
	// is away), republished as suspended.
	r.dss.setErr(errors.New("connection refused"))
	r.fly(46, 60, inUSpace)
	got := kinds(r.pub.take(), violation.KindNoAuthorisation)
	if len(transitions(got, false)) != 0 || len(got) == 0 || got[len(got)-1].Body.Detail["suspended"] != true {
		t.Fatalf("while down again: %s", describe(got))
	}
}

// height_limit_in_uspace skip_when_authorised (spec 01 §7): an aircraft
// over 120 m inside U-space airspace and matched to an intent with its
// height checked is not judged against 120 m; unmatched, it is; matched
// again, its height_120m clears authorised. With evaluate, or with the
// height not checked, it is judged even when matched (E-01 pairs).
func TestHeightLimitLiftedOnlyForAnAircraftAnAuthorisationCaps(t *testing.T) {
	high := func(wgs84 *float64) func(int) sample {
		return func(int) sample { return sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(200), wgs84: wgs84} }
	}
	skip := func(th *policy.Thresholds) { th.HeightLimitInUspace = policy.HeightSkipWhenAuthorised }

	r := newNARig(t, skip)
	r.dss.activate("oi-1", zLat, zLon)
	r.fly(0, 12, high(f64(218)))
	got := transitions(r.pub.take(), false)
	// The raise waits for the first outcome, which matches: nothing is
	// raised, nothing is cleared, the condition is held.
	if h := kinds(got, violation.KindHeight120m); len(h) != 0 {
		t.Fatalf("matched: %s", describe(got))
	}
	if r.w.Counters.Get(CounterHeightLifted) == 0 || r.w.noAuthStats().heightLifted != 1 {
		t.Fatalf("lifted %v", r.w.Counters.Snapshot())
	}
	r.dss.end("oi-1")
	r.fly(13, 16, high(f64(218)))
	got = transitions(r.pub.take(), false)
	if h := kinds(got, violation.KindHeight120m); len(h) != 1 || h[0].Body.State != violation.StateRaised || r.w.Counters.Get(CounterHeightRestored) != 1 {
		t.Fatalf("unmatched: %s", describe(got))
	}
	r.dss.activate("oi-2", zLat, zLon)
	r.fly(17, 21, high(f64(218)))
	got = transitions(r.pub.take(), false)
	if h := kinds(got, violation.KindHeight120m); len(h) != 1 || *h[0].Body.ClearReason != violation.ClearReasonAuthorised {
		t.Fatalf("matched again: %s", describe(got))
	}

	// evaluate: matched and still judged.
	e := newNARig(t, nil)
	e.dss.activate("oi-1", zLat, zLon)
	e.fly(0, 6, high(f64(218)))
	if h := kinds(transitions(e.pub.take(), false), violation.KindHeight120m); len(h) != 1 || h[0].Body.State != violation.StateRaised {
		t.Fatalf("evaluate: %s", describe(h))
	}
	// skip, but no WGS84 height: the match is horizontal only.
	n := newNARig(t, skip)
	n.dss.activate("oi-1", zLat, zLon)
	n.fly(0, 6, high(nil))
	if h := kinds(transitions(n.pub.take(), false), violation.KindHeight120m); len(h) != 1 || h[0].Body.State != violation.StateRaised {
		t.Fatalf("no height checked: %s", describe(h))
	}
}

// A U-space airspace withdrawn under an open no_authorisation clears it
// reconfigured (neither resolved nor left open); the source switched off
// clears it source_disabled with the presence.
func TestNoAuthorisationClearedReconfiguredAndSourceDisabled(t *testing.T) {
	r := newNARig(t, nil)
	r.fly(0, 11, inUSpace)
	if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) != 1 {
		t.Fatalf("raise %s", describe(got))
	}
	r.in.setZones(zoneOf(t, zoneSpec{id: "OTHER", lat: zLat + 1, lon: zLon, upper: 1500}.feature())...)
	r.second(12, inUSpace(12))
	got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation)
	if len(got) != 1 || *got[0].Body.ClearReason != violation.ClearReasonReconfigured {
		t.Fatalf("airspace withdrawn: %s", describe(got))
	}

	s := newNARig(t, nil)
	s.fly(0, 11, inUSpace)
	if got := kinds(transitions(s.pub.take(), false), violation.KindNoAuthorisation); len(got) != 1 {
		t.Fatalf("raise %s", describe(got))
	}
	s.in.setSources(coresources.State{Epoch: "e1", Version: 1, Controls: []coresources.Control{{SourceType: "direct_rid", Enabled: false}}})
	s.w.SwitchSources(context.Background())
	got = kinds(transitions(s.pub.take(), false), violation.KindNoAuthorisation)
	if len(got) != 1 || *got[0].Body.ClearReason != "source_disabled" {
		t.Fatalf("source off: %s", describe(got))
	}
}

// E-02, E-01: a detector without a DSS judges no aircraft for
// no_authorisation, counts each one entering U-space airspace and says so
// at error level; with a board beside it the same aircraft is judged.
func TestNoAuthorisationNotJudgedWithoutADSS(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	r.in.setZones(zoneOf(t, zoneSpec{id: "US1", typ: "USPACE", lat: zLat, lon: zLon, halfDeg: 0.01, upper: 5000}.feature())...)
	for sec := 0; sec <= 15; sec++ {
		r.at(float64(sec), inUSpace(sec))
		r.tick(float64(sec))
	}
	if got := kinds(transitions(r.pub.take(), false), violation.KindNoAuthorisation); len(got) != 0 || r.w.Counters.Get(CounterNoAuthNotJudged) != 1 {
		t.Fatalf("no DSS: %s %v", describe(got), r.w.Counters.Snapshot())
	}
	if !hasUSpace(r.in.Zones().Zones) || hasUSpace(nil) {
		t.Fatal("hasUSpace")
	}
	j := newNARig(t, nil)
	j.fly(0, 11, inUSpace)
	if got := kinds(transitions(j.pub.take(), false), violation.KindNoAuthorisation); len(got) != 1 || j.w.Counters.Get(CounterNoAuthNotJudged) != 0 {
		t.Fatalf("with a DSS: %s", describe(got))
	}
}

// skip_when_authorised: the height_120m of an aircraft entering U-space
// airspace over the limit waits for its first authorisation outcome, so
// an authorised aircraft is never raised and cleared authorised; an
// unmatched outcome raises it at once, opened at the first sample; with
// no outcome (the DSS down) it is raised once OutcomeMaxAge has passed,
// never held for good (E-01, E-02).
func TestHeightRaiseWaitsForTheFirstAuthorisationOutcome(t *testing.T) {
	high := func(int) sample { return sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(200), wgs84: f64(218)} }
	skip := func(th *policy.Thresholds) { th.HeightLimitInUspace = policy.HeightSkipWhenAuthorised }

	// Authorised: the first sample is held, the first outcome lifts it.
	a := newNARig(t, skip)
	a.dss.activate("oi-1", zLat, zLon)
	a.at(0, high(0))
	if st := a.w.noAuthStats(); st.heightAwaiting != 1 || a.w.Counters.Get(CounterHeightAwaiting) != 1 {
		t.Fatalf("awaiting %+v %v", st, a.w.Counters.Snapshot())
	}
	if h := kinds(a.pub.take(), violation.KindHeight120m); len(h) != 0 {
		t.Fatalf("raised before the first outcome: %s", describe(h))
	}
	a.board.Step(context.Background())
	a.tick(0)
	a.fly(1, 12, high)
	if h := kinds(a.pub.take(), violation.KindHeight120m); len(h) != 0 {
		t.Fatalf("authorised: %s", describe(h))
	}
	if st := a.w.noAuthStats(); st.heightLifted != 1 || st.heightAwaiting != 0 {
		t.Fatalf("lifted %+v", st)
	}

	// Unmatched: raised with the first outcome, opened at the first sample.
	u := newNARig(t, skip)
	u.fly(0, 3, high)
	h := kinds(transitions(u.pub.take(), false), violation.KindHeight120m)
	if len(h) != 1 || h[0].Body.State != violation.StateRaised {
		t.Fatalf("unmatched: %s", describe(h))
	}
	if opened, _ := time.Parse(time.RFC3339Nano, h[0].Body.OpenedAt); !opened.Equal(t0) {
		t.Fatalf("opened_at %s, want the first sample", h[0].Body.OpenedAt)
	}
	if u.w.Counters.Get(CounterHeightAwaiting) != 1 || u.w.noAuthStats().heightAwaiting != 0 {
		t.Fatalf("awaiting %v", u.w.Counters.Snapshot())
	}

	// The DSS down: no outcome ever stands; raised at OutcomeMaxAge.
	d := newNARig(t, skip)
	d.dss.setErr(errors.New("connection refused"))
	maxAge := int(d.board.S.OutcomeMaxAge / time.Second)
	raisedAt := -1
	for sec := 0; sec <= 30 && raisedAt < 0; sec++ {
		d.second(float64(sec), high(sec))
		if h := kinds(transitions(d.pub.take(), false), violation.KindHeight120m); len(h) > 0 {
			raisedAt = sec
		}
	}
	if raisedAt != maxAge {
		t.Fatalf("raised at %d with the DSS down, want %d", raisedAt, maxAge)
	}

	// No DSS at all: nothing to wait for, raised with the first sample.
	n := newRig(t, nil)
	n.in.setPolicy(1, skip)
	n.in.setZones(zoneOf(t, zoneSpec{id: "US1", typ: "USPACE", lat: zLat, lon: zLon, halfDeg: 0.01, upper: 5000}.feature())...)
	n.in.env = groundAt(0)
	n.at(0, high(0))
	n.tick(0)
	if h := kinds(transitions(n.pub.take(), false), violation.KindHeight120m); len(h) != 1 {
		t.Fatalf("no DSS: %s", describe(h))
	}
}
