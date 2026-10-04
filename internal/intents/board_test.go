package intents

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/zones"
)

const uLat, uLon = 41.70, 44.80

type boardRig struct {
	t   *testing.T
	b   *Board
	dss *fakeDSS
	clk *clock
	zs  []*zones.Zone
}

func newBoardRig(t *testing.T, mutate func(*Settings)) *boardRig {
	t.Helper()
	r := &boardRig{t: t, dss: newFakeDSS(), clk: &clock{now: t0}, zs: []*zones.Zone{uspaceZone("U1", uLat, uLon)}}
	s := DefaultSettings()
	if mutate != nil {
		mutate(&s)
	}
	r.b = NewBoard(s, r.dss, func() []*zones.Zone { return r.zs }, nil)
	r.b.Now = r.clk.Now
	return r
}

// at moves the clock to t0 + sec and steps.
func (r *boardRig) at(sec float64) {
	r.clk.set(t0.Add(time.Duration(sec * float64(time.Second))))
	r.b.Step(context.Background())
}

func (r *boardRig) want(id string, lat, lon float64, hae *float64) {
	r.b.Want(Query{TrackID: id, ZoneKey: "GEO/U1", Pos: core.LatLon{LatDeg: lat, LonDeg: lon}, AltHAEM: hae, At: r.clk.Now()})
}

func f64(v float64) *float64 { return &v }

// An aircraft inside an Activated intent's area matches it after the
// airspace and the position are read; one outside it does not, and says
// why (E-01). The position read carries the aircraft's height when it
// has one.
func TestBoardMatchesAnAircraftTheDSSPlacesInAnIntent(t *testing.T) {
	r := newBoardRig(t, nil)
	r.dss.put(refOf("oi-1", f3548.Activated, t0.Add(-time.Minute), t0.Add(time.Hour)), box(uLat, uLon, 0.001))
	r.at(0)
	if st, _ := r.b.State(); st != StateAvailable {
		t.Fatalf("state %s", st)
	}
	r.want("IN", uLat, uLon, f64(600))
	r.want("OUT", uLat+0.005, uLon, nil)
	r.at(1)
	in, ok := r.b.Outcome("IN")
	if !ok || !in.Matched || in.Match.ID != "oi-1" || !in.VerticalChecked {
		t.Fatalf("inside: %+v %v", in, ok)
	}
	out, ok := r.b.Outcome("OUT")
	if !ok || out.Matched || reasons(out)["oi-1"] != ReasonNotAtPosition || out.VerticalChecked {
		t.Fatalf("outside: %+v %v", out, ok)
	}
	zoneQ, pointQ := r.dss.counts()
	if zoneQ != 1 || pointQ != 2 {
		t.Fatalf("reads %d %d", zoneQ, pointQ)
	}
	var withHeight bool
	for _, a := range r.dss.aois {
		if c := a.Volume.OutlineCircle; c != nil && a.Volume.AltitudeLower != nil {
			withHeight = a.Volume.AltitudeLower.Value == 590 && a.Volume.AltitudeUpper.Value == 610 && a.Volume.AltitudeLower.Reference == f3548.W84 &&
				c.Radius.Value == 10
		}
	}
	if !withHeight {
		t.Fatal("the position read did not carry the WGS84 height and the radius")
	}
	if s := r.b.Stats(); s.Matched != 1 || s.Aircraft != 2 || s.Cached != 1 || len(s.Watched) != 1 || s.Watched[0] != "GEO/U1" {
		t.Fatalf("stats %+v", s)
	}
}

// With no intent of the airspace that could match (none, or only
// Accepted or ended ones) the board answers from the cache without a
// position read; with one that could, it reads the position.
func TestBoardAnswersFromTheCacheWhenNoIntentCouldMatch(t *testing.T) {
	r := newBoardRig(t, nil)
	r.dss.put(refOf("planned", f3548.Accepted, t0, t0.Add(time.Hour)), box(uLat, uLon, 0.001))
	r.at(0)
	r.want("A", uLat, uLon, nil)
	r.at(1)
	o, ok := r.b.Outcome("A")
	if _, pointQ := r.dss.counts(); !ok || o.Matched || pointQ != 0 || r.b.Counters.Get(CounterAnsweredFromCache) != 1 ||
		reasons(o)["planned"] != ReasonNotActivated {
		t.Fatalf("from the cache: %+v %v", o, ok)
	}
	r.dss.put(refOf("flying", f3548.Activated, t0, t0.Add(time.Hour)), box(uLat, uLon, 0.001))
	r.at(5) // the airspace re-read (Requery 5 s)
	r.want("A", uLat, uLon, nil)
	r.at(7)
	if o, _ := r.b.Outcome("A"); !o.Matched {
		t.Fatalf("after the re-read: %+v", o)
	}
	if _, pointQ := r.dss.counts(); pointQ == 0 {
		t.Fatal("no position read once an intent could match")
	}
}

// An intent ended by its USSP leaves the DSS: the next read withdraws
// it, and the aircraft is unmatched with the reason withdrawn.
func TestBoardSeesAnEndedIntentWithdrawn(t *testing.T) {
	r := newBoardRig(t, nil)
	r.dss.put(refOf("oi-1", f3548.Activated, t0, t0.Add(time.Hour)), box(uLat, uLon, 0.001))
	r.at(0)
	r.want("A", uLat, uLon, nil)
	r.at(1)
	if o, _ := r.b.Outcome("A"); !o.Matched {
		t.Fatalf("before: %+v", o)
	}
	r.dss.remove("oi-1")
	r.at(5)
	r.want("A", uLat, uLon, nil)
	r.at(5)
	o, ok := r.b.Outcome("A")
	if !ok || o.Matched || reasons(o)["oi-1"] != ReasonWithdrawn {
		t.Fatalf("after: %+v %v", o, ok)
	}
}

// E-02: the DSS taken down suspends the board (no outcome stands, the
// state says since when and why) and it resumes when the DSS answers;
// beside it the outcome while available.
func TestBoardIsSuspendedWhileTheDSSIsDown(t *testing.T) {
	r := newBoardRig(t, nil)
	r.dss.put(refOf("oi-1", f3548.Activated, t0, t0.Add(time.Hour)), box(uLat, uLon, 0.001))
	r.at(0)
	r.want("A", uLat, uLon, nil)
	r.at(1)
	if _, ok := r.b.Outcome("A"); !ok {
		t.Fatal("no outcome while available")
	}
	r.dss.fail(errDown)
	r.at(5)
	st, since := r.b.State()
	if _, ok := r.b.Outcome("A"); ok || st != StateUnavailable || !since.Equal(t0.Add(5*time.Second)) {
		t.Fatalf("down: %s %v", st, since)
	}
	if p := r.b.Problems(); len(p) != 1 || !strings.Contains(p[0], "no_authorisation suspended") || !strings.Contains(p[0], "connection refused") {
		t.Fatalf("problems %v", p)
	}
	if r.b.Counters.Get(CounterReadsFailed) != 1 {
		t.Fatal(r.b.Counters.Snapshot())
	}
	r.dss.fail(nil)
	r.at(10)
	r.want("A", uLat, uLon, nil)
	r.at(12)
	if o, ok := r.b.Outcome("A"); !ok || !o.Matched {
		t.Fatalf("resumed: %+v %v", o, ok)
	}
	if st, _ := r.b.State(); st != StateAvailable || len(r.b.Problems()) != 0 {
		t.Fatalf("resumed: %s %v", st, r.b.Problems())
	}
	// A failed position read suspends it too.
	r.dss.fail(errDown)
	r.at(14)
	if st, _ := r.b.State(); st != StateUnavailable {
		t.Fatalf("position read failed: %s", st)
	}
}

// An outcome stands OutcomeMaxAge; an aircraft no worker asks about is
// forgotten after WantTTL (counted); Forget drops one at once.
func TestBoardOutcomesAgeAndAircraftAreForgotten(t *testing.T) {
	r := newBoardRig(t, nil)
	r.at(0)
	r.want("A", uLat, uLon, nil)
	r.want("B", uLat, uLon, nil)
	r.at(1)
	if _, ok := r.b.Outcome("A"); !ok {
		t.Fatal("fresh outcome missing")
	}
	r.clk.set(t0.Add(12 * time.Second))
	if _, ok := r.b.Outcome("A"); ok {
		t.Fatal("an outcome older than OutcomeMaxAge stood")
	}
	r.b.Forget("B")
	if s := r.b.Stats(); s.Aircraft != 1 {
		t.Fatalf("after Forget %+v", s)
	}
	r.at(40)
	if s := r.b.Stats(); s.Aircraft != 0 || r.b.Counters.Get(CounterWantsExpired) != 1 {
		t.Fatalf("after WantTTL %+v %v", s, r.b.Counters.Snapshot())
	}
}

// E-10: past MaxTracks a new aircraft is refused and counted, one held is
// still updated; past ChecksPerStep the rest wait (counted) and are
// checked in the next step; past MaxZones the rest are counted.
func TestBoardBounds(t *testing.T) {
	r := newBoardRig(t, func(s *Settings) { s.MaxTracks, s.ChecksPerStep, s.MaxZones = 2, 1, 1 })
	r.zs = append(r.zs, uspaceZone("U2", uLat+1, uLon))
	r.dss.put(refOf("oi-1", f3548.Activated, t0, t0.Add(time.Hour)), box(uLat, uLon, 0.001))
	r.at(0)
	if r.b.Counters.Get(CounterZonesNotWatched) != 1 {
		t.Fatalf("zones %v", r.b.Counters.Snapshot())
	}
	r.want("A", uLat, uLon, nil)
	r.want("B", uLat, uLon, nil)
	r.want("C", uLat, uLon, nil)
	r.want("A", uLat, uLon, nil)
	if s := r.b.Stats(); s.Aircraft != 2 || r.b.Counters.Get(CounterChecksRefused) != 1 {
		t.Fatalf("aircraft %+v %v", s, r.b.Counters.Snapshot())
	}
	r.at(1)
	_, okA := r.b.Outcome("A")
	_, okB := r.b.Outcome("B")
	if !okA || okB || r.b.Counters.Get(CounterChecksDeferred) != 1 {
		t.Fatalf("one check per step: %v %v %v", okA, okB, r.b.Counters.Snapshot())
	}
	r.at(2)
	if _, ok := r.b.Outcome("B"); !ok {
		t.Fatal("the deferred aircraft was not checked next")
	}
}

// The states before any airspace, without a DSS, and before the first
// answer, each with what Problems says (E-02): nothing to say with no
// airspace in force, an error without a DSS while one is.
func TestBoardStatesAndProblems(t *testing.T) {
	r := newBoardRig(t, nil)
	if p := r.b.Problems(); len(p) != 1 || !strings.Contains(p[0], "not judged yet") {
		t.Fatalf("starting: %v", p)
	}
	r.zs = nil
	r.at(0)
	if st, _ := r.b.State(); st != StateNoUSpace || len(r.b.Problems()) != 0 {
		t.Fatalf("no airspace: %s %v", st, r.b.Problems())
	}
	if zoneQ, _ := r.dss.counts(); zoneQ != 0 {
		t.Fatal("the DSS was read with no airspace in force")
	}
	none := NewBoard(DefaultSettings(), nil, func() []*zones.Zone { return []*zones.Zone{uspaceZone("U1", uLat, uLon)} }, nil)
	none.Step(context.Background())
	if st, _ := none.State(); st != StateUnconfigured {
		t.Fatalf("unconfigured: %s", st)
	}
	if p := none.Problems(); len(p) != 1 || !strings.Contains(p[0], "no DSS") {
		t.Fatalf("unconfigured problems %v", p)
	}
	none.Zones = func() []*zones.Zone { return nil }
	if p := none.Problems(); len(p) != 0 {
		t.Fatalf("unconfigured with no airspace: %v", p)
	}
	attrs := r.b.StatusAttrs()
	if len(attrs) != 1 || attrs[0].Key != "no_authorisation" {
		t.Fatalf("status %v", attrs)
	}
}

// A U-space airspace whose box cannot be an area is counted and not read.
func TestBoardCountsAnAirspaceWithoutABox(t *testing.T) {
	r := newBoardRig(t, nil)
	r.zs[0].BBox = r.zs[0].BBox.PadM(0)
	r.zs[0].BBox.MaxLat = r.zs[0].BBox.MinLat
	r.at(0)
	if zoneQ, _ := r.dss.counts(); zoneQ != 0 || r.b.Counters.Get(CounterZoneNotBounded) != 1 {
		t.Fatalf("%d %v", zoneQ, r.b.Counters.Snapshot())
	}
}

// An aircraft in a U-space airspace the board does not read (its box
// is not an area, or it is past MaxZones) has no outcome: it would be
// judged from an empty cache and raised falsely. It is suspended and
// counted, never read from the DSS; the aircraft in the airspace read
// beside it is judged (E-01).
func TestBoardSuspendsAnAircraftInAnAirspaceItDoesNotRead(t *testing.T) {
	r := newBoardRig(t, func(s *Settings) { s.MaxZones = 1 })
	r.zs = append(r.zs, uspaceZone("U2", uLat+1, uLon))
	r.at(0)
	r.want("IN", uLat, uLon, nil)
	r.b.Want(Query{TrackID: "PAST", ZoneKey: "GEO/U2", Pos: core.LatLon{LatDeg: uLat + 1, LonDeg: uLon}, At: r.clk.Now()})
	r.at(1)
	if o, ok := r.b.Outcome("IN"); !ok || o.Matched {
		t.Fatalf("the aircraft in the airspace read: %+v %v", o, ok)
	}
	if o, ok := r.b.Outcome("PAST"); ok {
		t.Fatalf("judged in an airspace past MaxZones: %+v", o)
	}
	if r.b.Counters.Get(CounterChecksNotWatched) != 1 {
		t.Fatalf("counters %v", r.b.Counters.Snapshot())
	}

	u := newBoardRig(t, nil)
	u.zs[0].BBox.MaxLat = u.zs[0].BBox.MinLat
	u.at(0)
	if st, _ := u.b.State(); st != StateAvailable {
		t.Fatalf("state %s", st)
	}
	u.want("A", uLat, uLon, nil)
	u.at(1)
	if o, ok := u.b.Outcome("A"); ok {
		t.Fatalf("judged in an airspace without a box: %+v", o)
	}
	if zoneQ, pointQ := u.dss.counts(); zoneQ != 0 || pointQ != 0 || u.b.Counters.Get(CounterChecksNotWatched) != 1 {
		t.Fatalf("reads %d %d %v", zoneQ, pointQ, u.b.Counters.Snapshot())
	}
	// The box mended: read, and the aircraft judged.
	u.zs[0] = uspaceZone("U1", uLat, uLon)
	u.at(6)
	u.want("A", uLat, uLon, nil)
	u.at(9)
	if _, ok := u.b.Outcome("A"); !ok {
		t.Fatal("not judged once the airspace was read")
	}
}
