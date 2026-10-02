package dp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
)

// R-14: a state identical to the last published is not republished; a
// new state of the same flight is (E-01).
func TestUnchangedStateIsNotRepublished(t *testing.T) {
	clk := &clock{t: t0.Add(time.Second)}
	sp := &fakeSP{flights: []f3411.RIDFlight{flight("fl-1", state(t0, baseLatDeg, baseLonDeg))}, respTS: t0.Add(time.Second)}
	rec := &recorder{}
	e := engine(t, sp, rec, clk)
	p := NewProvider("ussp-lab-01", spBase, true, t0)
	tile := Tile{Box: box7km}
	e.Poll(context.Background(), p, tile, "isa-1")
	e.Poll(context.Background(), p, tile, "isa-1")
	if n := len(rec.published()); n != 1 {
		t.Fatalf("%d published, want 1", n)
	}
	if e.Memory.counters.Snapshot()[CounterStateUnchanged] != 1 {
		t.Fatalf("counters %v", e.Memory.counters.Snapshot())
	}
	sp.mu.Lock()
	sp.flights = []f3411.RIDFlight{flight("fl-1", state(t0.Add(time.Second), baseLatDeg+0.0001, baseLonDeg))}
	sp.respTS = t0.Add(2 * time.Second)
	sp.mu.Unlock()
	clk.add(time.Second)
	e.Poll(context.Background(), p, tile, "isa-1")
	if n := len(rec.published()); n != 2 {
		t.Fatalf("%d published after a new state, want 2", n)
	}
	if len(rec.rows) != 2 || len(rec.flights) != 2 || rec.flights[0].DedupeKey == rec.flights[1].DedupeKey {
		t.Fatalf("rows %d flights %d", len(rec.rows), len(rec.flights))
	}
	if rec.rows[0].USSPID == nil || *rec.rows[0].USSPID != "ussp-lab-01" || rec.rows[0].Trust != core.TrustProvider {
		t.Fatalf("tracks row %+v", rec.rows[0])
	}
}

// A flight in two tiles is one flight: polled in both, published once.
func TestFlightInTwoTilesIsPublishedOnce(t *testing.T) {
	clk := &clock{t: t0.Add(time.Second)}
	sp := &fakeSP{flights: []f3411.RIDFlight{flight("fl-1", state(t0, baseLatDeg, baseLonDeg))}, respTS: t0.Add(time.Second)}
	rec := &recorder{}
	e := engine(t, sp, rec, clk)
	p := NewProvider("ussp-lab-01", spBase, true, t0)
	q := Tile{Box: box7km}.Split4()
	e.Poll(context.Background(), p, q[0], "isa-1")
	e.Poll(context.Background(), p, q[1], "isa-1")
	if calls, _ := sp.count(); calls != 2 || len(rec.published()) != 1 {
		t.Fatalf("calls %d published %d", calls, len(rec.published()))
	}
}

// R-14, E-10: more flights than the response cap are cut and counted;
// at the cap nothing is.
func TestFlightsOverTheResponseCapAreCounted(t *testing.T) {
	for _, n := range []int{3, 5} {
		clk := &clock{t: t0.Add(time.Second)}
		var fl []f3411.RIDFlight
		for i := range n {
			fl = append(fl, flight("fl-"+string(rune('a'+i)), state(t0, baseLatDeg+float64(i)*0.0001, baseLonDeg)))
		}
		sp := &fakeSP{flights: fl, respTS: t0.Add(time.Second)}
		rec := &recorder{}
		e := engine(t, sp, rec, clk)
		e.S.MaxFlights = 3
		p := NewProvider("u", spBase, true, t0)
		e.Poll(context.Background(), p, Tile{Box: box7km}, "isa-1")
		if got := len(rec.published()); got != 3 {
			t.Fatalf("%d flights: %d published", n, got)
		}
		if over := p.Counters.Snapshot()[CounterFlightsTruncated]; over != uint64(n-3) {
			t.Fatalf("%d flights: %d counted over the cap", n, over)
		}
	}
}

// R-14: a 413 splits the tile into four, at most MaxSplitDepth times;
// past it the 413 is counted, the tile kept.
func TestA413SplitsTheTileUpToTheBound(t *testing.T) {
	sp := &fakeSP{err: &HTTPError{Op: "flights", Status: 413}}
	e := engine(t, sp, &recorder{}, nil)
	e.S.MaxSplitDepth = 1
	p := NewProvider("u", spBase, true, t0)
	root := Tile{Box: box7km}
	e.Poll(context.Background(), p, root, "isa-1")
	if !p.IsSplit(root.Key()) || len(e.leaves(p, root)) != 4 {
		t.Fatalf("split %v leaves %d", p.IsSplit(root.Key()), len(e.leaves(p, root)))
	}
	child := root.Split4()[0]
	e.Poll(context.Background(), p, child, "isa-1")
	if p.IsSplit(child.Key()) || len(e.leaves(p, root)) != 4 {
		t.Fatal("a tile at the bound was split")
	}
	s := p.Counters.Snapshot()
	if s[CounterPolls413] != 2 || s[CounterSplits] != 1 || s[CounterSplitsExhausted] != 1 {
		t.Fatalf("counters %v", s)
	}
}

// 05 §5: a provider slower than the F3411 p99 (3 s) is slow and polled
// at the slow rate; a fast one is polled at dp_poll_hz.
func TestSlowProviderIsPolledAtTheSlowRate(t *testing.T) {
	e := engine(t, &fakeSP{}, &recorder{}, nil)
	fast := NewProvider("fast", spBase, true, t0)
	for range 10 {
		fast.OK(200*time.Millisecond, t0, 0)
	}
	slow := NewProvider("slow", spBase, true, t0)
	for range 10 {
		slow.OK(4*time.Second, t0, 0)
	}
	if fast.Slow() || e.interval(fast) != time.Second {
		t.Fatalf("fast: slow %v interval %v", fast.Slow(), e.interval(fast))
	}
	if !slow.Slow() || e.interval(slow) != 2*time.Second || slow.Counters.Snapshot()[CounterMarkedSlow] != 1 {
		t.Fatalf("slow: slow %v interval %v counters %v", slow.Slow(), e.interval(slow), slow.Counters.Snapshot())
	}
	p95, p99 := slow.Percentiles()
	if p95 != 4*time.Second || p99 != 4*time.Second {
		t.Fatalf("p95 %v p99 %v", p95, p99)
	}
}

// R-14, E-02: a provider failing for 10 s is unavailable since its first
// failure and stays listed; a successful poll makes it available again.
func TestProviderUnavailableAfterTenSecondsOfFailures(t *testing.T) {
	p := NewProvider("u", spBase, true, t0)
	after := 10 * time.Second
	p.Failed(time.Second, t0, after)
	p.Failed(time.Second, t0.Add(9*time.Second), after)
	if !p.UnavailableSince().IsZero() {
		t.Fatal("unavailable after 9 s")
	}
	p.Failed(time.Second, t0.Add(10*time.Second), after)
	if !p.UnavailableSince().Equal(t0) {
		t.Fatalf("unavailable since %v, want %v", p.UnavailableSince(), t0)
	}
	p.OK(time.Second, t0.Add(11*time.Second), 0)
	if !p.UnavailableSince().IsZero() {
		t.Fatal("still unavailable after an answer")
	}
}

// A poll that fails is counted by cause and on the provider; the flights
// shown stay in memory (they age on the picture).
func TestPollFailuresAreCountedByCause(t *testing.T) {
	sp := &fakeSP{err: errors.New("connection refused")}
	e := engine(t, sp, &recorder{}, nil)
	p := NewProvider("u", spBase, true, t0)
	e.Poll(context.Background(), p, Tile{Box: box7km}, "isa-1")
	sp.mu.Lock()
	sp.err, sp.delay = nil, 200*time.Millisecond
	sp.mu.Unlock()
	e.S.RequestTimeout = 20 * time.Millisecond
	e.Poll(context.Background(), p, Tile{Box: box7km}, "isa-1")
	sp.mu.Lock()
	sp.delay, sp.err = 0, ErrTooLarge
	sp.mu.Unlock()
	e.Poll(context.Background(), p, Tile{Box: box7km}, "isa-1")
	s := p.Counters.Snapshot()
	if s[CounterPollsFailed] != 3 || s[CounterPollsTimedOut] != 1 || s[CounterPollsTooLarge] != 1 {
		t.Fatalf("counters %v", s)
	}
}

// R-14: details are fetched for a tile within the details diagonal (at
// most MaxDetailsPerPoll, counted beyond), never for a wider tile
// (counted); with details the flight takes its serial's track id.
func TestDetailsOnlyForSmallTilesAndBounded(t *testing.T) {
	var fl []f3411.RIDFlight
	det := map[string]*f3411.RIDFlightDetails{}
	for i := range 3 {
		id := "fl-" + string(rune('a'+i))
		fl = append(fl, flight(id, state(t0, baseLatDeg, baseLonDeg+float64(i)*0.0001)))
		det[id] = details(id, ctaSerial[:len(ctaSerial)-1]+string(rune('1'+i)), "")
	}
	sp := &fakeSP{flights: fl, respTS: t0.Add(time.Second), details: det}
	rec := &recorder{}
	e := engine(t, sp, rec, &clock{t: t0.Add(time.Second)})
	e.S.MaxDetailsPerPoll = 2
	p := NewProvider("u", spBase, true, t0)
	e.Poll(context.Background(), p, Tile{Box: box7km}, "isa-1")
	if _, n := sp.count(); n != 0 || p.Counters.Snapshot()[CounterDetailsLargeTile] != 3 {
		t.Fatalf("details fetched for a %.1f km tile: %d, counters %v", DiagonalKM(box7km), n, p.Counters.Snapshot())
	}
	e.Poll(context.Background(), p, Tile{Box: box2km}, "isa-1")
	if _, n := sp.count(); n != 2 || p.Counters.Snapshot()[CounterDetailsCapped] != 1 {
		t.Fatalf("details fetched %d, counters %v", n, p.Counters.Snapshot())
	}
	d, _ := e.Memory.Details(FlightKey{USSID: "u", FlightID: "fl-a"})
	if d == nil {
		t.Fatal("details not kept")
	}
}

// SC-16 (unit): a disabled provider gets no poller and its running ones
// stop at once; enabled again, it is polled again.
func TestDisabledProviderIsNotPolled(t *testing.T) {
	sp := &fakeSP{respTS: t0}
	g := &gate{}
	e := engine(t, sp, &recorder{}, &clock{t: t0})
	e.Gate = g
	e.Views = func(context.Context) []Box { return []Box{box2km} }
	tile, _ := TilesOf(box2km, f3411.NetMaxDisplayAreaDiagonalKm, 10)
	e.ISAs.FromSearch(tile[0].Key(), []f3411.IdentificationServiceArea{isa("isa-1", "ussp-lab-01", spBase)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Reconcile(ctx)
	if e.Pollers() != 1 || len(e.Providers()) != 1 {
		t.Fatalf("pollers %d providers %d", e.Pollers(), len(e.Providers()))
	}
	g.set("ussp-lab-01", true)
	e.Reconcile(ctx)
	if e.Pollers() != 0 {
		t.Fatalf("pollers %d after disabling", e.Pollers())
	}
	if e.Providers()[0].Counters.Snapshot()[CounterPollsDisabled] == 0 {
		t.Fatal("stop not counted")
	}
	g.set("ussp-lab-01", false)
	e.Reconcile(ctx)
	if e.Pollers() != 1 {
		t.Fatalf("pollers %d after enabling", e.Pollers())
	}
	cancel()
	e.wg.Wait()
}

// R-14: at most MaxTilesPerSP tiles per provider, the rest counted; a
// provider whose base URL is plain http to a non-loopback host, or whose
// owner is not a subject token, is never polled (counted); one not
// certified is polled and shown provider_unknown.
func TestProviderBoundsAndRefusals(t *testing.T) {
	e := engine(t, &fakeSP{respTS: t0}, &recorder{}, &clock{t: t0})
	e.S.MaxTilesPerSP = 2
	wide := Box{MinLat: 41.6, MinLon: 44.7, MaxLat: 41.7, MaxLon: 44.8}
	e.Views = func(context.Context) []Box { return []Box{wide} }
	tiles, _ := TilesOf(wide, f3411.NetMaxDisplayAreaDiagonalKm, 100)
	if len(tiles) < 3 {
		t.Fatalf("%d tiles", len(tiles))
	}
	for _, tl := range tiles {
		e.ISAs.FromSearch(tl.Key(), []f3411.IdentificationServiceArea{
			isa("isa-1", "ussp-lab-01", spBase), isa("isa-2", "ussp-plain", "http://sp.example.test"),
			isa("isa-3", "bad.owner", "https://other.example.test"),
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); e.wg.Wait() }()
	e.Reconcile(ctx)
	if e.Pollers() != 2 {
		t.Fatalf("pollers %d, want 2", e.Pollers())
	}
	ps := e.Providers()
	if len(ps) != 1 || ps[0].Known || ps[0].Counters.Snapshot()[CounterTilesCapped] == 0 {
		t.Fatalf("providers %+v", ps)
	}
	s := e.Counters.Snapshot()
	if s[CounterProviderBadURL] == 0 || s[CounterPlainHTTP] == 0 || s[CounterProviderBadID] == 0 {
		t.Fatalf("counters %v", s)
	}
	if _, err := CheckBaseURL("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("plain http to loopback refused: %v", err)
	}
}

// The policy's view diagonal is followed below the F3411 bound and
// never above it.
func TestPolicyDiagonalIsBoundedByF3411(t *testing.T) {
	e := engine(t, &fakeSP{}, &recorder{}, nil)
	e.Policy = func() (float64, float64) { return 2, 50 }
	if hz, d := e.policy(); hz != 2 || d != f3411.NetMaxDisplayAreaDiagonalKm {
		t.Fatalf("hz %v diagonal %v", hz, d)
	}
	e.Policy = func() (float64, float64) { return 1, 3 }
	if _, d := e.policy(); d != 3 {
		t.Fatalf("diagonal %v", d)
	}
}
