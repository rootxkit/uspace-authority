package ridpipe

import (
	"errors"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
)

// T-02, I-01 (review of PR #14): the wall-clock tick must not move the
// trackers' clocks. A Basic ID and a Location heard 10 s apart in one
// batch are a silence longer than the gap: the Location stays without
// an identity, whether the batch is live or backlog, and whether a tick
// ran just before it or not. The twin (E-01): the same two messages
// 1 s apart join.
func TestTickKeepsTheSpacingOfABatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		backlog bool
		apart   time.Duration
		joined  bool
	}{
		{"live 10 s apart", false, 10 * time.Second, false},
		{"backlog 10 s apart", true, 10 * time.Second, false},
		{"live 1 s apart", false, time.Second, true},
		{"backlog 1 s apart", true, time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, rec := pipe(DefaultSettings(), Deps{})
			ingest := t0.Add(time.Minute)
			p.Tick(ingest) // the process tick just before the batch
			b := batchOf("rx-1", ingest, tc.backlog,
				rxRow("rx-1", "TX-1", frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTOLD0001"}), at(t0)),
				rxRow("rx-1", "TX-1", frame(t, loc(baseLatDeg, baseLonDeg)), at(t0.Add(tc.apart))))
			observe(t, p, b)
			if got := len(rec.tracks(t)); (got == 1) != tc.joined {
				t.Fatalf("%d tracks published, joined want %v", got, tc.joined)
			}
			if n := p.Counters().Get(CounterTrackerClockHeld); n != 0 {
				t.Fatalf("tracker_clock_held %d inside one ordered batch", n)
			}
		})
	}
}

// SC-10 replayed as backlog with the process tick running: the same
// result as live (no Location under the old serial after the restart),
// and the backlog tracker's clock is never held back by wall time.
func TestScenarioSC10ReplayedAsBacklog(t *testing.T) {
	var seed uint64
	for s := uint64(1); s < 100000; s++ {
		if _, _, ok := sc10(t, s, DefaultSettings(), false); ok {
			seed = s
			break
		}
	}
	old, newRows, held := sc10Backlog(t, seed)
	if old != 0 || newRows == 0 || held != 0 {
		t.Fatalf("seed %d replayed: %d under the old serial, %d under the new, tracker_clock_held %d", seed, old, newRows, held)
	}
}

// Review of PR #14: the per-track memories belong to one tracker. One
// poor backlog fix of an aircraft must not put its live track on
// pressure for the hold (R-08), and a backlog identification must not
// make the live track announce again on ident.v1. The twin: a poor live
// fix does put the live track on pressure.
func TestBacklogNeverTouchesTheLiveTrackMemories(t *testing.T) {
	reg := testRegistry(t)
	unavailable := false
	p, rec := pipe(DefaultSettings(), Deps{Geoid: constGeoid{15.9}, Registry: func() identify.Lookup {
		if unavailable {
			return nil
		}
		return reg()
	}})
	send := func(when time.Time, backlog bool, code uint8) {
		l := loc(baseLatDeg, baseLonDeg)
		l.VertAccuracy = code
		observe(t, p, batchOf("rx-1", when, backlog, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", l), at(when))))
	}
	send(t0, false, 4)
	unavailable = true
	send(t0.Add(500*time.Millisecond), true, 1) // a replayed poor fix, while the projection is away
	unavailable = false
	send(t0.Add(time.Second), false, 4)
	ms := rec.tracks(t)
	if last := ms[len(ms)-1]; last.Backlog || last.Body.AltSource != "geodetic" || last.Body.AltAMSLM == nil {
		t.Fatalf("live track after a backlog poor fix: %s %v", last.Body.AltSource, last.Body.AltAMSLM)
	}
	live := 0
	for _, c := range rec.idents(t) {
		if !c.Backlog {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("live identification announced %d times", live)
	}
	send(t0.Add(2*time.Second), false, 1)
	if last := rec.tracks(t); last[len(last)-1].Body.AltSource != "pressure" {
		t.Fatal("a live poor fix did not put the live track on pressure")
	}
}

// Review of PR #14: an identification is remembered as announced only
// once ident.v1 took it, so a failed publish is retried with the next
// observation instead of being lost until the identification changes.
func TestFailedIdentPublishIsRetried(t *testing.T) {
	rec := &recorder{identErr: errors.New("nats: connection closed")}
	p, _ := pipe(DefaultSettings(), Deps{Publisher: rec, Registry: testRegistry(t)})
	send := func(when time.Time) {
		observe(t, p, batchOf("rx-1", when, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg, baseLonDeg)), at(when))))
	}
	send(t0)
	if p.Counters().Get(CounterIdentPublishFailed) != 1 || len(rec.idents(t)) != 0 {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
	rec.mu.Lock()
	rec.identErr = nil
	rec.mu.Unlock()
	send(t0.Add(time.Second))
	send(t0.Add(2 * time.Second))
	if n := len(rec.idents(t)); n != 1 {
		t.Fatalf("announced %d times after the bus returned, want 1", n)
	}
}
