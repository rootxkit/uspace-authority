package ridpipe

import (
	"testing"
	"time"

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
