package ridpipe

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"
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

// S-35 (review of PR #14): when a receiver borrows another receiver's
// fresh identity (I-03), the stored track names the receiver that lent
// it; a track identified by its own receiver names that receiver, and
// an unidentified one names none.
func TestIdentityReceiverIsStored(t *testing.T) {
	s := DefaultSettings()
	s.Tracker.IdentifyWithinS = -1
	p, _ := pipe(s, Deps{})
	observe(t, p, batchOf("rx-A", t0, false, rxRow("rx-A", "TX-1", frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTREG0001"}), at(t0))))
	now := t0.Add(time.Second)
	borrowed := batchOf("rx-B", now, false, rxRow("rx-B", "TX-1", frame(t, loc(baseLatDeg, baseLonDeg)), at(now)))
	observe(t, p, borrowed)
	own := batchOf("rx-A", now, false, rxRow("rx-A", "TX-1", frame(t, loc(baseLatDeg, baseLonDeg)), at(now)))
	observe(t, p, own)
	none := batchOf("rx-C", now, false, rxRow("rx-C", "TX-9", frame(t, loc(baseLatDeg, baseLonDeg)), at(now)))
	observe(t, p, none)
	for _, tc := range []struct {
		b    *Batch
		want any
	}{{borrowed, "rx-A"}, {own, "rx-A"}, {none, nil}} {
		if len(tc.b.Tracks) != 1 {
			t.Fatalf("%s: %d rows", tc.b.ReceiverID, len(tc.b.Tracks))
		}
		raw, _ := json.Marshal(tc.b.Tracks[0])
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		got, ok := m["identity_receiver"]
		if !ok || got != tc.want {
			t.Fatalf("%s: identity_receiver %v (present %v), want %v", tc.b.ReceiverID, got, ok, tc.want)
		}
	}
}

// The core limitation documented in doc.go and docs/PLAN.md Q-A21,
// pinned so a change in uspace-core is noticed: rid.Tracker forgets a
// transmitter silent for MaxGapS (3 s) before IdentifyWithinS (4 s) is
// reached, so a lone Location without an identity, followed only by
// more than 3 s of silence, is dropped with the address (counted in the
// tracker's silences) and never published unidentified. A transmitter
// that keeps sending Locations every second is published unidentified
// after 4 s (the twin).
func TestHeldLocationForgottenBeforeIdentifyWithin(t *testing.T) {
	p, rec := pipe(DefaultSettings(), Deps{})
	observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-LONE", frame(t, loc(baseLatDeg, baseLonDeg)), at(t0))))
	later := t0.Add(5 * time.Second)
	observe(t, p, batchOf("rx-1", later, false, rxRow("rx-1", "TX-LONE", frame(t, loc(baseLatDeg, baseLonDeg)), at(later))))
	live, _ := p.TrackerCounters()
	if len(rec.tracks(t)) != 0 || live.Get(rid.CounterSilences) != 1 {
		t.Fatalf("lone Location: %d tracks, silences %d", len(rec.tracks(t)), live.Get(rid.CounterSilences))
	}
	for s := range 6 {
		now := t0.Add(time.Minute + time.Duration(s)*time.Second)
		observe(t, p, batchOf("rx-1", now, false, rxRow("rx-1", "TX-STEADY", frame(t, loc(baseLatDeg, baseLonDeg)), at(now))))
	}
	if len(rec.tracks(t)) == 0 {
		t.Fatal("a steady transmitter without an identity was never published unidentified")
	}
}
