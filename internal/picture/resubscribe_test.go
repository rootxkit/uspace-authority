package picture

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// A console re-subscribing while its snapshot is being built holds no
// lock the bus goroutine needs: a track offered meanwhile in a cell both
// consoles watch returns at once and reaches the other console. The
// snapshot is then delivered to the re-subscribing console, before any
// live frame of its new viewport.
func TestResubscribeDoesNotDelayOtherConsoles(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	now := time.Now()
	fillTracks(t, h, 50, now)
	slow := connect(t, h, consoleSession(), nil)
	other := connect(t, h, consoleSession(), nil)
	subscribe(t, slow, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	subscribe(t, other, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))

	entered := make(chan struct{})
	release := make(chan struct{})
	var armed atomic.Bool
	armed.Store(true)
	h.testSnapshotHook = func() {
		if armed.CompareAndSwap(true, false) {
			close(entered)
			<-release
		}
	}
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	slow.in <- subscribeFrameOf(44.80, 41.70, 44.86, 41.74)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the re-subscription never built its snapshot")
	}
	offered := make(chan struct{})
	at := now.Add(time.Second)
	go func() {
		h.OfferTrack(trackMsg(t, "trk-000", baseLatDeg, baseLonDeg, at, core.IdentRegistered), at)
		close(offered)
	}()
	select {
	case <-offered:
	case <-time.After(time.Second):
		t.Fatal("OfferTrack waited for a console building its snapshot: every console stalls behind one re-subscription")
	}
	if n := countTrack(t, other, "trk-000", 300*time.Millisecond); n != 1 {
		t.Fatalf("the other console received %d frames of the track, want 1", n)
	}

	unblock()
	// The re-subscribing console: status, then the snapshot, and only
	// then live frames of the new viewport; the track offered while the
	// snapshot was built is in it or follows it, so the console ends at
	// the newest sample.
	var sawSnapshot bool
	deadline := time.After(2 * time.Second)
	for !sawSnapshot {
		select {
		case raw := <-slow.out:
			f := validateFrame(t, raw)
			switch f.Schema {
			case SchemaSnapshot:
				sawSnapshot = true
				snap := snapshotOf(t, f)
				if len(snap.Tracks) != 50 {
					t.Fatalf("snapshot holds %d tracks", len(snap.Tracks))
				}
			case SchemaTrack:
				t.Fatal("a live frame of the new viewport came before its snapshot")
			}
		case <-deadline:
			t.Fatal("no snapshot after the re-subscription")
		}
	}
}

// The snapshot is bounded: past SnapshotMaxBytes items are left out and
// the body says truncated; below the bound it holds every item and says
// truncated false (the pair).
func TestSnapshotBoundedAndSaysTruncated(t *testing.T) {
	now := time.Now()
	one := len(trackMsg(t, "trk-000", baseLatDeg, baseLonDeg, now, core.IdentRegistered))
	for _, tc := range []struct {
		name      string
		maxBytes  int
		truncated bool
	}{{"over", 10 * one, true}, {"under", 1 << 20, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval, c.SnapshotMaxBytes = time.Hour, tc.maxBytes })
			fillTracks(t, h, 50, now)
			conn := connect(t, h, consoleSession(), nil)
			conn.in <- subscribeFrameOf(44.80, 41.70, 44.85, 41.73)
			f, raw := conn.until(t, SchemaSnapshot, 2*time.Second)
			var body struct {
				SnapshotBody
				Truncated *bool `json:"truncated"`
			}
			if err := json.Unmarshal(f.Body, &body); err != nil {
				t.Fatal(err)
			}
			validate(t, idPictureSnapshot, raw)
			if body.Truncated == nil || *body.Truncated != tc.truncated {
				t.Fatalf("truncated %v, want %v", body.Truncated, tc.truncated)
			}
			if tc.truncated {
				if len(body.Tracks) == 0 || len(body.Tracks) >= 50 {
					t.Fatalf("truncated snapshot holds %d tracks", len(body.Tracks))
				}
				if len(f.Body) > tc.maxBytes+1024 {
					t.Fatalf("truncated body is %d bytes, bound %d", len(f.Body), tc.maxBytes)
				}
				if h.Counters().Get(CounterSnapshotsTruncated) == 0 {
					t.Fatal("truncation not counted")
				}
			} else if len(body.Tracks) != 50 {
				t.Fatalf("snapshot holds %d tracks, want 50", len(body.Tracks))
			}
		})
	}
}

// Re-subscriptions faster than SubscribeMinInterval are coalesced: the
// latest one is applied, the ones it superseded never build a snapshot,
// and they are counted. A single subscription is applied at once (the
// pair).
func TestResubscribesRateLimitedToTheLatest(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) {
		c.StatusInterval, c.SubscribeMinInterval = time.Hour, 300*time.Millisecond
	})
	conn := connect(t, h, consoleSession(), nil)
	start := time.Now()
	subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if d := time.Since(start); d > 250*time.Millisecond {
		t.Fatalf("a single subscription waited %s", d)
	}
	before := h.Counters().Get(CounterSnapshots)
	const burst = 12
	for i := range burst {
		conn.in <- subscribeFrameOf(44.80, 41.70, 44.85+float64(i)*0.001, 41.73)
	}
	// The last viewport is applied within two intervals, not after
	// burst intervals.
	last := fmt.Sprint(44.85 + float64(burst-1)*0.001)
	deadline := time.Now().Add(time.Second)
	for {
		h.mu.RLock()
		applied := false
		for c := range h.clients {
			c.mu.Lock()
			applied = c.lastBox.MaxLon == 44.85+float64(burst-1)*0.001
			c.mu.Unlock()
		}
		h.mu.RUnlock()
		if applied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the latest viewport (east %s) was not applied within 1s", last)
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	if built := h.Counters().Get(CounterSnapshots) - before; built > 3 {
		t.Fatalf("%d snapshots built for %d re-subscriptions", built, burst)
	}
	if h.Counters().Get(CounterSubscribesCoalesced) == 0 {
		t.Fatal("superseded subscriptions not counted")
	}
}
