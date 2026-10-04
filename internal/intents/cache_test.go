package intents

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
)

// A read of an airspace lists its intents; one the next read no longer
// lists is withdrawn (kept for the reasons) and listed again it is not;
// a position read never withdraws anything.
func TestCacheSyncWithdrawsWhatTheDSSNoLongerLists(t *testing.T) {
	c := NewCache(10, time.Hour, nil)
	a := refOf("a", f3548.Activated, t0, t0.Add(time.Hour))
	b := refOf("b", f3548.Activated, t0, t0.Add(time.Hour))
	c.Sync("GEO/U1", []f3548.OperationalIntentReference{a, b}, t0)
	c.Sync("GEO/U2", []f3548.OperationalIntentReference{b}, t0)
	c.Sync("GEO/U1", []f3548.OperationalIntentReference{a}, t0.Add(time.Second))
	if e, _ := c.Get("b"); e.Withdrawn != nil || !e.Zones["GEO/U2"] || e.Zones["GEO/U1"] {
		t.Fatalf("b still listed by U2: %+v", e)
	}
	c.Sync("GEO/U2", nil, t0.Add(2*time.Second))
	e, _ := c.Get("b")
	if e.Withdrawn == nil || !e.Withdrawn.Equal(t0.Add(2*time.Second)) || c.Withdrawn() != 1 {
		t.Fatalf("b withdrawn: %+v", e)
	}
	if got := c.InZone("GEO/U1"); len(got) != 2 || got[1].Ref.Id != "b" {
		t.Fatalf("U1 keeps the withdrawn intent it listed: %+v", got)
	}
	c.Add("GEO/U1", []f3548.OperationalIntentReference{a}, t0.Add(3*time.Second))
	if e, _ := c.Get("b"); e.Withdrawn == nil {
		t.Fatal("a position read withdrew or restored something")
	}
	c.Sync("GEO/U2", []f3548.OperationalIntentReference{b}, t0.Add(4*time.Second))
	if e, _ := c.Get("b"); e.Withdrawn != nil || c.Withdrawn() != 0 {
		t.Fatalf("listed again: %+v", e)
	}
}

// E-10: past its bound the cache drops the oldest withdrawn entry, else
// the one seen longest ago, and counts it; at the bound it drops nothing.
func TestCacheBoundEvictsWithdrawnFirstThenTheOldest(t *testing.T) {
	counters := &core.Counters{}
	c := NewCache(3, time.Hour, counters)
	end := t0.Add(time.Hour)
	c.Sync("Z", []f3548.OperationalIntentReference{refOf("old", f3548.Activated, t0, end)}, t0)
	c.Add("Z", []f3548.OperationalIntentReference{refOf("mid", f3548.Activated, t0, end)}, t0.Add(time.Second))
	c.Add("Y", []f3548.OperationalIntentReference{refOf("gone", f3548.Activated, t0, end)}, t0.Add(2*time.Second))
	c.Sync("Y", nil, t0.Add(3*time.Second)) // gone withdrawn
	if c.Len() != 3 || counters.Get(CounterCacheEvicted) != 0 {
		t.Fatalf("at the bound: %d %v", c.Len(), counters.Snapshot())
	}
	c.Add("Z", []f3548.OperationalIntentReference{refOf("new1", f3548.Activated, t0, end)}, t0.Add(4*time.Second))
	if _, ok := c.Get("gone"); ok || c.Len() != 3 || counters.Get(CounterCacheEvicted) != 1 {
		t.Fatalf("the withdrawn entry goes first: %d %v", c.Len(), counters.Snapshot())
	}
	c.Add("Z", []f3548.OperationalIntentReference{refOf("new2", f3548.Activated, t0, end)}, t0.Add(5*time.Second))
	if _, ok := c.Get("old"); ok || counters.Get(CounterCacheEvicted) != 2 {
		t.Fatalf("then the one seen longest ago: %v", counters.Snapshot())
	}
	if _, ok := c.Get("mid"); !ok {
		t.Fatal("a newer entry was evicted")
	}
}

// F3548 ExternalDataMaxRetentionTimeHours: an entry no read has listed
// for 24 h is purged (proven on a backdated entry), and one ended more
// than EndedKeep ago; a fresh one beside them stays.
func TestCachePurgesPast24HoursAndPastTheEnd(t *testing.T) {
	counters := &core.Counters{}
	c := NewCache(10, 10*time.Minute, counters)
	now := t0.Add(48 * time.Hour)
	// A long intent (30-day horizon), last listed 24 h and 1 s ago.
	c.Sync("Z", []f3548.OperationalIntentReference{refOf("backdated", f3548.Activated, t0, t0.Add(30*24*time.Hour))},
		now.Add(-RetentionMax-time.Second))
	c.Add("Z", []f3548.OperationalIntentReference{refOf("ended", f3548.Activated, now.Add(-time.Hour), now.Add(-11*time.Minute))}, now)
	c.Add("Z", []f3548.OperationalIntentReference{refOf("fresh", f3548.Activated, now, now.Add(time.Hour))}, now.Add(-RetentionMax+time.Second))
	if !c.Oldest().Equal(now.Add(-RetentionMax - time.Second)) {
		t.Fatalf("oldest %v", c.Oldest())
	}
	c.Purge(now)
	if _, ok := c.Get("backdated"); ok {
		t.Fatal("an entry older than 24 h was kept")
	}
	if _, ok := c.Get("ended"); ok {
		t.Fatal("an entry ended past EndedKeep was kept")
	}
	if _, ok := c.Get("fresh"); !ok || c.Len() != 1 || counters.Get(CounterCachePurged) != 2 {
		t.Fatalf("fresh entry: %d %v", c.Len(), counters.Snapshot())
	}
	if now.Sub(c.Oldest()) > RetentionMax {
		t.Fatal("the cache holds peer data older than 24 h")
	}
}
