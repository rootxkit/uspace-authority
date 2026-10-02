package ingest

import (
	"fmt"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

func newTestDedupe(t *testing.T, perRx, receivers int) *Dedupe {
	t.Helper()
	d, err := NewDedupe(time.Minute, perRx, receivers, &core.Counters{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A key is fresh, then in flight while reserved, then a duplicate once
// committed, and fresh again after the window; a released key is fresh.
func TestDedupeLifecycle(t *testing.T) {
	d := newTestDedupe(t, 10, 10)
	now := time.Unix(1000, 0)
	if m := d.Reserve("rx-1", []string{"k"}, now); m[0] != Fresh {
		t.Fatal(m)
	}
	if m := d.Reserve("rx-1", []string{"k"}, now); m[0] != InFlight {
		t.Fatal(m)
	}
	d.Release("rx-1", []string{"k"})
	if m := d.Reserve("rx-1", []string{"k"}, now); m[0] != Fresh {
		t.Fatal("released key not fresh", m)
	}
	d.Commit("rx-1", []string{"k"}, now)
	if m := d.Reserve("rx-1", []string{"k"}, now.Add(59*time.Second)); m[0] != Duplicate {
		t.Fatal(m)
	}
	if m := d.Reserve("rx-1", []string{"k"}, now.Add(61*time.Second)); m[0] != Fresh {
		t.Fatal("expired key not fresh", m)
	}
	if m := d.Reserve("rx-2", []string{"k"}, now); m[0] != Fresh {
		t.Fatal("another receiver's key is not a duplicate", m)
	}
	if m := d.Reserve("rx-3", []string{"x", "x"}, now); m[0] != Fresh || m[1] != Duplicate {
		t.Fatal("a key twice in one batch", m)
	}
	d.Release("rx-9", []string{"k"})
	d.Commit("rx-9", []string{"k"}, now)
}

// E-10: the keys per receiver and the receivers are bounded; past each
// bound the oldest is forgotten and counted.
func TestDedupeBounds(t *testing.T) {
	d := newTestDedupe(t, 5, 3)
	now := time.Unix(1000, 0)
	for i := range 8 {
		k := fmt.Sprint(i)
		d.Reserve("rx-1", []string{k}, now)
		d.Commit("rx-1", []string{k}, now)
	}
	if d.Len("rx-1") != 5 || d.Counters.Get(CounterDedupeEvicted) != 3 {
		t.Fatalf("len %d evicted %d", d.Len("rx-1"), d.Counters.Get(CounterDedupeEvicted))
	}
	if m := d.Reserve("rx-1", []string{"0"}, now); m[0] != Fresh {
		t.Fatal("an evicted key still a duplicate")
	}
	for i := range 5 {
		d.Reserve(fmt.Sprintf("rx-x%d", i), []string{"k"}, now)
	}
	if d.Receivers() != 3 || d.Counters.Get(CounterDedupeReceiversEv) != 3 {
		t.Fatalf("receivers %d evicted %d", d.Receivers(), d.Counters.Get(CounterDedupeReceiversEv))
	}
	if _, err := NewDedupe(0, 1, 1, &core.Counters{}); err == nil {
		t.Fatal("zero window accepted")
	}
}
