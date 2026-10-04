package intents

import (
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
)

// Counter names of the cache (E-09, E-10).
const (
	CounterCacheEvicted = "intent_cache_evicted" // a reference dropped for the bound: the oldest withdrawn, else the one seen longest ago
	CounterCachePurged  = "intent_cache_purged"  // a reference past the 24 h retention or ended past EndedKeep
)

// RetentionMax is how long peer data is kept at most: F3548
// ExternalDataMaxRetentionTimeHours (24 h; spec 02 F6).
const RetentionMax = f3548.ExternalDataMaxRetentionTimeHours * time.Hour

// Entry is one cached operational intent reference.
type Entry struct {
	Ref f3548.OperationalIntentReference
	// Zones are the U-space airspaces (zone keys) whose latest read
	// listed it; LastZones those that ever did, for a withdrawn entry's
	// reasons.
	Zones, LastZones map[string]bool
	// FirstSeen and LastSeen are the wall times of the reads that listed
	// it; Withdrawn is when a read of every airspace that listed it no
	// longer did (nil while listed).
	FirstSeen, LastSeen time.Time
	Withdrawn           *time.Time
}

// Cache holds the references read from the DSS, bounded by Max, purged
// at RetentionMax after the last read that listed them and EndedKeep
// after their time_end (F3548 ExternalDataMaxRetentionTimeHours, spec 02
// F6). Not safe for concurrent use: the Board guards it.
type Cache struct {
	Max       int
	EndedKeep time.Duration
	Counters  *core.Counters

	entries map[string]*Entry
}

// NewCache returns an empty cache of at most maxEntries entries.
func NewCache(maxEntries int, endedKeep time.Duration, counters *core.Counters) *Cache {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Cache{Max: maxEntries, EndedKeep: endedKeep, Counters: counters, entries: map[string]*Entry{}}
}

// Len is the number of cached references.
func (c *Cache) Len() int { return len(c.entries) }

// Withdrawn is the number of cached references no longer in the DSS.
func (c *Cache) Withdrawn() int {
	n := 0
	for _, e := range c.entries {
		if e.Withdrawn != nil {
			n++
		}
	}
	return n
}

// Get is the entry of id.
func (c *Cache) Get(id string) (Entry, bool) {
	e, ok := c.entries[id]
	if !ok {
		return Entry{}, false
	}
	return clone(e), true
}

func clone(e *Entry) Entry {
	out := *e
	out.Zones, out.LastZones = maps.Clone(e.Zones), maps.Clone(e.LastZones)
	return out
}

// put adds or refreshes ref as listed for zone at now.
func (c *Cache) put(zone string, ref f3548.OperationalIntentReference, now time.Time) {
	e, ok := c.entries[ref.Id]
	if !ok {
		c.makeRoom()
		e = &Entry{Zones: map[string]bool{}, LastZones: map[string]bool{}, FirstSeen: now}
		c.entries[ref.Id] = e
	}
	e.Ref, e.LastSeen, e.Withdrawn = ref, now, nil
	e.Zones[zone], e.LastZones[zone] = true, true
}

// makeRoom drops one entry when the cache is full: the oldest withdrawn
// one, else the one last seen longest ago (ties by id).
func (c *Cache) makeRoom() {
	if c.Max <= 0 || len(c.entries) < c.Max {
		return
	}
	var victim *Entry
	for _, e := range c.entries {
		if victim == nil || older(e, victim) {
			victim = e
		}
	}
	delete(c.entries, victim.Ref.Id)
	c.Counters.Inc(CounterCacheEvicted)
}

// older orders eviction: withdrawn before listed, then the earlier
// withdrawal or last read, then the lower id.
func older(a, b *Entry) bool {
	aw, bw := a.Withdrawn != nil, b.Withdrawn != nil
	switch {
	case aw != bw:
		return aw
	case aw && !a.Withdrawn.Equal(*b.Withdrawn):
		return a.Withdrawn.Before(*b.Withdrawn)
	case !a.LastSeen.Equal(b.LastSeen):
		return a.LastSeen.Before(b.LastSeen)
	}
	return a.Ref.Id < b.Ref.Id
}

// Sync records a complete read of zone at now: every reference listed is
// put; every entry the zone listed before and no longer does leaves the
// zone, and one left in no zone is marked withdrawn (kept for the
// reasons until purged).
func (c *Cache) Sync(zone string, refs []f3548.OperationalIntentReference, now time.Time) {
	listed := make(map[string]bool, len(refs))
	for i := range refs {
		listed[refs[i].Id] = true
		c.put(zone, refs[i], now)
	}
	for id, e := range c.entries {
		if !e.Zones[zone] || listed[id] {
			continue
		}
		delete(e.Zones, zone)
		if len(e.Zones) == 0 && e.Withdrawn == nil {
			at := now
			e.Withdrawn = &at
		}
	}
}

// Add records refs the DSS placed at an aircraft in zone, without
// withdrawing anything (a position read is not a read of the zone).
func (c *Cache) Add(zone string, refs []f3548.OperationalIntentReference, now time.Time) {
	for i := range refs {
		c.put(zone, refs[i], now)
	}
}

// InZone are the entries the latest read of zone listed, and the
// withdrawn ones it listed before, ordered by id.
func (c *Cache) InZone(zone string) []Entry {
	var out []Entry
	for _, e := range c.entries {
		if e.Zones[zone] || (e.Withdrawn != nil && e.LastZones[zone]) {
			out = append(out, clone(e))
		}
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Ref.Id, b.Ref.Id) })
	return out
}

// Purge drops what may no longer be kept or is of no further use: an
// entry no read has listed for RetentionMax (peer data retained at most
// 24 h, F3548), and one whose time_end is more than EndedKeep ago.
func (c *Cache) Purge(now time.Time) {
	for id, e := range c.entries {
		if now.Sub(e.LastSeen) > RetentionMax || now.Sub(e.Ref.TimeEnd.Value) > c.EndedKeep {
			delete(c.entries, id)
			c.Counters.Inc(CounterCachePurged)
		}
	}
}

// Oldest is the earliest LastSeen held (zero when empty): the status
// proves nothing older than 24 h is kept.
func (c *Cache) Oldest() time.Time {
	var t time.Time
	for _, e := range c.entries {
		if t.IsZero() || e.LastSeen.Before(t) {
			t = e.LastSeen
		}
	}
	return t
}
