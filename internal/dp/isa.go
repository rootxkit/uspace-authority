package dp

import (
	"slices"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
)

// Counters of the ISA store.
const (
	CounterISAsRefused = "isas_refused_bound"
	CounterISAsExpired = "isas_expired"
	CounterISAsRemoved = "isas_removed_by_notification"
	// CounterISAsOwnerChange counts notifications refused because they
	// would change the owner of a held ISA (audit A-B1).
	CounterISAsOwnerChange = "isas_refused_owner_change"
)

type isaEntry struct {
	isa   f3411.IdentificationServiceArea
	tiles map[string]bool
	// box is the ISA's horizontal extent when a notification gave it;
	// a searched ISA is known only to lie in or near the tiles that
	// found it.
	box *Box
}

// ISAs are the identification service areas the Display Provider knows,
// bounded (E-10). The set of Service Providers to poll comes only from
// them (00 §7: never a configured USSP address). An ISA is used until
// its time_end, also while the DSS cannot be reached (02 F7).
type ISAs struct {
	Max      int
	Counters *core.Counters

	mu sync.Mutex
	m  map[string]*isaEntry
}

func (s *ISAs) init() {
	if s.m == nil {
		s.m = map[string]*isaEntry{}
	}
	if s.Counters == nil {
		s.Counters = &core.Counters{}
	}
}

// Len is the number of ISAs held.
func (s *ISAs) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// FromSearch takes the DSS's answer for one tile: the listed ISAs are
// in it, and an ISA the tile listed before and no longer does is not
// (it stays known for the other tiles that list it, or by its extent).
func (s *ISAs) FromSearch(tileKey string, isas []f3411.IdentificationServiceArea) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	listed := map[string]bool{}
	for i := range isas {
		if isas[i].Id == "" {
			continue
		}
		listed[isas[i].Id] = true
		s.upsertLocked(isas[i], tileKey, nil)
	}
	for id, e := range s.m {
		if e.tiles[tileKey] && !listed[id] {
			delete(e.tiles, tileKey)
			if len(e.tiles) == 0 && e.box == nil {
				delete(s.m, id)
			}
		}
	}
}

func (s *ISAs) upsertLocked(isa f3411.IdentificationServiceArea, tileKey string, box *Box) {
	e, ok := s.m[isa.Id]
	if !ok {
		if s.Max > 0 && len(s.m) >= s.Max {
			s.Counters.Inc(CounterISAsRefused)
			return
		}
		e = &isaEntry{tiles: map[string]bool{}}
		s.m[isa.Id] = e
	}
	e.isa = isa
	if tileKey != "" {
		e.tiles[tileKey] = true
	}
	if box != nil {
		e.box = box
	}
}

// Notify applies an ISA change notification (02 F7): with a service area
// the ISA is created or replaced, its extent from the notification's
// extents; without one it was deleted. A notification never changes
// the owner of a held ISA: it is refused (false) and counted, whoever
// checked the caller before (audit A-B1, defence in depth).
func (s *ISAs) Notify(id string, area *f3411.IdentificationServiceArea, extents *f3411.Volume4D) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	if area == nil {
		if _, ok := s.m[id]; ok {
			delete(s.m, id)
			s.Counters.Inc(CounterISAsRemoved)
		}
		return true
	}
	if e, ok := s.m[id]; ok && e.isa.Owner != area.Owner {
		s.Counters.Inc(CounterISAsOwnerChange)
		return false
	}
	var box *Box
	if extents != nil {
		if b, _, _, err := f3411.Volume4DToZonesEnvelope(*extents); err == nil {
			box = &b
		}
	}
	isa := *area
	isa.Id = id
	s.upsertLocked(isa, "", box)
	return true
}

// Expire forgets the ISAs whose time_end has passed.
func (s *ISAs) Expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.m {
		if !e.isa.TimeEnd.Value.IsZero() && e.isa.TimeEnd.Value.Before(now) {
			delete(s.m, id)
			s.Counters.Inc(CounterISAsExpired)
		}
	}
}

// ForTile lists the ISAs in force at now that the tile's search found or
// whose extent meets the tile, sorted by id.
func (s *ISAs) ForTile(t Tile, now time.Time) []f3411.IdentificationServiceArea {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := t.Key()
	var out []f3411.IdentificationServiceArea
	for _, e := range s.m {
		if !e.isa.TimeEnd.Value.IsZero() && e.isa.TimeEnd.Value.Before(now) {
			continue
		}
		if !e.isa.TimeStart.Value.IsZero() && e.isa.TimeStart.Value.After(now) {
			continue
		}
		if e.tiles[key] || (e.box != nil && Intersects(*e.box, t.Box)) || e.coversParent(t) {
			out = append(out, e.isa)
		}
	}
	slices.SortFunc(out, func(a, b f3411.IdentificationServiceArea) int {
		switch {
		case a.Id < b.Id:
			return -1
		case a.Id > b.Id:
			return 1
		}
		return 0
	})
	return out
}

// coversParent reports whether a search of a tile that t was split from
// (after a 413) found the ISA: the split tiles are polled for the same
// Service Providers as the tile itself.
func (e *isaEntry) coversParent(t Tile) bool {
	for key := range e.tiles {
		if parent, ok := ParseTileKey(key); ok && parent.Depth < t.Depth && Intersects(parent.Box, t.Box) {
			return true
		}
	}
	return false
}

// Owner is the owner of the ISA id, and whether it is known.
func (s *ISAs) Owner(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok {
		return "", false
	}
	return e.isa.Owner, true
}
