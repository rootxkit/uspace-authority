package picture

import (
	"container/list"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/cell"
)

// item is the last message of one aircraft.
type item struct {
	key      string
	cell     cell.ID
	captured time.Time
	// pos is the track's position (nil for a manned aircraft, whose body
	// the picture does not read): the HTTP snapshot filters by it.
	pos *core.LatLon
	// sourceType and instance name the track's source (source_state).
	sourceType, instance string
	track                *trackIn
	raw                  []byte
	elem                 *list.Element
}

// putResult is what store.put did.
type putResult int

const (
	putNew putResult = iota
	putUpdated
	putOlder // not newer than the message held: refused
)

// cache is the state cache of one kind of aircraft (05 §3: the last
// message per id, per cell): bounded (E-10) with the aircraft updated
// longest ago evicted first, and swept of what is older than
// stale_after_s. It is safe for concurrent use.
type cache struct {
	max int

	mu     sync.RWMutex
	lru    *list.List // front: updated most recently
	byKey  map[string]*item
	byCell map[cell.ID]map[string]*item
}

func newCache(maxItems int) *cache {
	return &cache{max: maxItems, lru: list.New(), byKey: map[string]*item{}, byCell: map[cell.ID]map[string]*item{}}
}

// put stores it. A message not newer than the one held for its key is
// refused (putOlder): the picture never moves an aircraft back in time.
// A new key past the bound evicts the aircraft updated longest ago,
// returned.
func (s *cache) put(it *item) (putResult, *item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byKey[it.key]; ok {
		if !it.captured.After(old.captured) {
			return putOlder, nil
		}
		s.unlinkCell(old)
		it.elem = old.elem
		it.elem.Value = it
		s.lru.MoveToFront(it.elem)
		s.byKey[it.key] = it
		s.linkCell(it)
		return putUpdated, nil
	}
	var evicted *item
	if s.max > 0 && len(s.byKey) >= s.max {
		if back := s.lru.Back(); back != nil {
			evicted, _ = back.Value.(*item)
			if evicted != nil {
				s.removeLocked(evicted)
			}
		}
	}
	it.elem = s.lru.PushFront(it)
	s.byKey[it.key] = it
	s.linkCell(it)
	return putNew, evicted
}

func (s *cache) linkCell(it *item) {
	m := s.byCell[it.cell]
	if m == nil {
		m = map[string]*item{}
		s.byCell[it.cell] = m
	}
	m[it.key] = it
}

func (s *cache) unlinkCell(it *item) {
	if m := s.byCell[it.cell]; m != nil {
		delete(m, it.key)
		if len(m) == 0 {
			delete(s.byCell, it.cell)
		}
	}
}

func (s *cache) removeLocked(it *item) {
	s.unlinkCell(it)
	delete(s.byKey, it.key)
	if it.elem != nil {
		s.lru.Remove(it.elem)
	}
}

// sweep removes every aircraft whose last message was captured before
// cutoff and returns how many.
func (s *cache) sweep(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, it := range s.byKey {
		if it.captured.Before(cutoff) {
			s.removeLocked(it)
			n++
		}
	}
	return n
}

// inCells returns the aircraft of cells (each once), unordered.
func (s *cache) inCells(cells map[cell.ID]struct{}) []*item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*item
	for c := range cells {
		for _, it := range s.byCell[c] {
			out = append(out, it)
		}
	}
	return out
}

// countIn is the number of aircraft in cells.
func (s *cache) countIn(cells map[cell.ID]struct{}) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for c := range cells {
		n += len(s.byCell[c])
	}
	return n
}

// len is the number of aircraft held.
func (s *cache) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey)
}
