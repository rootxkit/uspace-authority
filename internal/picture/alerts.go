package picture

import (
	"container/list"
	"sync"
	"time"

	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// alert is one active violation as last heard on alrt.v1.
type alert struct {
	id       string
	cell     cell.ID
	raw      []byte
	lastSeen time.Time
}

// alertVerdict is what alertSet.offer made of a message.
type alertVerdict int

const (
	// alertForward: a raise, a clear, or the first message of a
	// violation the picture did not hold: every console in its cell is
	// told.
	alertForward alertVerdict = iota
	// alertRefresh: a republish of a violation held (C-08): stored, not
	// forwarded (the consoles hold it).
	alertRefresh
	// alertAfterClear: a raise or update of a violation already cleared
	// (a read-back older than the clear): ignored.
	alertAfterClear
)

// alertSet holds the active violations for the replay to a connecting
// console (C-08): a raise or republish stores the message, a clear
// removes it (and remembers the id, so an older message read back later
// cannot revive a cleared violation), the set is bounded (E-10).
//
// A violation detect stops republishing is never dropped at once: past
// silentAfter it is unconfirmed (the console is told, degraded
// alerts_unconfirmed), and only past forgetAfter does it leave the
// picture, counted and logged; a later republish brings it back. The
// picture never closes a violation: api's records do (WP-12).
type alertSet struct {
	max, maxCleared int
	silentAfter     time.Duration
	forgetAfter     time.Duration

	mu         sync.Mutex
	byID       map[string]*alert
	cleared    map[string]*list.Element
	clearedLRU *list.List
}

func newAlertSet(maxAlerts, maxCleared int, silentAfter, forgetAfter time.Duration) *alertSet {
	return &alertSet{
		max: maxAlerts, maxCleared: maxCleared, silentAfter: silentAfter, forgetAfter: forgetAfter,
		byID: map[string]*alert{}, cleared: map[string]*list.Element{}, clearedLRU: list.New(),
	}
}

// offer takes one validated violation message received at now. evicted
// is true when a new violation pushed the one heard longest ago out.
func (s *alertSet) offer(m *violation.Message, raw []byte, c5 cell.ID, now time.Time) (v alertVerdict, evicted bool) {
	id := m.Body.ViolationID
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.Body.State == violation.StateCleared {
		delete(s.byID, id)
		s.rememberCleared(id)
		return alertForward, false
	}
	if _, gone := s.cleared[id]; gone {
		return alertAfterClear, false
	}
	if a, ok := s.byID[id]; ok {
		if now.Before(a.lastSeen) {
			// A read-back older than what the bus already delivered.
			return alertRefresh, false
		}
		a.raw, a.lastSeen, a.cell = raw, now, c5
		if m.Body.State == violation.StateRaised {
			return alertForward, false
		}
		return alertRefresh, false
	}
	if s.max > 0 && len(s.byID) >= s.max {
		var oldest *alert
		for _, a := range s.byID {
			if oldest == nil || a.lastSeen.Before(oldest.lastSeen) {
				oldest = a
			}
		}
		delete(s.byID, oldest.id)
		evicted = true
	}
	s.byID[id] = &alert{id: id, cell: c5, raw: raw, lastSeen: now}
	return alertForward, evicted
}

func (s *alertSet) rememberCleared(id string) {
	if e, ok := s.cleared[id]; ok {
		s.clearedLRU.MoveToFront(e)
		return
	}
	s.cleared[id] = s.clearedLRU.PushFront(id)
	for s.maxCleared > 0 && s.clearedLRU.Len() > s.maxCleared {
		back := s.clearedLRU.Back()
		if old, ok := back.Value.(string); ok {
			delete(s.cleared, old)
		}
		s.clearedLRU.Remove(back)
	}
}

// age forgets the violations silent for forgetAfter and returns how
// many, and the number unconfirmed (silent for silentAfter) with the
// instant the earliest of them became unconfirmed.
func (s *alertSet) age(now time.Time) (forgotten, unconfirmed int, since time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, a := range s.byID {
		silent := now.Sub(a.lastSeen)
		switch {
		case silent > s.forgetAfter:
			delete(s.byID, id)
			forgotten++
		case silent > s.silentAfter:
			unconfirmed++
			if at := a.lastSeen.Add(s.silentAfter); since.IsZero() || at.Before(since) {
				since = at
			}
		}
	}
	return forgotten, unconfirmed, since
}

// ageNoForget is age without forgetting: while the bus is down nothing
// leaves the picture, only the count of unconfirmed grows.
func (s *alertSet) ageNoForget(now time.Time) (forgotten, unconfirmed int, since time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.byID {
		if now.Sub(a.lastSeen) > s.silentAfter {
			unconfirmed++
			if at := a.lastSeen.Add(s.silentAfter); since.IsZero() || at.Before(since) {
				since = at
			}
		}
	}
	return 0, unconfirmed, since
}

// inCells returns the messages of the active violations in cells.
func (s *alertSet) inCells(cells map[cell.ID]struct{}) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, a := range s.byID {
		if _, ok := cells[a.cell]; ok {
			out = append(out, a.raw)
		}
	}
	return out
}

// len is the number of active violations held.
func (s *alertSet) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}
