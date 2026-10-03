package dp

import (
	"container/list"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
)

// lru is a map bounded to max entries (E-10): putting a new key at the
// bound drops the least recently used one and reports it. Not safe for
// concurrent use.
type lru[K comparable, V any] struct {
	max   int
	items map[K]*list.Element
	order *list.List
}

type lruEntry[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](maxEntries int) *lru[K, V] {
	return &lru[K, V]{max: max(1, maxEntries), items: make(map[K]*list.Element), order: list.New()}
}

func (l *lru[K, V]) get(k K) (V, bool) {
	if el, ok := l.items[k]; ok {
		l.order.MoveToFront(el)
		return el.Value.(*lruEntry[K, V]).val, true
	}
	var zero V
	return zero, false
}

func (l *lru[K, V]) put(k K, v V) (evicted bool) {
	if el, ok := l.items[k]; ok {
		el.Value.(*lruEntry[K, V]).val = v
		l.order.MoveToFront(el)
		return false
	}
	if len(l.items) >= l.max {
		if back := l.order.Back(); back != nil {
			delete(l.items, back.Value.(*lruEntry[K, V]).key)
			l.order.Remove(back)
			evicted = true
		}
	}
	l.items[k] = l.order.PushFront(&lruEntry[K, V]{key: k, val: v})
	return evicted
}

func (l *lru[K, V]) len() int { return len(l.items) }

// each calls fn for every entry, most recently used first, without
// marking any used.
func (l *lru[K, V]) each(fn func(K, V)) {
	for el := l.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*lruEntry[K, V])
		fn(e.key, e.val)
	}
}

// FlightKey is one flight of one Service Provider: a flight seen in two
// tiles (or two views) is one flight.
type FlightKey struct {
	USSID    string
	FlightID string
}

// Flight is what the Display Provider remembers of one flight.
type Flight struct {
	// StateTS and Position are the last state published; an identical
	// state is not published again (R-14).
	StateTS  time.Time
	Position [3]float64 // lat, lng, alt (HAE, NaN when absent)
	// Status is the operational status of that state ("" when absent).
	Status string
	// Details and DetailsAt: the last details fetched.
	Details    *f3411.RIDFlightDetails
	DetailsRaw []byte
	DetailsAt  time.Time
	// Ident is the last identification announced on ident.v1.
	Ident    *core.Identification
	Last     *Mapped
	LastSeen time.Time
	ISAID    string
}

// Counters of the memory.
const (
	CounterStateUnchanged = "state_unchanged_not_republished"
	CounterFlightsEvicted = "flights_memory_evicted"
)

// Memory is the bounded flight memory (E-10), safe for concurrent use.
type Memory struct {
	mu       sync.Mutex
	flights  *lru[FlightKey, *Flight]
	counters *core.Counters
}

// NewMemory holds at most maxFlights flights.
func NewMemory(maxFlights int, counters *core.Counters) *Memory {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Memory{flights: newLRU[FlightKey, *Flight](maxFlights), counters: counters}
}

// Len is the number of flights held.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.flights.len()
}

func (m *Memory) entry(k FlightKey) *Flight {
	f, ok := m.flights.get(k)
	if !ok {
		f = &Flight{}
		if m.flights.put(k, f) {
			m.counters.Inc(CounterFlightsEvicted)
		}
	}
	return f
}

// Details is the flight's cached details and when they were fetched.
func (m *Memory) Details(k FlightKey) (*f3411.RIDFlightDetails, time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flights.get(k)
	if !ok {
		return nil, time.Time{}
	}
	return f.Details, f.DetailsAt
}

// DetailsRaw is the flight's cached details and their body as received.
func (m *Memory) DetailsRaw(k FlightKey) (*f3411.RIDFlightDetails, []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.flights.get(k)
	if !ok {
		return nil, nil
	}
	return f.Details, f.DetailsRaw
}

// SetDetailsRaw stores the flight's details and their body as received.
func (m *Memory) SetDetailsRaw(k FlightKey, d *f3411.RIDFlightDetails, raw []byte, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.entry(k)
	f.Details, f.DetailsRaw, f.DetailsAt = d, raw, at
}

// position is the comparable position of a state.
func position(st *f3411.RIDAircraftState) [3]float64 {
	p := st.Position.LatLon()
	alt := nan()
	if a := st.Position.AltHAEM(); a != nil {
		alt = *a
	}
	return [3]float64{p.LatDeg, p.LonDeg, alt}
}

func same(a, b [3]float64) bool {
	for i := range a {
		if a[i] != b[i] && !(a[i] != a[i] && b[i] != b[i]) { // NaN equals NaN here
			return false
		}
	}
	return true
}

// Fresh reports whether st differs from the last state published for k
// (its timestamp, its position or its operational status: an emergency
// declared at the same instant is news, audit A-N3) and, when it does,
// records it as published. An identical state is counted (R-14).
func (m *Memory) Fresh(k FlightKey, st *f3411.RIDAircraftState, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.entry(k)
	f.LastSeen = now
	pos := position(st)
	status := ""
	if st.OperationalStatus != nil {
		status = string(*st.OperationalStatus)
	}
	if !f.StateTS.IsZero() && f.StateTS.Equal(st.Timestamp.Value) && same(f.Position, pos) && f.Status == status {
		m.counters.Inc(CounterStateUnchanged)
		return false
	}
	f.StateTS, f.Position, f.Status = st.Timestamp.Value, pos, status
	return true
}

// Published records the mapped state of k and returns the
// identification announced before it (nil for the first).
func (m *Memory) Published(k FlightKey, mp *Mapped, isaID string) *core.Identification {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.entry(k)
	f.Last, f.ISAID = mp, isaID
	return f.Ident
}

// Announced records the identification announced on ident.v1 for k.
func (m *Memory) Announced(k FlightKey, id core.Identification) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.entry(k)
	f.Ident = &id
}

// Snapshot lists the last published state of every flight seen since
// since, most recent first.
func (m *Memory) Snapshot(since time.Time) []FlightView {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FlightView
	m.flights.each(func(k FlightKey, f *Flight) {
		if f.Last != nil && !f.LastSeen.Before(since) {
			out = append(out, FlightView{Key: k, Mapped: f.Last, Details: f.Details, LastSeen: f.LastSeen})
		}
	})
	return out
}

// FlightView is one flight as the observation interface reads it.
type FlightView struct {
	Key      FlightKey
	Mapped   *Mapped
	Details  *f3411.RIDFlightDetails
	LastSeen time.Time
}
