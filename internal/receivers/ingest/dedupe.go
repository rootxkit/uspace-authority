package ingest

import (
	"container/list"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Counter names of the dedupe window (E-09, E-10).
const (
	CounterDuplicates        = "observations_duplicate"
	CounterDedupeEvicted     = "dedupe_entries_evicted"
	CounterDedupeReceiversEv = "dedupe_receivers_evicted"
)

// Mark is what Reserve says about one key.
type Mark int

// The marks.
const (
	// Fresh: never seen in the window; now reserved for this batch.
	Fresh Mark = iota
	// Duplicate: accepted already within the window.
	Duplicate
	// InFlight: reserved by a batch whose queue write has not finished.
	InFlight
)

type dedupeEntry struct {
	key     string
	expires time.Time
	pending bool
}

type receiverWindow struct {
	id    string
	keys  map[string]*list.Element
	order *list.List // front = oldest
	elem  *list.Element
}

// Dedupe is the per-receiver window of observations accepted in the last
// Window (60 s): a replayed batch publishes nothing twice (B-05). A key is
// reserved before the queue write and released if the write fails, so a
// refused batch can be retried without its observations reading as
// duplicates. Both the keys per receiver and the receivers are bounded,
// oldest evicted first and counted (E-10); an evicted key can be queued
// once more, which the writer's own dedupe key absorbs (WP-9).
type Dedupe struct {
	Window       time.Duration
	MaxPerRx     int
	MaxReceivers int
	Counters     *core.Counters

	mu    sync.Mutex
	byRx  map[string]*receiverWindow
	rxLRU *list.List // front = least recently used
}

// NewDedupe returns an empty window.
func NewDedupe(window time.Duration, maxPerReceiver, maxReceivers int, counters *core.Counters) (*Dedupe, error) {
	if window <= 0 || maxPerReceiver < 1 || maxReceivers < 1 || counters == nil {
		return nil, core.Fieldf("dedupe", "window, bounds and counters are required")
	}
	return &Dedupe{Window: window, MaxPerRx: maxPerReceiver, MaxReceivers: maxReceivers, Counters: counters,
		byRx: map[string]*receiverWindow{}, rxLRU: list.New()}, nil
}

func (d *Dedupe) window(id string) *receiverWindow {
	if w, ok := d.byRx[id]; ok {
		d.rxLRU.MoveToBack(w.elem)
		return w
	}
	for len(d.byRx) >= d.MaxReceivers {
		oldest := d.rxLRU.Front()
		d.rxLRU.Remove(oldest)
		delete(d.byRx, oldest.Value.(*receiverWindow).id)
		d.Counters.Inc(CounterDedupeReceiversEv)
	}
	w := &receiverWindow{id: id, keys: map[string]*list.Element{}, order: list.New()}
	w.elem = d.rxLRU.PushBack(w)
	d.byRx[id] = w
	return w
}

func (w *receiverWindow) expire(now time.Time) {
	for e := w.order.Front(); e != nil; {
		ent := e.Value.(*dedupeEntry)
		if ent.pending || now.Before(ent.expires) {
			// Entries are appended in time order; pending ones hold
			// their place until released or settled.
			if !ent.pending {
				return
			}
			e = e.Next()
			continue
		}
		next := e.Next()
		w.order.Remove(e)
		delete(w.keys, ent.key)
		e = next
	}
}

// Reserve marks each key of one receiver's batch at now. Fresh keys are
// reserved; the caller settles them with Commit after the queue write or
// gives them back with Release.
func (d *Dedupe) Reserve(receiverID string, keys []string, now time.Time) []Mark {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := d.window(receiverID)
	w.expire(now)
	marks := make([]Mark, len(keys))
	mine := make(map[string]bool, len(keys))
	for i, k := range keys {
		if el, ok := w.keys[k]; ok {
			// A key twice in one batch is a duplicate of itself, not a
			// batch in flight.
			if el.Value.(*dedupeEntry).pending && !mine[k] {
				marks[i] = InFlight
			} else {
				marks[i] = Duplicate
			}
			continue
		}
		for len(w.keys) >= d.MaxPerRx {
			oldest := w.order.Front()
			ent := oldest.Value.(*dedupeEntry)
			w.order.Remove(oldest)
			delete(w.keys, ent.key)
			d.Counters.Inc(CounterDedupeEvicted)
		}
		w.keys[k] = w.order.PushBack(&dedupeEntry{key: k, expires: now.Add(d.Window), pending: true})
		mine[k] = true
		marks[i] = Fresh
	}
	return marks
}

// Commit settles reserved keys: they count as accepted until now + Window.
func (d *Dedupe) Commit(receiverID string, keys []string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.byRx[receiverID]
	if !ok {
		return
	}
	for _, k := range keys {
		if el, ok := w.keys[k]; ok {
			ent := el.Value.(*dedupeEntry)
			ent.pending = false
			ent.expires = now.Add(d.Window)
			w.order.MoveToBack(el)
		}
	}
}

// Release gives reserved keys back after a failed queue write.
func (d *Dedupe) Release(receiverID string, keys []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.byRx[receiverID]
	if !ok {
		return
	}
	for _, k := range keys {
		if el, ok := w.keys[k]; ok && el.Value.(*dedupeEntry).pending {
			w.order.Remove(el)
			delete(w.keys, k)
		}
	}
}

// Len is the number of keys held for receiverID.
func (d *Dedupe) Len(receiverID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if w, ok := d.byRx[receiverID]; ok {
		return len(w.keys)
	}
	return 0
}

// Receivers is the number of receivers held.
func (d *Dedupe) Receivers() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.byRx)
}
