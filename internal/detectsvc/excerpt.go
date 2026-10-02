package detectsvc

import (
	"container/list"

	"github.com/rootxkit/uspace-core/alerting"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/violation"
)

// Counters of the excerpt store (E-09, E-10).
const (
	CounterExcerptSamplesDropped  = "excerpt_samples_dropped"  // a sample past the per-aircraft bound: the oldest is dropped
	CounterExcerptAircraftEvicted = "excerpt_aircraft_evicted" // an aircraft past the store's bound: the least recently heard is forgotten
)

// held is one sample with its placement in seconds.
type held struct {
	atS    float64
	sample violation.Sample
}

// aircraftLog is the recent samples of one aircraft, oldest first, and
// the last sample admitted as the monitor judged it (re-observed when
// the monitor is rebuilt).
type aircraftLog struct {
	id      string
	samples []held
	last    *Observed
	elem    *list.Element
}

// Observed is a sample as the monitor was given it: the track and the
// monitor's wall time then. A rebuilt monitor is given it again at that
// same wall time, so its lateness and staleness are judged as they were.
type Observed struct {
	Track alerting.Track
	WallS float64
}

// Excerpts keeps the recent samples of every aircraft heard, so that a
// raise can copy the window before it (03 §1 evidence_excerpt) and a
// rebuilt monitor can be fed each aircraft's last sample (INV-03). It is
// bounded twice (E-10): MaxSamples per aircraft (the oldest dropped) and
// MaxAircraft in all (the least recently heard forgotten), each counted.
// It is owned by one worker goroutine.
type Excerpts struct {
	WindowS     float64
	MaxSamples  int
	MaxAircraft int
	Counters    *core.Counters

	byID map[string]*aircraftLog
	lru  *list.List
}

// NewExcerpts returns an empty store.
func NewExcerpts(windowS float64, maxSamples, maxAircraft int, counters *core.Counters) *Excerpts {
	return &Excerpts{WindowS: windowS, MaxSamples: max(maxSamples, 1), MaxAircraft: max(maxAircraft, 1), Counters: counters,
		byID: map[string]*aircraftLog{}, lru: list.New()}
}

// Len is the number of aircraft held.
func (e *Excerpts) Len() int { return len(e.byID) }

func (e *Excerpts) entry(id string) *aircraftLog {
	if l, ok := e.byID[id]; ok {
		e.lru.MoveToBack(l.elem)
		return l
	}
	if len(e.byID) >= e.MaxAircraft {
		oldest := e.lru.Front()
		victim := oldest.Value.(*aircraftLog)
		e.lru.Remove(oldest)
		delete(e.byID, victim.id)
		e.Counters.Inc(CounterExcerptAircraftEvicted)
	}
	l := &aircraftLog{id: id}
	l.elem = e.lru.PushBack(l)
	e.byID[id] = l
	return l
}

// Add keeps s, placed at atS, for aircraft id, and drops what has left
// the window behind it.
func (e *Excerpts) Add(id string, atS float64, s violation.Sample) {
	l := e.entry(id)
	l.samples = append(l.samples, held{atS: atS, sample: s})
	cut := 0
	for cut < len(l.samples) && l.samples[cut].atS < atS-e.WindowS {
		cut++
	}
	if over := len(l.samples) - cut - e.MaxSamples; over > 0 {
		cut += over
		e.Counters.Add(CounterExcerptSamplesDropped, uint64(over))
	}
	if cut > 0 {
		l.samples = append(l.samples[:0], l.samples[cut:]...)
	}
}

// SetLast records the last sample of id handed to the monitor, observed
// at the monitor's wall time wallS.
func (e *Excerpts) SetLast(id string, tr alerting.Track, wallS float64) {
	l := e.entry(id)
	l.last = &Observed{Track: tr, WallS: wallS}
}

// Last is every aircraft's last observed sample, in no order.
func (e *Excerpts) Last() []Observed {
	out := make([]Observed, 0, len(e.byID))
	for _, l := range e.byID {
		if l.last != nil {
			out = append(out, *l.last)
		}
	}
	return out
}

// LastOf is the last observed sample of id, if the store still holds it.
func (e *Excerpts) LastOf(id string) (Observed, bool) {
	l, ok := e.byID[id]
	if !ok || l.last == nil {
		return Observed{}, false
	}
	return *l.last, true
}

// Window returns the samples of id placed in (fromS, toS], oldest first.
func (e *Excerpts) Window(id string, fromS, toS float64) []violation.Sample {
	l, ok := e.byID[id]
	if !ok {
		return []violation.Sample{}
	}
	out := []violation.Sample{}
	for i := range l.samples {
		if h := &l.samples[i]; h.atS > fromS && h.atS <= toS {
			out = append(out, h.sample)
		}
	}
	return out
}

// lastSample is the newest sample of id.
func (e *Excerpts) lastSample(id string) (violation.Sample, bool) {
	l, ok := e.byID[id]
	if !ok || len(l.samples) == 0 {
		return violation.Sample{}, false
	}
	return l.samples[len(l.samples)-1].sample, true
}
