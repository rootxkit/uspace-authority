package dp

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/track"
)

// fakeSP answers Flights and Details from its fields; every call is
// counted.
type fakeSP struct {
	mu        sync.Mutex
	flights   []f3411.RIDFlight
	respTS    time.Time
	err       error
	delay     time.Duration
	details   map[string]*f3411.RIDFlightDetails
	calls     int
	detailsN  int
	views     []Box
	detailErr error
}

func (s *fakeSP) Flights(ctx context.Context, _ string, b Box) (*f3411.GetFlightsResponse, []json.RawMessage, error) {
	s.mu.Lock()
	s.calls++
	s.views = append(s.views, b)
	delay, err := s.delay, s.err
	fl := append([]f3411.RIDFlight(nil), s.flights...)
	ts := s.respTS
	s.mu.Unlock()
	if delay > 0 {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	if err != nil {
		return nil, nil, err
	}
	raws := make([]json.RawMessage, len(fl))
	for i := range fl {
		raws[i], _ = json.Marshal(fl[i])
	}
	return &f3411.GetFlightsResponse{Flights: &fl, Timestamp: f3411.Time{Format: f3411.RFC3339, Value: ts}}, raws, nil
}

func (s *fakeSP) Details(_ context.Context, _, id string) (*f3411.RIDFlightDetails, json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.detailsN++
	if s.detailErr != nil {
		return nil, nil, s.detailErr
	}
	d, ok := s.details[id]
	if !ok {
		return nil, nil, &HTTPError{Op: "details", Status: 404}
	}
	raw, _ := json.Marshal(d)
	return d, raw, nil
}

func (s *fakeSP) count() (calls, details int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls, s.detailsN
}

// recorder is a Sink that keeps everything.
type recorder struct {
	mu      sync.Mutex
	tracks  []*Message
	idents  []*track.IdentChange
	rows    []track.Row
	flights []FlightRow
	err     error
}

func (r *recorder) Track(m *Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.tracks = append(r.tracks, m)
	return nil
}

func (r *recorder) Ident(c *track.IdentChange) error {
	if err := c.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.idents = append(r.idents, c)
	return nil
}

func (r *recorder) Rows(tracks []track.Row, flights []FlightRow) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows = append(r.rows, tracks...)
	r.flights = append(r.flights, flights...)
}

func (r *recorder) published() []*Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*Message(nil), r.tracks...)
}

// gate is a source-control switch per instance.
type gate struct {
	mu  sync.Mutex
	off map[string]bool
}

func (g *gate) Query(_ string, id *string) coresources.Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	if id != nil && g.off[*id] {
		w := coresources.WhyInstance
		return coresources.Decision{Enabled: false, WhyDisabled: &w}
	}
	return coresources.Decision{Enabled: true}
}

func (g *gate) set(id string, off bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.off == nil {
		g.off = map[string]bool{}
	}
	g.off[id] = off
}

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// engine is an Engine around sp with rec as its sink.
func engine(t testing.TB, sp SPCalls, rec Sink, clk *clock) *Engine {
	t.Helper()
	s := DefaultSettings()
	e := &Engine{
		S: s, SP: sp, ISAs: &ISAs{Max: 100}, Discovery: &Discovery{}, Sink: rec, Memory: NewMemory(1000, nil),
		Counters: &core.Counters{}, MapCounters: &core.Counters{},
	}
	if clk != nil {
		e.Now = clk.now
	}
	e.mu.Lock()
	e.init()
	e.mu.Unlock()
	return e
}
