package sources

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// StatusBody is the body of source/status/v1 (uspace-lab
// schemas/common/source/status/v1) with the extras an adapter may add.
type StatusBody struct {
	Source         string            `json:"source"`
	SourceInstance *string           `json:"source_instance"`
	State          string            `json:"state"`
	Since          string            `json:"since"`
	AgeS           *float64          `json:"age_s"`
	DisabledBy     *string           `json:"disabled_by"`
	DisabledByWho  *string           `json:"disabled_by_who"`
	Counters       map[string]uint64 `json:"counters"`
	Lagging        bool              `json:"lagging"`
	LagS           *float64          `json:"lag_s"`
}

// Status is the last status of one source and when api received it.
type Status struct {
	Body       StatusBody
	ReceivedAt time.Time
}

// Counter names of the store (E-09, E-10).
const (
	CounterStatusReceived  = "status_received"
	CounterStatusMalformed = "status_malformed"
	CounterStatusEvicted   = "status_evicted"
	// CounterStatusUnknownType counts statuses naming a source type
	// this system does not know, refused (audit B-N6).
	CounterStatusUnknownType = "status_unknown_type"
)

// StatusStore keeps the last source/status/v1 per (type, instance), at
// most Max sources: past it the source heard longest ago is evicted and
// counted (E-10).
type StatusStore struct {
	Max      int
	Counters *core.Counters
	Now      func() time.Time

	mu   sync.Mutex
	last map[key]Status
}

func (s *StatusStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *StatusStore) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

// Offer takes one message of src.v1.>.
func (s *StatusStore) Offer(raw []byte) {
	var env bus.Envelope[StatusBody]
	if err := json.Unmarshal(raw, &env); err != nil || env.Schema != "source/status/v1" || env.Body.Source == "" {
		s.inc(CounterStatusMalformed)
		return
	}
	s.inc(CounterStatusReceived)
	if !slices.Contains(Types, env.Body.Source) {
		// Bounded is not enough: a flood of invented types would evict
		// every real source (audit B-N6).
		s.inc(CounterStatusUnknownType)
		return
	}
	k := keyOf(env.Body.Source, env.Body.SourceInstance)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last = map[key]Status{}
	}
	if _, ok := s.last[k]; !ok && s.Max > 0 && len(s.last) >= s.Max {
		var oldest key
		var at time.Time
		first := true
		for kk := range s.last {
			if r := s.last[kk].ReceivedAt; first || r.Before(at) {
				oldest, at, first = kk, r, false
			}
		}
		delete(s.last, oldest)
		s.inc(CounterStatusEvicted)
	}
	s.last[k] = Status{Body: env.Body, ReceivedAt: s.now()}
}

// Get is the last status of (sourceType, instanceID).
func (s *StatusStore) Get(sourceType string, instanceID *string) (Status, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.last[keyOf(sourceType, instanceID)]
	return st, ok
}

// Instances lists the (type, instance) pairs heard, sorted.
func (s *StatusStore) Instances() [][2]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][2]string, 0, len(s.last))
	for k := range s.last {
		if !k.whole {
			out = append(out, [2]string{k.sourceType, k.instanceID})
		}
	}
	slices.SortFunc(out, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	return out
}

// Len is the number of sources held.
func (s *StatusStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.last)
}

// Run subscribes to src.v1.> on nc until ctx ends; the subscription
// survives reconnects.
func (s *StatusStore) Run(ctx context.Context, nc *nats.Conn, logger *slog.Logger) {
	ch := make(chan *nats.Msg, 256)
	for ctx.Err() == nil {
		sub, err := nc.ChanSubscribe(bus.SubjectSrcAll, ch)
		if err == nil {
			for {
				select {
				case <-ctx.Done():
					_ = sub.Unsubscribe()
					return
				case m := <-ch:
					s.Offer(m.Data)
				}
			}
		}
		if logger != nil {
			logger.Debug("source status subscription unavailable; retrying", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// Health values the console shows beside the switch (B-11).
const (
	HealthHealthy    = "healthy"
	HealthStale      = "stale"
	HealthLagging    = "lagging"
	HealthNeverHeard = "never_heard"
)

// Health is what the console shows of a source's last status: never
// heard (no status, or the adapter has never heard it), stale (the
// adapter says so, or its status itself is older than staleAfter: the
// adapter is silent), lagging (live but replaying old backlog) or
// healthy. A disabled source is healthy while it is still heard (its
// refusals rise), stale once silent.
func Health(st Status, have bool, now time.Time, staleAfter time.Duration) string {
	if !have {
		return HealthNeverHeard
	}
	if now.Sub(st.ReceivedAt) > staleAfter {
		return HealthStale
	}
	b := st.Body
	switch b.State {
	case "live":
		if b.Lagging {
			return HealthLagging
		}
		return HealthHealthy
	case "stale", "down":
		return HealthStale
	case "disabled":
		switch {
		case b.AgeS == nil:
			return HealthNeverHeard
		case *b.AgeS <= staleAfter.Seconds():
			return HealthHealthy
		}
		return HealthStale
	}
	return HealthNeverHeard
}

// NewStatusStore returns a store of at most maxSources sources with its
// own counters.
func NewStatusStore(maxSources int) *StatusStore {
	return &StatusStore{Max: maxSources, Counters: &core.Counters{}}
}
