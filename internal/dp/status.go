package dp

import (
	"context"
	"log/slog"
	"math"
	"time"

	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Source states of source/status/v1.
const (
	StateLive     = "live"
	StateStale    = "stale"
	StateDown     = "down"
	StateDisabled = "disabled"
	StateUnknown  = "unknown"
)

// StatusBody is source/status/v1's body (uspace-lab
// schemas/common/source/status/v1) with the Display Provider's extras,
// which the schema admits (unknown members are ignored within the major
// version): the ISAs and tiles the Service Provider is polled for, its
// polls and flights, its response times, slow and unavailable since T,
// whether it matches an operating certificate, and the DSS's state.
type StatusBody struct {
	Source           string            `json:"source"`
	SourceInstance   *string           `json:"source_instance"`
	State            string            `json:"state"`
	Since            string            `json:"since"`
	AgeS             *float64          `json:"age_s"`
	DisabledBy       *string           `json:"disabled_by"`
	DisabledByWho    *string           `json:"disabled_by_who"`
	Counters         map[string]uint64 `json:"counters"`
	Lagging          bool              `json:"lagging"`
	LagS             *float64          `json:"lag_s"`
	USSBaseURL       string            `json:"uss_base_url"`
	ISAs             int               `json:"isas"`
	Tiles            int               `json:"tiles"`
	Flights          int               `json:"flights"`
	P95S             float64           `json:"p95_s"`
	P99S             float64           `json:"p99_s"`
	Slow             bool              `json:"slow"`
	UnavailableSince *string           `json:"unavailable_since"`
	ProviderUnknown  bool              `json:"provider_unknown"`
	DSS              string            `json:"dss"`
	DSSSince         *string           `json:"dss_since"`
}

// StatusSchema is the status message's schema.
const StatusSchema = "source/status/v1"

// Status publishes src.v1.network_rid.<uss_id> for every Service
// Provider seen, every interval (04 §3.6): live, down (unavailable since
// T: polls failing for UnavailableAfter; never removed), disabled (by
// whom), or unknown before its first answer; with the counters of every
// limit (R-14, E-09).
type Status struct {
	Engine *Engine
	Pub    bus.Publisher
	// Who says who switched a source off (sources.Follower).
	Who     func(sourceType string, instanceID *string) *string
	Logger  *slog.Logger
	Limiter *logging.Limiter
	Now     func() time.Time

	since map[string]sinceOf
}

type sinceOf struct {
	state string
	at    time.Time
}

func (s *Status) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func secondsOf(d time.Duration) float64 { return math.Round(d.Seconds()*1000) / 1000 }

// Snapshot is the status of p at now.
func (s *Status) Snapshot(p *Provider, now time.Time) StatusBody {
	e := s.Engine
	inst := p.USSID
	tiles, isas, flights := p.Shape()
	p95, p99 := p.Percentiles()
	b := StatusBody{
		Source: SourceType, SourceInstance: &inst, Counters: p.Counters.Snapshot(), USSBaseURL: p.BaseURL,
		ISAs: isas, Tiles: tiles, Flights: flights, P95S: secondsOf(p95), P99S: secondsOf(p99), Slow: p.Slow(),
		ProviderUnknown: !p.Known(),
	}
	if e.Discovery != nil {
		st, since := e.Discovery.State()
		b.DSS = st
		if !since.IsZero() && st != DSSOK {
			v := bus.Stamp(since)
			b.DSSSince = &v
		}
	}
	last := p.LastOK()
	if !last.IsZero() {
		age := math.Max(0, now.Sub(last).Seconds())
		b.AgeS = &age
	}
	d := coresources.Decision{Enabled: true}
	if e.Gate != nil {
		d = e.Gate.Query(SourceType, &inst)
	}
	unavailable := p.UnavailableSince()
	switch {
	case !d.Enabled:
		by := string(coresources.WhyInstance)
		if d.WhyDisabled != nil {
			by = string(*d.WhyDisabled)
		}
		b.State, b.DisabledBy = StateDisabled, &by
		if s.Who != nil {
			b.DisabledByWho = s.Who(SourceType, &inst)
		}
	case !unavailable.IsZero():
		b.State = StateDown
		v := bus.Stamp(unavailable)
		b.UnavailableSince = &v
	case last.IsZero():
		b.State = StateUnknown
	default:
		b.State = StateLive
	}
	if s.since == nil {
		s.since = map[string]sinceOf{}
	}
	key := p.BaseURL
	prev, ok := s.since[key]
	if !ok || prev.state != b.State {
		at := now
		if b.State == StateDown {
			at = unavailable
		}
		prev = sinceOf{state: b.State, at: at}
		s.since[key] = prev
	}
	b.Since = bus.Stamp(prev.at)
	return b
}

// Publish sends every provider's status once and returns how many.
func (s *Status) Publish(now time.Time) int {
	n := 0
	for _, p := range s.Engine.Providers() {
		subject, err := bus.Subjects.Src(SourceType, p.USSID)
		if err != nil {
			continue
		}
		env := bus.SystemEnvelope(StatusSchema, Producer, now, s.Snapshot(p, now))
		if err := bus.PublishCore(s.Pub, subject, env); err != nil {
			if s.Limiter != nil {
				s.Limiter.Limited("dp_status_publish").Warn("Service Provider status not published", slog.String("error", err.Error()))
			}
			continue
		}
		n++
	}
	return n
}

// Run publishes every interval until ctx ends.
func (s *Status) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Publish(s.now())
		}
	}
}
