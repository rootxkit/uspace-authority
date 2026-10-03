package dp

import (
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
)

// Counters of a Service Provider (R-14: every limit has one; E-09).
const (
	CounterPolls             = "polls"
	CounterPollsOK           = "polls_ok"
	CounterPollsFailed       = "polls_failed"
	CounterPollsTimedOut     = "polls_timed_out"
	CounterPolls413          = "polls_413"
	CounterSplits            = "tiles_split_after_413"
	CounterSplitsExhausted   = "tiles_413_at_max_split"
	CounterPollsTooLarge     = "responses_over_body_cap"
	CounterPollsRefused      = "responses_refused"
	CounterFlights           = "flights_received"
	CounterFlightsTruncated  = "flights_over_response_cap"
	CounterPublished         = "states_published"
	CounterPublishFailed     = "states_publish_failed"
	CounterDetails           = "details_fetched"
	CounterDetailsFailed     = "details_failed"
	CounterDetailsCapped     = "details_over_poll_cap"
	CounterDetailsLargeTile  = "details_skipped_tile_over_2km"
	CounterTilesCapped       = "tiles_over_sp_cap"
	CounterPollsDisabled     = "polls_stopped_source_disabled"
	CounterPlainHTTP         = "polls_refused_plain_http"
	CounterProviderUnknown   = "provider_unknown"
	CounterIdentChanges      = "ident_changes_published"
	CounterIdentFailed       = "ident_publish_failed"
	CounterMarkedSlow        = "marked_slow"
	CounterMarkedUnavailable = "marked_unavailable"
)

// latencyWindow is how many response times the percentiles are taken
// over.
const latencyWindow = 100

// slowAfter is the F3411 p99 a Service Provider must answer within
// (NetSpDataResponseTime99thPercentileSeconds); slower, it is polled at
// the slow rate and shown slow with its age (05 §5).
const slowAfter = f3411.NetSpDataResponseTime99thPercentileSeconds * time.Second

// Provider is one Service Provider as the Display Provider sees it: the
// uss_base_url an ISA named and the ISA's owner (its client id at the
// DSS, the source instance of its tracks). Safe for concurrent use.
type Provider struct {
	USSID   string
	BaseURL string
	// known is false when the owner matches no operating certificate:
	// still polled, shown provider_unknown (nothing hidden). It follows
	// the certificate register (Engine.Certified) on every reconcile.
	known atomic.Bool

	Counters core.Counters

	mu               sync.Mutex
	latencies        []time.Duration
	next             int
	lastOK           time.Time
	failingSince     time.Time
	unavailableSince time.Time
	slow             bool
	splits           map[string]bool
	tiles            int
	isas             int
	flights          int
	firstSeen        time.Time
}

// NewProvider returns a provider first seen at now.
func NewProvider(ussID, baseURL string, known bool, now time.Time) *Provider {
	p := &Provider{USSID: ussID, BaseURL: baseURL, splits: map[string]bool{}, firstSeen: now}
	p.known.Store(known)
	return p
}

// Known reports whether the owner holds an operating or limited
// certificate.
func (p *Provider) Known() bool { return p.known.Load() }

// SetKnown records whether the owner is certified and reports whether
// that changed.
func (p *Provider) SetKnown(known bool) bool { return p.known.Swap(known) != known }

// OK records a successful poll answered in took at now with n flights.
func (p *Provider) OK(took time.Duration, now time.Time, n int) {
	p.Counters.Inc(CounterPollsOK)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record(took)
	p.lastOK, p.failingSince, p.unavailableSince = now, time.Time{}, time.Time{}
	p.flights = n
	slow := p.percentileLocked(0.99) > slowAfter
	if slow && !p.slow {
		p.Counters.Inc(CounterMarkedSlow)
	}
	p.slow = slow
}

func (p *Provider) record(took time.Duration) {
	if len(p.latencies) < latencyWindow {
		p.latencies = append(p.latencies, took)
		return
	}
	p.latencies[p.next] = took
	p.next = (p.next + 1) % latencyWindow
}

// Failed records a failed poll at now (took: how long it ran). Failing
// for longer than after makes the provider unavailable since the first
// failure; it is never removed (R-14, E-02).
func (p *Provider) Failed(took time.Duration, now time.Time, after time.Duration) {
	p.Counters.Inc(CounterPollsFailed)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.record(took)
	if p.failingSince.IsZero() {
		p.failingSince = now
	}
	if p.unavailableSince.IsZero() && now.Sub(p.failingSince) >= after {
		p.unavailableSince = p.failingSince
		p.Counters.Inc(CounterMarkedUnavailable)
	}
	if p.percentileLocked(0.99) > slowAfter {
		if !p.slow {
			p.Counters.Inc(CounterMarkedSlow)
		}
		p.slow = true
	}
}

// percentileLocked is the q-th percentile of the recent response times
// (nearest rank).
func (p *Provider) percentileLocked(q float64) time.Duration {
	if len(p.latencies) == 0 {
		return 0
	}
	s := slices.Clone(p.latencies)
	slices.Sort(s)
	i := int(math.Ceil(q*float64(len(s)))) - 1
	return s[max(0, min(i, len(s)-1))]
}

// Percentiles are p95 and p99 of the recent response times.
func (p *Provider) Percentiles() (p95, p99 time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.percentileLocked(0.95), p.percentileLocked(0.99)
}

// Slow reports whether the provider is polled at the slow rate.
func (p *Provider) Slow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.slow
}

// UnavailableSince is when the provider became unavailable; zero while
// it answers.
func (p *Provider) UnavailableSince() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.unavailableSince
}

// LastOK is the last successful poll.
func (p *Provider) LastOK() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastOK
}

// Split marks the tile key split after a 413.
func (p *Provider) Split(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.splits[key] = true
}

// IsSplit reports whether the tile key was split for this provider.
func (p *Provider) IsSplit(key string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.splits[key]
}

// SetShape records how many tiles and ISAs the provider is polled for.
func (p *Provider) SetShape(tiles, isas int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tiles, p.isas = tiles, isas
}

// Shape is the provider's tiles, ISAs and flights of the last poll.
func (p *Provider) Shape() (tiles, isas, flights int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tiles, p.isas, p.flights
}

// FirstSeen is when the provider was first named by an ISA.
func (p *Provider) FirstSeen() time.Time { return p.firstSeen }
