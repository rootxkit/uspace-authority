package dp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/identify"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/timeplace"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// SourceType is this adapter's type in source control and status
// (04 §2 source).
const SourceType = "network_rid"

// Engine counters (E-09).
const (
	CounterViewsOverCap       = "views_over_cap"
	CounterProvidersOverCap   = "providers_over_cap"
	CounterProviderBadID      = "providers_refused_owner_not_a_token"
	CounterProviderBadURL     = "providers_refused_base_url"
	CounterProviderOwnerClash = "providers_owner_conflict"
	CounterRowsQueued         = "rows_queued"
)

// Gate is the source-control switch (internal/sources.Follower).
type Gate interface {
	Query(sourceType string, instanceID *string) coresources.Decision
}

// SPCalls are the Service Provider operations a poll makes (Client).
type SPCalls interface {
	Flights(ctx context.Context, sp string, b Box) (*f3411.GetFlightsResponse, []json.RawMessage, error)
	Details(ctx context.Context, sp, id string) (*f3411.RIDFlightDetails, json.RawMessage, error)
}

// Sink takes what a poll publishes: tracks on trk.v1, identification
// changes on ident.v1 (core NATS), and the rows towards tsdb-writer.
type Sink interface {
	Track(m *Message) error
	Ident(c *track.IdentChange) error
	Rows(tracks []track.Row, flights []FlightRow)
}

// Settings are the Engine's limits (config.DPPollerTuning, R-14).
type Settings struct {
	RequestTimeout     time.Duration
	MaxFlights         int
	MaxTilesPerSP      int
	MaxDetailsPerPoll  int
	DetailsConcurrency int
	UnavailableAfter   time.Duration
	SlowPollHz         float64
	MaxSplitDepth      int
	MaxViews           int
	MaxTiles           int
	MaxProviders       int
	// DetailsTTL is how long fetched details are used before they are
	// fetched again.
	DetailsTTL time.Duration
	// Certified are the ISA owners holding an operating certificate.
	Certified map[string]bool
	Network   timeplace.NetworkPolicy
}

// DefaultSettings are the documented defaults (R-14).
func DefaultSettings() Settings {
	return Settings{
		RequestTimeout: 5 * time.Second, MaxFlights: 500, MaxTilesPerSP: 64, MaxDetailsPerPoll: 20, DetailsConcurrency: 4,
		UnavailableAfter: 10 * time.Second, SlowPollHz: 0.5, MaxSplitDepth: 3, MaxViews: 64, MaxTiles: 512,
		MaxProviders: 256, DetailsTTL: 5 * time.Minute, Network: timeplace.DefaultNetworkPolicy(),
	}
}

// PolicyValues are the authority_policy values the Engine follows:
// dp_poll_hz and dp_view_diagonal_km.
type PolicyValues func() (pollHz, viewDiagonalKM float64)

// Engine is the Display Provider: views to tiles, tiles to the Service
// Providers their ISAs name, and one poller per (Service Provider,
// tile), each at most one request in flight (05 §5).
type Engine struct {
	S         Settings
	SP        SPCalls
	ISAs      *ISAs
	Discovery *Discovery
	// Views lists the boxes to display (oversight areas and console
	// viewports).
	Views    func(ctx context.Context) []Box
	Gate     Gate
	Policy   PolicyValues
	Registry func() identify.Lookup
	Geoid    geoid.Undulator
	Sink     Sink
	Memory   *Memory
	// Counters are the engine's; MapCounters the mapping's.
	Counters    *core.Counters
	MapCounters *core.Counters
	Logger      *slog.Logger
	// Limiter logs each limit at most once a minute (R-14).
	Limiter *logging.Limiter
	Now     func() time.Time

	mu        sync.Mutex
	providers map[string]*Provider // by base URL
	pollers   map[pollKey]*running
	tiles     []Tile
	wg        sync.WaitGroup
}

type pollKey struct {
	base string
	tile string
}

type running struct {
	cancel context.CancelFunc
	isaID  string
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) init() {
	if e.providers == nil {
		e.providers, e.pollers = map[string]*Provider{}, map[pollKey]*running{}
	}
	if e.Counters == nil {
		e.Counters = &core.Counters{}
	}
	if e.MapCounters == nil {
		e.MapCounters = &core.Counters{}
	}
	if e.Memory == nil {
		e.Memory = NewMemory(50000, nil)
	}
	if e.Logger == nil {
		e.Logger = logging.Discard()
	}
	if e.Limiter == nil {
		e.Limiter = logging.NewLimiter(e.Logger, time.Minute, 0, e.Counters)
	}
}

func (e *Engine) policy() (hz, diagKM float64) {
	hz, diagKM = 1, f3411.NetMaxDisplayAreaDiagonalKm
	if e.Policy != nil {
		if h, d := e.Policy(); h > 0 && d > 0 {
			hz, diagKM = h, d
		}
	}
	return hz, min(diagKM, f3411.NetMaxDisplayAreaDiagonalKm)
}

// Tiles is the current root tiles (for discovery).
func (e *Engine) Tiles() []Tile {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.tiles)
}

// Providers lists every Service Provider seen, by id.
func (e *Engine) Providers() []*Provider {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := slices.Collect(maps.Values(e.providers))
	slices.SortFunc(out, func(a, b *Provider) int {
		if a.USSID != b.USSID {
			if a.USSID < b.USSID {
				return -1
			}
			return 1
		}
		if a.BaseURL < b.BaseURL {
			return -1
		}
		return 1
	})
	return out
}

// Pollers is the number of pollers running.
func (e *Engine) Pollers() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pollers)
}

// Enabled is source control's answer for one Service Provider.
func (e *Engine) Enabled(ussID string) bool {
	if e.Gate == nil {
		return true
	}
	return e.Gate.Query(SourceType, &ussID).Enabled
}

// tilesOf computes the root tiles of the views.
func (e *Engine) tilesOf(boxes []Box) []Tile {
	_, diag := e.policy()
	if e.S.MaxViews > 0 && len(boxes) > e.S.MaxViews {
		e.Counters.Add(CounterViewsOverCap, uint64(len(boxes)-e.S.MaxViews))
		e.Limiter.Limited("dp_views_cap").Warn("more views than DP_MAX_VIEWS; the rest are not displayed",
			slog.Int("views", len(boxes)), slog.Int("max", e.S.MaxViews))
		boxes = boxes[:e.S.MaxViews]
	}
	seen := map[string]bool{}
	var out []Tile
	for _, b := range boxes {
		left := e.S.MaxTiles - len(out)
		if e.S.MaxTiles <= 0 {
			left = 1 << 20
		}
		ts, over := TilesOf(b, diag, max(left, 0))
		if over > 0 {
			e.Discovery.Counters.Add(CounterTilesOverCap, uint64(over))
			e.Limiter.Limited("dp_tiles_cap").Warn("more tiles than DP_MAX_TILES; part of a view is not displayed",
				slog.Int("over", over), slog.Int("max", e.S.MaxTiles))
		}
		for _, t := range ts {
			if k := t.Key(); !seen[k] {
				seen[k] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// Reconcile computes the tiles of the views and the pollers they need,
// and starts and stops pollers to match: a disabled Service Provider's
// pollers are stopped at once (SC-16), a tile split after a 413 is
// polled as its quarters, at most MaxTilesPerSP tiles per provider.
func (e *Engine) Reconcile(ctx context.Context) {
	var boxes []Box
	if e.Views != nil {
		boxes = e.Views(ctx)
	}
	tiles := e.tilesOf(boxes)
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.init()
	e.tiles = tiles
	type want struct {
		p     *Provider
		tile  Tile
		isaID string
	}
	desired := map[pollKey]want{}
	perSP := map[*Provider]int{}
	isasPerSP := map[*Provider]map[string]bool{}
	for _, t := range tiles {
		isas := e.ISAs.ForTile(t, now)
		for i := range isas {
			isa := &isas[i]
			p := e.providerLocked(isa, now)
			if p == nil || !e.Enabled(p.USSID) {
				continue
			}
			if isasPerSP[p] == nil {
				isasPerSP[p] = map[string]bool{}
			}
			isasPerSP[p][isa.Id] = true
			for _, leaf := range e.leaves(p, t) {
				k := pollKey{base: p.BaseURL, tile: leaf.Key()}
				if _, dup := desired[k]; dup {
					continue
				}
				if e.S.MaxTilesPerSP > 0 && perSP[p] >= e.S.MaxTilesPerSP {
					p.Counters.Inc(CounterTilesCapped)
					e.Limiter.Limited("dp_sp_tiles_cap:"+p.USSID).Warn("more tiles than DP_MAX_TILES_PER_SP for a Service Provider; the rest are not polled",
						slog.String("uss_id", p.USSID), slog.Int("max", e.S.MaxTilesPerSP))
					continue
				}
				perSP[p]++
				desired[k] = want{p: p, tile: leaf, isaID: isa.Id}
			}
		}
	}
	for _, p := range e.providers {
		p.SetShape(perSP[p], len(isasPerSP[p]))
	}
	for k, r := range e.pollers {
		if _, ok := desired[k]; !ok {
			r.cancel()
			delete(e.pollers, k)
			if p := e.providers[k.base]; p != nil && !e.Enabled(p.USSID) {
				p.Counters.Inc(CounterPollsDisabled)
			}
		}
	}
	for k, w := range desired {
		if _, ok := e.pollers[k]; ok {
			continue
		}
		pctx, cancel := context.WithCancel(ctx)
		e.pollers[k] = &running{cancel: cancel, isaID: w.isaID}
		e.wg.Go(func() { e.runPoller(pctx, w.p, w.tile, w.isaID) })
	}
}

// leaves is t, or its quarters (recursively) where p answered 413.
func (e *Engine) leaves(p *Provider, t Tile) []Tile {
	if t.Depth >= e.S.MaxSplitDepth || !p.IsSplit(t.Key()) {
		return []Tile{t}
	}
	var out []Tile
	for _, q := range t.Split4() {
		out = append(out, e.leaves(p, q)...)
	}
	return out
}

// providerLocked is the provider an ISA names, created on first sight
// (bounded); nil when the ISA cannot be polled: an owner that is not a
// subject token, a base URL refused (plain http to a non-loopback host)
// or the bound reached. e.mu is held.
func (e *Engine) providerLocked(isa *f3411.IdentificationServiceArea, now time.Time) *Provider {
	base := isa.UssBaseUrl
	if p, ok := e.providers[base]; ok {
		if p.USSID != isa.Owner {
			e.Counters.Inc(CounterProviderOwnerClash)
		}
		return p
	}
	if _, err := bus.Token("uss_id", isa.Owner); err != nil {
		e.Counters.Inc(CounterProviderBadID)
		e.Limiter.Limited("dp_bad_owner").Warn("an ISA's owner is not usable as a source instance; its Service Provider is not polled",
			slog.String("isa_id", isa.Id))
		return nil
	}
	if _, err := CheckBaseURL(base); err != nil {
		e.Counters.Inc(CounterProviderBadURL)
		if errors.Is(err, ErrPlainHTTP) {
			e.Counters.Inc(CounterPlainHTTP)
		}
		e.Limiter.Limited("dp_bad_base_url:"+isa.Owner).Warn("an ISA's uss_base_url is refused; its Service Provider is not polled",
			slog.String("uss_id", isa.Owner), slog.String("error", err.Error()))
		return nil
	}
	if e.S.MaxProviders > 0 && len(e.providers) >= e.S.MaxProviders {
		e.Counters.Inc(CounterProvidersOverCap)
		e.Limiter.Limited("dp_providers_cap").Warn("more Service Providers than DP_MAX_PROVIDERS; the new one is not polled",
			slog.String("uss_id", isa.Owner))
		return nil
	}
	known := e.S.Certified[isa.Owner]
	p := NewProvider(isa.Owner, base, known, now)
	if !known {
		p.Counters.Inc(CounterProviderUnknown)
		e.Logger.Warn("Service Provider matches no operating certificate: polled and shown provider_unknown",
			slog.String("uss_id", isa.Owner), slog.String("uss_base_url", base))
	} else {
		e.Logger.Info("Service Provider discovered", slog.String("uss_id", isa.Owner), slog.String("uss_base_url", base))
	}
	e.providers[base] = p
	return p
}

// Run reconciles every second, and at once when source control changes
// (changes may be nil), until ctx ends, then stops every poller.
func (e *Engine) Run(ctx context.Context, changes <-chan struct{}) {
	e.mu.Lock()
	e.init()
	e.mu.Unlock()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		e.Reconcile(ctx)
		select {
		case <-ctx.Done():
			e.mu.Lock()
			for k, r := range e.pollers {
				r.cancel()
				delete(e.pollers, k)
			}
			e.mu.Unlock()
			e.wg.Wait()
			return
		case <-t.C:
		case <-changes:
		}
	}
}

// interval is the time between two polls of p.
func (e *Engine) interval(p *Provider) time.Duration {
	hz, _ := e.policy()
	if p.Slow() && e.S.SlowPollHz > 0 {
		hz = e.S.SlowPollHz
	}
	return time.Duration(float64(time.Second) / hz)
}

func (e *Engine) runPoller(ctx context.Context, p *Provider, t Tile, isaID string) {
	for ctx.Err() == nil {
		start := e.now()
		if !e.Enabled(p.USSID) {
			p.Counters.Inc(CounterPollsDisabled)
			return
		}
		e.Poll(ctx, p, t, isaID)
		wait := e.interval(p) - e.now().Sub(start)
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Poll polls p once for tile t: the flights, the details the limits
// allow, and every changed state mapped and published.
func (e *Engine) Poll(ctx context.Context, p *Provider, t Tile, isaID string) {
	p.Counters.Inc(CounterPolls)
	start := e.now()
	cctx, cancel := context.WithTimeout(ctx, e.S.RequestTimeout)
	resp, raws, err := e.SP.Flights(cctx, p.BaseURL, t.Box)
	cancel()
	took := e.now().Sub(start)
	if err != nil {
		if ctx.Err() != nil {
			return // stopped: not the provider's failure
		}
		e.pollFailed(p, t, err, took, cctx.Err())
		return
	}
	rx := e.now()
	flights := []f3411.RIDFlight{}
	if resp.Flights != nil {
		flights = *resp.Flights
	}
	p.Counters.Add(CounterFlights, uint64(len(flights)))
	if e.S.MaxFlights > 0 && len(flights) > e.S.MaxFlights {
		p.Counters.Add(CounterFlightsTruncated, uint64(len(flights)-e.S.MaxFlights))
		e.Limiter.Limited("dp_flights_cap:"+p.USSID).Warn("more flights in one response than DP_MAX_FLIGHTS_PER_RESPONSE; the rest are not shown this poll",
			slog.String("uss_id", p.USSID), slog.Int("flights", len(flights)), slog.Int("max", e.S.MaxFlights))
		flights = flights[:e.S.MaxFlights]
	}
	p.OK(took, rx, len(flights))
	e.fetchDetails(ctx, p, t, flights, rx)
	var respTS *time.Time
	if v := resp.Timestamp.Value; !v.IsZero() {
		respTS = &v
	}
	var trackRows []track.Row
	var flightRows []FlightRow
	for i := range flights {
		f := &flights[i]
		key := FlightKey{USSID: p.USSID, FlightID: f.Id}
		// A flight in two tiles, or a state already published, is
		// published once (R-14).
		if f.CurrentState != nil && !e.Memory.Fresh(key, f.CurrentState, rx) {
			continue
		}
		details, detailsRaw := e.Memory.DetailsRaw(key)
		mp, ok := Map(&Input{USSID: p.USSID, ISAID: isaID, Flight: f, Details: details, ResponseTS: respTS, RxTS: rx},
			MapDeps{Registry: e.lookup(), Geoid: e.Geoid, Network: e.S.Network, Counters: e.MapCounters})
		if !ok {
			continue
		}
		if err := e.Sink.Track(mp.Message); err != nil {
			p.Counters.Inc(CounterPublishFailed)
			e.Limiter.Limited("dp_publish").Warn("track not published", slog.String("uss_id", p.USSID), slog.String("error", err.Error()))
		} else {
			p.Counters.Inc(CounterPublished)
		}
		prev := e.Memory.Published(key, mp, isaID)
		e.identChange(p, key, mp, prev)
		airborne := mp.Airborne
		row := track.RowOf(&mp.Message.Message, mp.Times, DedupeKey(p.USSID, f.Id, f.CurrentState.Timestamp.Value), &airborne)
		row.USSPID = strPtr(p.USSID)
		trackRows = append(trackRows, row)
		var raw json.RawMessage
		if i < len(raws) {
			raw = raws[i]
		}
		flightRows = append(flightRows, NewFlightRow(p, isaID, f.Id, mp.Message.Body.TrackID, rx, f.CurrentState.Timestamp.Value, raw, detailsRaw))
	}
	if len(trackRows) > 0 {
		e.Counters.Add(CounterRowsQueued, uint64(len(trackRows)))
		e.Sink.Rows(trackRows, flightRows)
	}
}

func (e *Engine) lookup() identify.Lookup {
	if e.Registry == nil {
		return nil
	}
	return e.Registry()
}

// pollFailed counts a failed poll by its cause, splits a tile on a 413
// and records the failure on the provider.
func (e *Engine) pollFailed(p *Provider, t Tile, err error, took time.Duration, deadline error) {
	switch {
	case StatusOf(err) == 413:
		p.Counters.Inc(CounterPolls413)
		if t.Depth < e.S.MaxSplitDepth {
			p.Split(t.Key())
			p.Counters.Inc(CounterSplits)
			e.Limiter.Limited("dp_413:"+p.USSID).Info("Service Provider answered 413: the tile is split into four",
				slog.String("uss_id", p.USSID), slog.Int("depth", t.Depth+1))
			return
		}
		p.Counters.Inc(CounterSplitsExhausted)
		e.Limiter.Limited("dp_413_max:"+p.USSID).Warn("Service Provider answered 413 for a tile already split DP_MAX_SPLIT_DEPTH times",
			slog.String("uss_id", p.USSID), slog.Int("depth", t.Depth))
	case errors.Is(deadline, context.DeadlineExceeded):
		p.Counters.Inc(CounterPollsTimedOut)
	case errors.Is(err, ErrTooLarge):
		p.Counters.Inc(CounterPollsTooLarge)
	case errors.Is(err, ErrPlainHTTP):
		p.Counters.Inc(CounterPlainHTTP)
	default:
		var fe *core.FieldError
		if errors.As(err, &fe) {
			p.Counters.Inc(CounterPollsRefused)
		}
	}
	before := p.UnavailableSince()
	p.Failed(took, e.now(), e.S.UnavailableAfter)
	if since := p.UnavailableSince(); before.IsZero() && !since.IsZero() {
		e.Logger.Warn("Service Provider unavailable: its flights stay on the picture with their age",
			slog.String("uss_id", p.USSID), slog.Time("unavailable_since", since), slog.String("error", err.Error()))
	} else {
		e.Limiter.Limited("dp_poll_failed:"+p.USSID).Warn("poll of a Service Provider failed",
			slog.String("uss_id", p.USSID), slog.String("error", err.Error()))
	}
}

// fetchDetails fetches the details of the flights that have none (or
// whose details are older than DetailsTTL), only for a tile within the
// F3411 details diagonal (NetDetailsMaxDisplayAreaDiagonalKm), at most
// MaxDetailsPerPoll per poll and DetailsConcurrency at once (R-14).
func (e *Engine) fetchDetails(ctx context.Context, p *Provider, t Tile, flights []f3411.RIDFlight, now time.Time) {
	var need []string
	for i := range flights {
		key := FlightKey{USSID: p.USSID, FlightID: flights[i].Id}
		if d, at := e.Memory.Details(key); d != nil && now.Sub(at) < e.S.DetailsTTL {
			continue
		}
		need = append(need, flights[i].Id)
	}
	if len(need) == 0 {
		return
	}
	if DiagonalKM(t.Box) > f3411.NetDetailsMaxDisplayAreaDiagonalKm {
		p.Counters.Add(CounterDetailsLargeTile, uint64(len(need)))
		return
	}
	if len(need) > e.S.MaxDetailsPerPoll {
		p.Counters.Add(CounterDetailsCapped, uint64(len(need)-e.S.MaxDetailsPerPoll))
		e.Limiter.Limited("dp_details_cap:"+p.USSID).Info("more flights without details than DP_MAX_DETAILS_PER_POLL; the rest wait for the next poll",
			slog.String("uss_id", p.USSID), slog.Int("max", e.S.MaxDetailsPerPoll))
		need = need[:e.S.MaxDetailsPerPoll]
	}
	sem := make(chan struct{}, max(1, e.S.DetailsConcurrency))
	var wg sync.WaitGroup
	for _, id := range need {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, e.S.RequestTimeout)
			defer cancel()
			d, raw, err := e.SP.Details(cctx, p.BaseURL, id)
			if err != nil {
				if ctx.Err() == nil {
					p.Counters.Inc(CounterDetailsFailed)
					e.Limiter.Limited("dp_details:"+p.USSID).Warn("flight details not fetched; the flight is shown unidentified until they are",
						slog.String("uss_id", p.USSID), slog.String("error", err.Error()))
				}
				return
			}
			p.Counters.Inc(CounterDetails)
			e.Memory.SetDetailsRaw(FlightKey{USSID: p.USSID, FlightID: id}, d, raw, e.now())
		})
	}
	wg.Wait()
}

// identChange announces the identification on ident.v1 when it differs
// from the last one announced for the flight.
func (e *Engine) identChange(p *Provider, key FlightKey, mp *Mapped, prev *core.Identification) {
	m := &mp.Message.Message
	id := m.Body.Identification
	if !track.IdentChanged(prev, id) {
		return
	}
	if err := e.Sink.Ident(track.NewIdentChange(m, prev, e.now())); err != nil {
		p.Counters.Inc(CounterIdentFailed)
		return
	}
	p.Counters.Inc(CounterIdentChanges)
	e.Memory.Announced(key, id)
}

// DedupeKey makes a redelivered row write once (B-05): the provider,
// the flight and the state's own time.
func DedupeKey(ussID, flightID string, stateTS time.Time) string {
	return "network_rid:" + ussID + ":" + flightID + ":" + stateTS.UTC().Format(time.RFC3339Nano)
}
