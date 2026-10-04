package intents

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// State is the DSS as the detector sees it.
type State string

// The states.
const (
	// StateUnconfigured: no DSS base URL or no client secret; nothing is
	// read and no_authorisation is not judged (said at error level while
	// a U-space airspace is in force).
	StateUnconfigured State = "dss_unconfigured"
	// StateNoUSpace: no U-space airspace is in force (spec 08 Q2: none is
	// designated yet); there is nothing to read or judge.
	StateNoUSpace State = "no_uspace_designated"
	// StateStarting: a U-space airspace is in force and the DSS has not
	// answered yet.
	StateStarting State = "starting"
	// StateAvailable: the last reads were answered.
	StateAvailable State = "available"
	// StateUnavailable: a read failed; the detector is suspended (it
	// raises nothing and clears nothing on a match) until one succeeds.
	StateUnavailable State = "dss_unavailable"
)

// Counter names of the board (E-09).
const (
	CounterZoneReads         = "intent_zone_reads"           // a U-space airspace read from the DSS
	CounterPositionReads     = "intent_position_reads"       // an aircraft's position read from the DSS
	CounterReadsFailed       = "intent_reads_failed"         // a read the DSS did not answer, or answered with a refusal: the detector is suspended
	CounterAnsweredFromCache = "intent_checks_from_cache"    // an aircraft judged without a read: no cached intent of its airspace could match
	CounterChecksRefused     = "intent_checks_refused"       // a new aircraft refused for MaxTracks: it is not judged for no_authorisation
	CounterChecksDeferred    = "intent_checks_deferred"      // an aircraft not checked this step for ChecksPerStep: checked in a later one
	CounterZonesNotWatched   = "uspace_zones_not_watched"    // a U-space airspace past MaxZones: its aircraft are not judged
	CounterWantsExpired      = "intent_checks_expired"       // an aircraft no worker asked about for WantTTL: forgotten
	CounterZoneNotBounded    = "uspace_zone_not_bounded"     // a U-space airspace whose box cannot be read as an area: not watched
	CounterOutcomesTruncated = "intent_candidates_truncated" // an outcome with more candidates than MaxCandidates
)

// Settings bound a Board (config.DetectIntents).
type Settings struct {
	// Requery is the period of the reads of every U-space airspace
	// (the DSS subscription the brief names needs a scope the authority
	// does not hold, Q-A5; the period stands in for it).
	Requery time.Duration
	// Horizon is how far ahead an airspace is read (the next hour).
	Horizon time.Duration
	// Recheck is the least time between two reads of one aircraft's
	// position; ChecksPerStep bounds the reads of one step.
	Recheck       time.Duration
	ChecksPerStep int
	// CheckRadiusM is the radius of the area asked for an aircraft;
	// VerticalMarginM widens its height each way.
	CheckRadiusM    float64
	VerticalMarginM float64
	// OutcomeMaxAge is how long an outcome stands for the aircraft.
	OutcomeMaxAge time.Duration
	// WantTTL forgets an aircraft no worker asked about for that long.
	WantTTL time.Duration
	// MaxTracks bounds the aircraft held; MaxZones the airspaces read;
	// MaxCandidates the candidates an outcome carries.
	MaxTracks, MaxZones, MaxCandidates int
	// MaxCached bounds the cache; EndedKeep keeps an ended intent for the
	// reasons that long after its time_end.
	MaxCached int
	EndedKeep time.Duration
	// Timeout bounds one read.
	Timeout time.Duration
}

// DefaultSettings are config.DetectIntents's defaults.
func DefaultSettings() Settings {
	return Settings{
		Requery: 5 * time.Second, Horizon: time.Hour, Recheck: 2 * time.Second, ChecksPerStep: 20,
		CheckRadiusM: 10, VerticalMarginM: 10, OutcomeMaxAge: 10 * time.Second, WantTTL: 30 * time.Second,
		MaxTracks: 10_000, MaxZones: 64, MaxCandidates: 16, MaxCached: 10_000, EndedKeep: 10 * time.Minute,
		Timeout: 5 * time.Second,
	}
}

// Query asks for the intents at an aircraft's sample.
type Query struct {
	TrackID string
	// ZoneKey is the U-space airspace the aircraft is in
	// (ZoneKeyOf(country, identifier)).
	ZoneKey string
	Pos     core.LatLon
	// AltHAEM is the height above the WGS84 ellipsoid (the track's
	// alt_wgs84_m), nil when the track has none: the position is then
	// asked without a height (VerticalChecked false).
	AltHAEM *float64
	At      time.Time
}

// ZoneKeyOf names a U-space airspace on the board.
func ZoneKeyOf(country, identifier string) string { return country + "/" + identifier }

type want struct {
	q                  Query
	askedAt, checkedAt time.Time
}

type zoneEntry struct {
	key  string
	zone *zones.Zone
}

// Board is the detector's view of the operational intents, shared by
// every worker of the process: the workers ask for their aircraft inside
// a U-space airspace (Want) and read the outcome (Outcome); Run reads the
// DSS. Safe for concurrent use; no lock is held during a read.
type Board struct {
	S        Settings
	DSS      DSS // nil: unconfigured
	Zones    func() []*zones.Zone
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	Now      func() time.Time

	mu       sync.Mutex
	cache    *Cache
	wants    map[string]*want
	outcomes map[string]Outcome
	state    State
	since    time.Time
	lastErr  string
	watched  []string
	nextZone time.Time
}

// NewBoard returns a board reading dss (nil: unconfigured).
func NewBoard(s Settings, dss DSS, zs func() []*zones.Zone, counters *core.Counters) *Board {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Board{S: s, DSS: dss, Zones: zs, Counters: counters, cache: NewCache(s.MaxCached, s.EndedKeep, counters),
		wants: map[string]*want{}, outcomes: map[string]Outcome{}, state: StateStarting}
}

func (b *Board) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

// Want asks for the intents at q (never blocks on the DSS). A new
// aircraft past MaxTracks is refused and counted; it is not judged.
func (b *Board) Want(q Query) {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	w, ok := b.wants[q.TrackID]
	if !ok {
		if b.S.MaxTracks > 0 && len(b.wants) >= b.S.MaxTracks {
			b.Counters.Inc(CounterChecksRefused)
			return
		}
		w = &want{}
		b.wants[q.TrackID] = w
	}
	w.q, w.askedAt = q, now
}

// Forget drops an aircraft that left every U-space airspace.
func (b *Board) Forget(trackID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.wants, trackID)
	delete(b.outcomes, trackID)
}

// Outcome is the aircraft's outcome when one stands: the DSS available
// and the outcome at most OutcomeMaxAge old. Otherwise the aircraft's
// authorisation is unknown, and the detector neither raises nor clears.
func (b *Board) Outcome(trackID string) (Outcome, bool) {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != StateAvailable {
		return Outcome{}, false
	}
	o, ok := b.outcomes[trackID]
	if !ok || now.Sub(o.CheckedAt) > b.S.OutcomeMaxAge {
		return Outcome{}, false
	}
	return o, true
}

// State is the DSS state and since when it holds.
func (b *Board) State() (State, time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state, b.since
}

func (b *Board) setState(s State, now time.Time, cause string) {
	if b.state != s {
		b.state, b.since = s, now
	}
	b.lastErr = cause
}

// Run steps the board every second until ctx ends.
func (b *Board) Run(ctx context.Context, period time.Duration) {
	if period <= 0 {
		period = time.Second
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		b.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Step is one round: the airspaces in force read when due, then the
// aircraft whose outcome is due, then the purge (the cache never holds
// peer data past 24 h, F3548).
func (b *Board) Step(ctx context.Context) {
	now := b.now()
	zs := b.uspaceZones()
	b.mu.Lock()
	b.watched = b.watched[:0]
	for _, z := range zs {
		b.watched = append(b.watched, z.key)
	}
	b.cache.Purge(now)
	b.expireWants(now)
	switch {
	case b.DSS == nil:
		b.setState(StateUnconfigured, now, "")
		b.mu.Unlock()
		return
	case len(zs) == 0:
		b.setState(StateNoUSpace, now, "")
		b.nextZone = time.Time{}
		b.mu.Unlock()
		return
	}
	zoneDue := !now.Before(b.nextZone)
	b.mu.Unlock()

	if zoneDue {
		ok := b.readZones(ctx, zs, now)
		b.mu.Lock()
		b.nextZone = now.Add(b.S.Requery)
		if ok {
			b.setState(StateAvailable, now, "")
		}
		b.mu.Unlock()
	}
	b.checkPositions(ctx, now)
}

// uspaceZones are the U-space airspaces in force, by key, at most
// MaxZones (the rest counted).
func (b *Board) uspaceZones() []zoneEntry {
	if b.Zones == nil {
		return nil
	}
	var out []zoneEntry
	seen := map[string]bool{}
	for _, z := range b.Zones() {
		if z == nil || z.Type != core.ZoneUSpace {
			continue
		}
		k := ZoneKeyOf(z.Country, z.Identifier)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, zoneEntry{key: k, zone: z})
	}
	slices.SortFunc(out, func(a, c zoneEntry) int { return strings.Compare(a.key, c.key) })
	if b.S.MaxZones > 0 && len(out) > b.S.MaxZones {
		b.Counters.Add(CounterZonesNotWatched, uint64(len(out)-b.S.MaxZones))
		out = out[:b.S.MaxZones]
	}
	return out
}

// expireWants forgets aircraft no worker asked about for WantTTL.
func (b *Board) expireWants(now time.Time) {
	for id, w := range b.wants {
		if now.Sub(w.askedAt) > b.S.WantTTL {
			delete(b.wants, id)
			delete(b.outcomes, id)
			b.Counters.Inc(CounterWantsExpired)
		}
	}
}

// fail records a read the DSS did not answer: the detector is suspended.
func (b *Board) fail(now time.Time, what string, err error) {
	b.Counters.Inc(CounterReadsFailed)
	b.mu.Lock()
	b.setState(StateUnavailable, now, what+": "+err.Error())
	b.mu.Unlock()
	if b.Limiter != nil {
		b.Limiter.Limited("intents_read_failed").Warn("the DSS did not answer an operational intent read; no_authorisation is suspended until it does",
			slog.String("read", what), slog.String("error", err.Error()))
	} else if b.Logger != nil {
		b.Logger.Warn("the DSS did not answer an operational intent read; no_authorisation is suspended until it does",
			slog.String("read", what), slog.String("error", err.Error()))
	}
}

func (b *Board) query(ctx context.Context, aoi f3548.Volume4D) ([]f3548.OperationalIntentReference, error) {
	timeout := b.S.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return b.DSS.Query(qctx, aoi)
}

// readZones reads every airspace over [now, now+Horizon]; it stops at the
// first failure and reports whether all were read.
func (b *Board) readZones(ctx context.Context, zs []zoneEntry, now time.Time) bool {
	for _, z := range zs {
		aoi, ok := zoneArea(z.zone, now, now.Add(b.S.Horizon))
		if !ok {
			b.Counters.Inc(CounterZoneNotBounded)
			continue
		}
		refs, err := b.query(ctx, aoi)
		if err != nil {
			b.fail(now, "airspace "+z.key, err)
			return false
		}
		b.Counters.Inc(CounterZoneReads)
		b.mu.Lock()
		b.cache.Sync(z.key, refs, now)
		b.mu.Unlock()
	}
	return true
}

// zoneArea is the area of interest of an airspace: its bounding box as a
// polygon (the box is conservative, uspace-core zones), every height, the
// window given.
func zoneArea(z *zones.Zone, from, to time.Time) (f3548.Volume4D, bool) {
	bb := z.BBox
	if !(bb.MinLat < bb.MaxLat) || !(bb.MinLon < bb.MaxLon) {
		return f3548.Volume4D{}, false
	}
	poly := f3548.Polygon{Vertices: []f3548.LatLngPoint{
		{Lat: bb.MinLat, Lng: bb.MinLon}, {Lat: bb.MinLat, Lng: bb.MaxLon}, {Lat: bb.MaxLat, Lng: bb.MaxLon}, {Lat: bb.MaxLat, Lng: bb.MinLon},
	}}
	return f3548.Volume4D{
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: from.UTC()},
		TimeEnd:   &f3548.Time{Format: f3548.RFC3339, Value: to.UTC()},
		Volume:    f3548.Volume3D{OutlinePolygon: &poly},
	}, true
}

// pointArea is the area of interest of an aircraft's sample: a circle of
// CheckRadiusM around it, its WGS84 height widened by VerticalMarginM
// when known, one second either side of captured_at.
func (b *Board) pointArea(q Query) f3548.Volume4D {
	c := q.Pos
	v := f3548.Volume3D{OutlineCircle: &f3548.Circle{
		Center: &f3548.LatLngPoint{Lat: c.LatDeg, Lng: c.LonDeg},
		Radius: &f3548.Radius{Units: f3548.RadiusUnitsM, Value: float32(b.S.CheckRadiusM)},
	}}
	if q.AltHAEM != nil && core.IsFinite(*q.AltHAEM) {
		lo := f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: *q.AltHAEM - b.S.VerticalMarginM}
		hi := f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: *q.AltHAEM + b.S.VerticalMarginM}
		v.AltitudeLower, v.AltitudeUpper = &lo, &hi
	}
	return f3548.Volume4D{
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: q.At.Add(-time.Second).UTC()},
		TimeEnd:   &f3548.Time{Format: f3548.RFC3339, Value: q.At.Add(time.Second).UTC()},
		Volume:    v,
	}
}

// due are the aircraft whose outcome is due (never checked, or checked
// Recheck ago), the longest waiting first, at most ChecksPerStep (the
// rest counted deferred).
func (b *Board) due(now time.Time) []Query {
	b.mu.Lock()
	defer b.mu.Unlock()
	type item struct {
		q  Query
		at time.Time
	}
	var items []item
	for _, w := range b.wants {
		if w.checkedAt.IsZero() || now.Sub(w.checkedAt) >= b.S.Recheck {
			items = append(items, item{w.q, w.checkedAt})
		}
	}
	slices.SortFunc(items, func(a, c item) int {
		if !a.at.Equal(c.at) {
			return a.at.Compare(c.at)
		}
		return strings.Compare(a.q.TrackID, c.q.TrackID)
	})
	if n := b.S.ChecksPerStep; n > 0 && len(items) > n {
		b.Counters.Add(CounterChecksDeferred, uint64(len(items)-n))
		items = items[:n]
	}
	out := make([]Query, 0, len(items))
	for _, it := range items {
		out = append(out, it.q)
	}
	return out
}

// checkPositions judges the due aircraft while the DSS is available: from
// the cache when no intent of the airspace could match, else from a read
// of the aircraft's position; a failed read suspends the detector.
func (b *Board) checkPositions(ctx context.Context, now time.Time) {
	b.mu.Lock()
	available := b.state == StateAvailable
	b.mu.Unlock()
	if !available {
		return
	}
	for _, q := range b.due(now) {
		b.mu.Lock()
		inZone := b.cache.InZone(q.ZoneKey)
		b.mu.Unlock()
		possible := slices.ContainsFunc(inZone, func(e Entry) bool { return couldMatch(&e, q.At) })
		var here []f3548.OperationalIntentReference
		if possible {
			refs, err := b.query(ctx, b.pointArea(q))
			if err != nil {
				b.fail(now, "aircraft "+q.TrackID, err)
				return
			}
			b.Counters.Inc(CounterPositionReads)
			here = refs
		} else {
			b.Counters.Inc(CounterAnsweredFromCache)
		}
		o := Judge(inZone, here, q.At, q.AltHAEM != nil, b.S.MaxCandidates)
		o.TrackID, o.CheckedAt = q.TrackID, now
		if o.Truncated {
			b.Counters.Inc(CounterOutcomesTruncated)
		}
		b.mu.Lock()
		if len(here) > 0 {
			b.cache.Add(q.ZoneKey, here, now)
		}
		if w, ok := b.wants[q.TrackID]; ok {
			w.checkedAt = now
			b.outcomes[q.TrackID] = o
		}
		b.mu.Unlock()
	}
}

// Stats are the board's numbers for the status line.
type Stats struct {
	State            State
	Since            time.Time
	LastError        string
	Watched          []string
	Cached           int
	Withdrawn        int
	OldestCached     time.Time
	Aircraft         int
	Outcomes         int
	Matched          int
	OldestOutcomeAge time.Duration
}

// Stats reads the board.
func (b *Board) Stats() Stats {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	s := Stats{State: b.state, Since: b.since, LastError: b.lastErr, Watched: slices.Clone(b.watched),
		Cached: b.cache.Len(), Withdrawn: b.cache.Withdrawn(), OldestCached: b.cache.Oldest(), Aircraft: len(b.wants), Outcomes: len(b.outcomes)}
	for _, o := range b.outcomes {
		if o.Matched {
			s.Matched++
		}
		if age := now.Sub(o.CheckedAt); age > s.OldestOutcomeAge {
			s.OldestOutcomeAge = age
		}
	}
	return s
}

// StatusAttrs are the board's status-line attributes (WP-26: zones
// watched, intents cached, DSS state, matches).
func (b *Board) StatusAttrs() []slog.Attr {
	s := b.Stats()
	attrs := []slog.Attr{
		slog.String("dss_state", string(s.State)), slog.Any("uspace_zones_watched", s.Watched),
		slog.Int("intents_cached", s.Cached), slog.Int("intents_withdrawn", s.Withdrawn),
		slog.Int("aircraft_in_uspace", s.Aircraft), slog.Int("aircraft_matched", s.Matched),
	}
	if !s.OldestCached.IsZero() {
		attrs = append(attrs, slog.Float64("oldest_intent_age_s", b.now().Sub(s.OldestCached).Seconds()))
	}
	if s.State == StateUnavailable {
		attrs = append(attrs, slog.Time("dss_unavailable_since", s.Since), slog.String("dss_last_error", s.LastError))
	}
	return []slog.Attr{slog.GroupAttrs("no_authorisation", attrs...)}
}

// Problems is what keeps no_authorisation from being judged, for the
// detector's not_judged list (E-02): nothing while no U-space airspace is
// in force or the DSS answers.
func (b *Board) Problems() []string {
	s := b.Stats()
	inForce := b.inForce()
	switch s.State {
	case StateUnconfigured:
		if inForce {
			return []string{"no_authorisation not judged: no DSS (DSS_BASE_URL and DETECT_CLIENT_SECRET_FILE) while a U-space airspace is in force"}
		}
	case StateUnavailable:
		return []string{"no_authorisation suspended: the DSS is unavailable since " + s.Since.UTC().Format(time.RFC3339) + " (" + s.LastError + ")"}
	case StateStarting:
		if inForce {
			return []string{"no_authorisation not judged yet: the DSS has not answered"}
		}
	case StateNoUSpace, StateAvailable:
	}
	return nil
}

// inForce reports whether a U-space airspace is in force.
func (b *Board) inForce() bool {
	if b.Zones == nil {
		return false
	}
	return slices.ContainsFunc(b.Zones(), func(z *zones.Zone) bool { return z != nil && z.Type == core.ZoneUSpace })
}
