package picture

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// Counter names of the hub (E-09, E-10).
const (
	GaugeClientsName           = "picture_clients"
	CounterClientsOpened       = "clients_opened"
	CounterClientsClosed       = "clients_closed"
	CounterRefusedOrigin       = "upgrade_refused_origin"
	CounterRefusedCapacity     = "upgrade_refused_capacity"
	CounterRefusedRequest      = "upgrade_refused_request"
	CounterClosedRelogin       = "closed_relogin"
	CounterClosedUnavailable   = "closed_session_unavailable"
	CounterClosedInvalid       = "closed_invalid_frame"
	CounterClosedWriteFailed   = "closed_write_failed"
	CounterFramesSent          = "frames_sent"
	CounterFramesQueueFull     = "frames_dropped_queue_full"
	CounterFramesThrottled     = "frames_throttled"
	CounterSubscribes          = "subscribes"
	CounterSubscribeTooLarge   = "subscribe_viewport_too_large"
	CounterSnapshots           = "snapshots"
	CounterSnapshotsTruncated  = "snapshots_truncated"
	CounterSubscribesCoalesced = "subscribes_coalesced"
	CounterTracks              = "tracks_received"
	CounterTracksMalformed     = "tracks_malformed"
	CounterTracksBacklog       = "tracks_backlog_not_shown"
	CounterTracksOlder         = "tracks_older_ignored"
	CounterTracksEvicted       = "tracks_evicted"
	CounterTracksAgedOut       = "tracks_aged_out"
	CounterManned              = "manned_received"
	CounterMannedMalformed     = "manned_malformed"
	CounterMannedBacklog       = "manned_backlog_not_shown"
	CounterMannedOlder         = "manned_older_ignored"
	CounterMannedEvicted       = "manned_evicted"
	CounterMannedAgedOut       = "manned_aged_out"
	CounterAlerts              = "alerts_received"
	CounterAlertsMalformed     = "alerts_malformed"
	CounterAlertsAfterClear    = "alerts_after_clear_ignored"
	CounterAlertsEvicted       = "alerts_evicted"
	CounterAlertsForgotten     = "alerts_forgotten"
	CounterSourceStatusFrames  = "source_status_frames"
	CounterStatusFrames        = "status_frames"
	CounterFramesNotEncoded    = "frames_not_encoded"
	CounterSessionRecheckFails = "session_recheck_unavailable"
)

// Degraded slugs of console/status/v1 (docs/runbooks/picture.md).
const (
	DegradedNATS           = "nats_unavailable"
	DegradedProjections    = "projections_unreadable"
	DegradedRegistryAbsent = "registry_projection_absent"
	DegradedCISAbsent      = "cis_absent"
	DegradedCISStale       = "cis_stale"
	DegradedDP             = "dp_unavailable"
	// DegradedManned: the ANSP's manned traffic feed is not live (down
	// since T, stale, or never heard; WP-15): manned aircraft are missing
	// or old, the sky is not empty.
	DegradedManned            = "manned_unavailable"
	DegradedAlertsUnconfirmed = "alerts_unconfirmed"
	DegradedAlertsReplaying   = "alerts_replaying"
	DegradedSessions          = "session_verifier_unavailable"
	DegradedSwitchesUnknown   = "source_control_unknown"
	DegradedPolicyDefault     = "policy_default"
	DegradedTracksEvicted     = "tracks_evicted"
	// Per connection.
	DegradedNoSubscription   = "no_subscription"
	DegradedViewportTooLarge = "viewport_too_large"
	DegradedSessionUnchecked = "session_unchecked"
)

// dp_state values (the authority defines them; the lab's schema takes a
// slug).
const (
	DPPolling     = "polling"
	DPStale       = "stale"
	DPDisabled    = "disabled"
	DPUnavailable = "unavailable"
)

// nats values.
const (
	NATSConnected   = "connected"
	NATSUnavailable = "unavailable"
)

// Conn is one WebSocket connection as the hub uses it; *websocket.Conn
// through WSConn, and fakes in tests.
type Conn interface {
	Read(ctx context.Context) ([]byte, error)
	Write(ctx context.Context, frame []byte) error
	Close(code websocket.StatusCode, reason string) error
}

// PolicyView is what the status frame carries of the active policy.
type PolicyView struct {
	Version        string
	StaleAfterS    float64
	LiveMaxAgeS    float64
	CISStaleBoundS float64
	// Default: no policy has been read yet; the documented defaults
	// (policy.Defaults) are shown and the frame says so.
	Default bool
	// RegNumPattern is the registration-number pattern the public part
	// of an operator number is cut under (empty: regnum.DefaultPattern).
	RegNumPattern string
}

// ProjectionView is what the status frame carries of the projections,
// each age on the database's clock.
type ProjectionView struct {
	// Read: at least one read succeeded.
	Read bool
	// FailingSince is when reads started failing (zero: the last read
	// succeeded).
	FailingSince   time.Time
	RegistryAgeS   *float64
	CISVersion     *string
	CISAgeS        *float64
	ZonesVersion   *string
	RegistryAbsent bool
	CISAbsent      bool
}

// BusView is the state of the bus connection.
type BusView struct {
	Connected bool
	// Since is when the bus was lost (or the process started without
	// it); zero while connected.
	Since time.Time
}

// Inputs are what the status frames are made of; each answers from
// memory. A nil function answers as unknown.
type Inputs struct {
	Policy        func() PolicyView
	Projections   func(now time.Time) ProjectionView
	Bus           func() BusView
	VerifierReady func() bool
	SwitchesKnown func() bool
}

// Config configures a Hub.
type Config struct {
	MaxClients           int
	SendBuffer           int
	WriteTimeout         time.Duration
	StatusInterval       time.Duration
	MaxCells             int
	MaxTracks            int
	MaxManned            int
	MaxAlerts            int
	ThrottleAbove        int
	ThrottleEvery        time.Duration
	AlertSilent          time.Duration
	AlertForget          time.Duration
	SubscribeMaxBytes    int64
	SubscribeMinInterval time.Duration
	SnapshotMaxBytes     int
	SessionRecheck       time.Duration
	SessionGrace         time.Duration
	Now                  func() time.Time
	Logger               *slog.Logger
	Limiter              *logging.Limiter
}

func (c *Config) defaults() {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	defD := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&c.MaxClients, 500)
	def(&c.SendBuffer, 1024)
	def(&c.MaxCells, cell.DefaultViewportMax)
	def(&c.MaxTracks, 50000)
	def(&c.MaxManned, 10000)
	def(&c.MaxAlerts, 10000)
	def(&c.ThrottleAbove, 200)
	defD(&c.WriteTimeout, 5*time.Second)
	defD(&c.StatusInterval, 2*time.Second)
	defD(&c.ThrottleEvery, 500*time.Millisecond)
	defD(&c.AlertSilent, 5*time.Second)
	defD(&c.AlertForget, 120*time.Second)
	defD(&c.SessionRecheck, 15*time.Second)
	defD(&c.SessionGrace, 60*time.Second)
	def(&c.SnapshotMaxBytes, 8<<20)
	if c.SubscribeMaxBytes <= 0 {
		c.SubscribeMaxBytes = 4096
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logger == nil {
		c.Logger = logging.Discard()
	}
	if c.Limiter == nil {
		c.Limiter = logging.NewLimiter(c.Logger, time.Minute, 0, nil)
	}
}

// Hub is the picture: the caches of tracks, manned aircraft and active
// violations, the source view, and the connected consoles with their
// viewports. Messages come in through OfferTrack, OfferManned and
// OfferViolation; Tick sends the status every interval.
type Hub struct {
	cfg      Config
	in       Inputs
	tracks   *cache
	manned   *cache
	alerts   *alertSet
	sources  *SourceView
	counters *core.Counters

	ctx    context.Context
	cancel context.CancelFunc
	poke   chan struct{}

	mu       sync.RWMutex
	clients  map[*client]struct{}
	byCell   map[cell.ID]map[*client]struct{}
	reserved int
	closed   bool

	replaying    atomic.Bool
	lastEvictNS  atomic.Int64
	degradedMu   sync.Mutex
	degradedSeen map[string]time.Time

	// regnum is the validator of the active registration-number
	// pattern, compiled once per pattern.
	regnum atomic.Pointer[regnumFor]

	// testSnapshotHook, when set, runs while a snapshot is built.
	testSnapshotHook func()
}

// NewHub returns a hub over sv (nil: no sources listed).
func NewHub(cfg Config, in Inputs, sv *SourceView, counters *core.Counters) *Hub {
	cfg.defaults()
	if counters == nil {
		counters = &core.Counters{}
	}
	if sv == nil {
		sv = &SourceView{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Hub{
		cfg: cfg, in: in, sources: sv, counters: counters,
		tracks: newCache(cfg.MaxTracks), manned: newCache(cfg.MaxManned),
		alerts: newAlertSet(cfg.MaxAlerts, cfg.MaxAlerts, cfg.AlertSilent, cfg.AlertForget),
		ctx:    ctx, cancel: cancel, poke: make(chan struct{}, 1),
		clients: map[*client]struct{}{}, byCell: map[cell.ID]map[*client]struct{}{},
		degradedSeen: map[string]time.Time{},
	}
}

// Counters are the hub's counters.
func (h *Hub) Counters() *core.Counters { return h.counters }

// Sources is the hub's source view.
func (h *Hub) Sources() *SourceView { return h.sources }

// SetReplaying marks the read-back of active violations in progress
// (degraded alerts_replaying).
func (h *Hub) SetReplaying(on bool) { h.replaying.Store(on) }

// Len is the number of connected consoles.
func (h *Hub) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Sizes are the numbers of tracks, manned aircraft and active violations
// held.
func (h *Hub) Sizes() (tracks, manned, alerts int) {
	return h.tracks.len(), h.manned.len(), h.alerts.len()
}

// Poke asks Run for a status round now (a bus state change).
func (h *Hub) Poke() {
	select {
	case h.poke <- struct{}{}:
	default:
	}
}

// Reserve takes a connection slot, or reports the hub full or closed.
func (h *Hub) Reserve() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.clients)+h.reserved >= h.cfg.MaxClients {
		return false
	}
	h.reserved++
	return true
}

// Release gives back a slot Reserve took that was not used.
func (h *Hub) Release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reserved--
}

// ---- messages in ----------------------------------------------------

// OfferTrack takes one trk.v1 message received at rx: stored as its
// track's latest and sent to every console whose viewport holds its
// cell (throttled per track above ThrottleAbove tracks). A backlog
// sample is history and never shown live.
func (h *Hub) OfferTrack(raw []byte, rx time.Time) {
	h.counters.Inc(CounterTracks)
	m, captured, c5, err := decodeTrack(raw)
	if err != nil {
		h.counters.Inc(CounterTracksMalformed)
		h.cfg.Limiter.Limited("picture_track_malformed").Warn("track message refused", slog.String("error", err.Error()))
		return
	}
	if m.Backlog {
		h.counters.Inc(CounterTracksBacklog)
		return
	}
	h.publicRegs(&m.Body.Identification)
	pos := core.LatLon{LatDeg: m.Body.Position.Lat, LonDeg: m.Body.Position.Lng}
	it := &item{key: m.Body.TrackID, cell: c5, captured: captured, pos: &pos, sourceType: string(m.Body.Source),
		instance: m.Body.SourceInstance, track: m}
	res, evicted := h.tracks.put(it)
	switch {
	case res == putOlder:
		h.counters.Inc(CounterTracksOlder)
		return
	case evicted != nil:
		h.counters.Inc(CounterTracksEvicted)
		h.lastEvictNS.Store(rx.UnixNano())
		h.cfg.Limiter.Limited("picture_tracks_evicted").Error("track cache full: the track updated longest ago was evicted",
			slog.String("evicted", evicted.key), slog.Int("max_tracks", h.cfg.MaxTracks))
	}
	state := h.sources.StateOf(it.sourceType, it.instance)
	var forConsole, forOther []byte
	for _, c := range h.watching(c5) {
		var f []byte
		if c.sess.Console() {
			if forConsole == nil {
				forConsole = h.encodeTrack(it, rx, state, true)
			}
			f = forConsole
		} else {
			if forOther == nil {
				forOther = h.encodeTrack(it, rx, state, false)
			}
			f = forOther
		}
		if f != nil {
			c.offerTrack(it.key, c5, f, rx)
		}
	}
}

// regnumFor is a validator and the pattern it was compiled from.
type regnumFor struct {
	pattern string
	v       *regnum.Validator
}

// publicRegs cuts the operator numbers of id to their public part
// (regnum.PublicPart under the active policy's pattern): the EU
// registration secret a broadcast may carry never leaves the picture,
// for any realm or role (G-04). It is cut once, as the track is taken,
// so the live frames and every snapshot hold the same value.
func (h *Hub) publicRegs(id *core.Identification) {
	v := h.validator()
	for _, reg := range []**string{&id.OperatorReg, &id.RegisteredOperatorReg} {
		if *reg != nil {
			*reg = ptr(v.PublicPart(**reg))
		}
	}
}

// validator is the validator of the active pattern; a pattern that does
// not compile falls back to regnum.DefaultPattern, logged.
func (h *Hub) validator() *regnum.Validator {
	pattern := h.policy().RegNumPattern
	if pattern == "" {
		pattern = regnum.DefaultPattern
	}
	if cur := h.regnum.Load(); cur != nil && cur.pattern == pattern {
		return cur.v
	}
	v, err := regnum.NewValidator(pattern)
	if err != nil {
		h.cfg.Limiter.Limited("picture_regnum_pattern").Error("registration_number_pattern does not compile: operator numbers are cut under the default pattern",
			slog.String("error", err.Error()))
		v, _ = regnum.NewValidator("")
	}
	h.regnum.Store(&regnumFor{pattern: pattern, v: v})
	return v
}

func (h *Hub) encodeTrack(it *item, now time.Time, state string, console bool) []byte {
	f, err := encodeTrack(it.track, it.captured, now, state, console)
	if err != nil {
		h.counters.Inc(CounterFramesNotEncoded)
		return nil
	}
	return f
}

// OfferManned takes one man.v1 message: stored and forwarded as
// received to every console watching its cell with the manned layer.
func (h *Hub) OfferManned(subject string, raw []byte) {
	h.counters.Inc(CounterManned)
	icao24, c5, captured, backlog, rank, err := decodeManned(subject, raw)
	if err != nil {
		h.counters.Inc(CounterMannedMalformed)
		h.cfg.Limiter.Limited("picture_manned_malformed").Warn("manned message refused", slog.String("error", err.Error()))
		return
	}
	if backlog {
		h.counters.Inc(CounterMannedBacklog)
		return
	}
	res, evicted := h.manned.put(&item{key: icao24, cell: c5, captured: captured, ageRank: rank, raw: raw})
	switch {
	case res == putOlder:
		h.counters.Inc(CounterMannedOlder)
		return
	case evicted != nil:
		h.counters.Inc(CounterMannedEvicted)
	}
	for _, c := range h.watching(c5) {
		c.offerLayer(LayerManned, c5, raw)
	}
}

// OfferViolation takes one alrt.v1 message received at rx: raises,
// clears and first sightings are forwarded to the consoles watching its
// cell; republishes refresh the replay set (C-08).
func (h *Hub) OfferViolation(raw []byte, rx time.Time) {
	h.counters.Inc(CounterAlerts)
	if len(raw) > maxMessageBytes {
		h.counters.Inc(CounterAlertsMalformed)
		return
	}
	m, err := violation.Decode(raw)
	var c5 cell.ID
	if err == nil {
		c5, err = cell.Parse(m.Body.Cell5)
	}
	if err != nil {
		h.counters.Inc(CounterAlertsMalformed)
		h.cfg.Limiter.Limited("picture_alert_malformed").Warn("violation message refused", slog.String("error", err.Error()))
		return
	}
	v, evicted := h.alerts.offer(m, raw, c5, rx)
	if evicted {
		h.counters.Inc(CounterAlertsEvicted)
		h.cfg.Limiter.Limited("picture_alerts_evicted").Error("active violation set full: the one heard longest ago left the picture",
			slog.Int("max_alerts", h.cfg.MaxAlerts))
	}
	switch v {
	case alertAfterClear:
		h.counters.Inc(CounterAlertsAfterClear)
		return
	case alertRefresh:
		return
	case alertForward:
	}
	for _, c := range h.watching(c5) {
		c.offerLayer(LayerAlerts, c5, raw)
	}
}

// watching lists the consoles whose viewport holds c5 now; each client
// checks again under its own lock (the viewport may have moved).
func (h *Hub) watching(c5 cell.ID) []*client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	set := h.byCell[c5]
	if len(set) == 0 {
		return nil
	}
	out := make([]*client, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	return out
}

func (h *Hub) snapshotClients() []*client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*client, 0, len(h.clients))
	for c := range h.clients {
		out = append(out, c)
	}
	return out
}

// ---- status ---------------------------------------------------------

// statusParts are the members of the status frame every connection
// shares at one instant.
type statusParts struct {
	policy      PolicyView
	proj        ProjectionView
	bus         BusView
	sources     []SourceState
	dpState     string
	degraded    map[string]time.Time
	unconfirmed int
}

func (h *Hub) policy() PolicyView {
	if h.in.Policy != nil {
		return h.in.Policy()
	}
	return PolicyView{Version: "0", StaleAfterS: 15, LiveMaxAgeS: 10, CISStaleBoundS: 300, Default: true}
}

func (h *Hub) busView() BusView {
	if h.in.Bus != nil {
		return h.in.Bus()
	}
	return BusView{Connected: true}
}

// since keeps, for a condition that holds now, the instant it started
// holding (first seen by this process), and forgets one that ended.
func (h *Hub) since(present map[string]time.Time, now time.Time) map[string]time.Time {
	h.degradedMu.Lock()
	defer h.degradedMu.Unlock()
	out := make(map[string]time.Time, len(present))
	for slug, at := range present {
		if !at.IsZero() {
			out[slug] = at
			h.degradedSeen[slug] = at
			continue
		}
		first, ok := h.degradedSeen[slug]
		if !ok {
			first = now
			h.degradedSeen[slug] = first
		}
		out[slug] = first
	}
	for slug := range h.degradedSeen {
		if _, ok := present[slug]; !ok {
			delete(h.degradedSeen, slug)
		}
	}
	return out
}

// parts builds the shared status at now; all is the source rows Compute
// returned.
func (h *Hub) parts(now time.Time, all []SourceState, unconfirmed int, unconfirmedSince time.Time) statusParts {
	p := statusParts{policy: h.policy(), bus: h.busView(), sources: all, unconfirmed: unconfirmed}
	if h.in.Projections != nil {
		p.proj = h.in.Projections(now)
	}
	present := map[string]time.Time{}
	if !p.bus.Connected {
		present[DegradedNATS] = p.bus.Since
	}
	switch {
	case h.in.Projections == nil:
	case !p.proj.FailingSince.IsZero():
		present[DegradedProjections] = p.proj.FailingSince
	}
	if p.proj.Read && p.proj.RegistryAbsent {
		present[DegradedRegistryAbsent] = time.Time{}
	}
	if p.proj.Read && p.proj.CISAbsent {
		present[DegradedCISAbsent] = time.Time{}
	}
	if p.proj.CISAgeS != nil && p.policy.CISStaleBoundS > 0 && *p.proj.CISAgeS > p.policy.CISStaleBoundS {
		present[DegradedCISStale] = time.Time{}
	}
	switch h.sources.TypeState("network_rid") {
	case StateLive:
		p.dpState = DPPolling
	case StateDisabled:
		p.dpState = DPDisabled
	case StateStale:
		p.dpState = DPStale
		present[DegradedDP] = time.Time{}
	default:
		p.dpState = DPUnavailable
		present[DegradedDP] = time.Time{}
	}
	switch h.sources.TypeState("ansp_feed") {
	case StateLive, StateDisabled:
	default:
		present[DegradedManned] = time.Time{}
	}
	if unconfirmed > 0 {
		present[DegradedAlertsUnconfirmed] = unconfirmedSince
	}
	if h.replaying.Load() {
		present[DegradedAlertsReplaying] = time.Time{}
	}
	if h.in.VerifierReady != nil && !h.in.VerifierReady() {
		present[DegradedSessions] = time.Time{}
	}
	if h.in.SwitchesKnown != nil && !h.in.SwitchesKnown() {
		present[DegradedSwitchesUnknown] = time.Time{}
	}
	if p.policy.Default {
		present[DegradedPolicyDefault] = time.Time{}
	}
	if at := h.lastEvictNS.Load(); at != 0 && now.Sub(time.Unix(0, at)) < 2*h.cfg.StatusInterval {
		present[DegradedTracksEvicted] = time.Time{}
	}
	p.degraded = h.since(present, now)
	return p
}

// statusFrameLocked is c's console/status/v1 frame at now; c.mu is
// held.
func (h *Hub) statusFrameLocked(c *client, p *statusParts, now time.Time) ([]byte, error) {
	perConn := map[string]time.Time{}
	switch {
	case !c.subscribed:
		perConn[DegradedNoSubscription] = c.openedAt
	case c.tooLarge:
		perConn[DegradedViewportTooLarge] = c.tooLargeAt
	}
	if at := c.uncheckedSince(); !at.IsZero() {
		perConn[DegradedSessionUnchecked] = at
	}
	body := StatusBody{
		ConnectionID: c.id, ServerTS: stamp(now), PolicyVersion: p.policy.Version,
		StaleAfterS: p.policy.StaleAfterS, LiveMaxAgeS: p.policy.LiveMaxAgeS, DroppedFrames: c.dropped.Load(),
		Sources: p.sources, DPState: p.dpState, NATS: NATSConnected,
		ProjectionAgeS: p.proj.RegistryAgeS, CISVersion: p.proj.CISVersion, CISAgeS: p.proj.CISAgeS,
		DegradedSince: map[string]string{},
	}
	if !p.bus.Connected {
		body.NATS = NATSUnavailable
		if !p.bus.Since.IsZero() {
			body.NATSSince = ptr(stamp(p.bus.Since))
		}
	}
	if body.Sources == nil {
		body.Sources = []SourceState{}
	}
	for slug, at := range p.degraded {
		body.Degraded = append(body.Degraded, slug)
		body.DegradedSince[slug] = stamp(at)
	}
	for slug, at := range perConn {
		body.Degraded = append(body.Degraded, slug)
		body.DegradedSince[slug] = stamp(at)
	}
	slices.Sort(body.Degraded)
	if body.Degraded == nil {
		body.Degraded = []string{}
	}
	h.counters.Inc(CounterStatusFrames)
	return systemFrame(SchemaStatus, now, body)
}

// Tick is one status interval at now: the caches are aged (only while
// the bus is connected: with the bus down nothing is removed, and the
// consoles see every aircraft age), violations silent too long are
// forgotten, every source whose state changed is announced
// (source/status/v1), and every console is sent its status.
func (h *Hub) Tick(now time.Time) {
	p := h.policy()
	b := h.busView()
	if b.Connected && p.StaleAfterS > 0 {
		cutoff := now.Add(-time.Duration(p.StaleAfterS * float64(time.Second)))
		if n := h.tracks.sweep(cutoff); n > 0 {
			h.counters.Add(CounterTracksAgedOut, uint64(n))
		}
		if n := h.manned.sweep(cutoff); n > 0 {
			h.counters.Add(CounterMannedAgedOut, uint64(n))
		}
	}
	forgotten := 0
	var unconfirmed int
	var unconfirmedSince time.Time
	if b.Connected {
		forgotten, unconfirmed, unconfirmedSince = h.alerts.age(now)
	} else {
		_, unconfirmed, unconfirmedSince = h.alerts.ageNoForget(now)
	}
	if forgotten > 0 {
		h.counters.Add(CounterAlertsForgotten, uint64(forgotten))
		h.cfg.Logger.Error("active violations neither republished nor cleared left the picture; a republish brings them back",
			slog.Int("forgotten", forgotten), slog.Duration("after", h.cfg.AlertForget))
	}
	all, changed := h.sources.Compute(now)
	parts := h.parts(now, all, unconfirmed, unconfirmedSince)
	var srcFrames [][]byte
	for _, s := range changed {
		f, err := systemFrame(SchemaSource, now, s)
		if err != nil {
			h.counters.Inc(CounterFramesNotEncoded)
			continue
		}
		srcFrames = append(srcFrames, f)
	}
	for _, c := range h.snapshotClients() {
		for _, f := range srcFrames {
			c.enqueueAny(f)
			h.counters.Inc(CounterSourceStatusFrames)
		}
		c.mu.Lock()
		c.refreshViewLocked(h.tracks, now, h.cfg.ThrottleEvery)
		f, err := h.statusFrameLocked(c, &parts, now)
		if err == nil {
			c.pushStatus(f)
		} else {
			h.counters.Inc(CounterFramesNotEncoded)
		}
		var resnap *snapshotFilter
		var gen uint64
		if forgotten > 0 && c.subscribed {
			// A console replaces its store with a snapshot: what left
			// the picture leaves the console with it, said, not silent.
			gen = c.nextGenLocked()
			resnap = &snapshotFilter{cells: c.cells, layers: c.layers, console: c.sess.Console()}
		}
		c.mu.Unlock()
		if resnap != nil {
			h.sendSnapshot(c, gen, *resnap, now)
		}
	}
}

// Run sends the status every interval and after a poke until ctx ends;
// then it closes every console (1001).
func (h *Hub) Run(ctx context.Context) {
	t := time.NewTicker(h.cfg.StatusInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.Close()
			return
		case <-t.C:
			h.Tick(h.cfg.Now())
		case <-h.poke:
			h.Tick(h.cfg.Now())
		}
	}
}

// Close closes every console with 1001 and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	for _, c := range h.snapshotClients() {
		h.detach(c, CloseGoingAway, "the instance is stopping")
	}
	h.cancel()
}

// ---- snapshots ------------------------------------------------------

// snapshotFilter selects what a snapshot holds.
type snapshotFilter struct {
	cells   map[cell.ID]struct{}
	layers  map[string]bool
	console bool
	// box, when set, keeps only the tracks inside it (the HTTP snapshot);
	// the WebSocket snapshot holds the viewport's cells with the margin.
	box *geodesy.BBox
}

// snapshotBody builds console/snapshot/v1's body at now, its items
// bounded to SnapshotMaxBytes: active violations first, then tracks,
// then manned aircraft; past the bound the rest is left out and the body
// says truncated. It takes no lock of the hub or of a console, so the
// bus goroutine is never held behind a snapshot.
func (h *Hub) snapshotBody(f snapshotFilter, now time.Time) SnapshotBody {
	if h.testSnapshotHook != nil {
		h.testSnapshotHook()
	}
	body := SnapshotBody{Tracks: []json.RawMessage{}, Alerts: []json.RawMessage{}, Manned: []json.RawMessage{}}
	if h.in.Projections != nil {
		body.ZonesVersion = h.in.Projections(now).ZonesVersion
	}
	budget := h.cfg.SnapshotMaxBytes
	fits := func(raw []byte) bool {
		if len(raw)+1 > budget {
			body.Truncated = true
			return false
		}
		budget -= len(raw) + 1
		return true
	}
	if f.layers[LayerAlerts] {
		for _, raw := range h.alerts.inCells(f.cells) {
			if !fits(raw) {
				break
			}
			body.Alerts = append(body.Alerts, raw)
		}
	}
	if f.layers[LayerTracks] && !body.Truncated {
		items := h.tracks.inCells(f.cells)
		slices.SortFunc(items, func(a, b *item) int { return compareStrings(a.key, b.key) })
		for _, it := range items {
			if f.box != nil && (it.pos == nil || !f.box.Contains(*it.pos)) {
				continue
			}
			fr := h.encodeTrack(it, now, h.sources.StateOf(it.sourceType, it.instance), f.console)
			if fr == nil {
				continue
			}
			if !fits(fr) {
				break
			}
			body.Tracks = append(body.Tracks, fr)
		}
	}
	if f.layers[LayerManned] && !body.Truncated {
		items := h.manned.inCells(f.cells)
		slices.SortFunc(items, func(a, b *item) int { return compareStrings(a.key, b.key) })
		for _, it := range items {
			if !fits(it.raw) {
				break
			}
			body.Manned = append(body.Manned, it.raw)
		}
	}
	h.counters.Inc(CounterSnapshots)
	if body.Truncated {
		h.counters.Inc(CounterSnapshotsTruncated)
		h.cfg.Limiter.Limited("picture_snapshot_truncated").Warn("snapshot truncated at its bound; the console should narrow its viewport",
			slog.Int("max_bytes", h.cfg.SnapshotMaxBytes))
	}
	return body
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// sendSnapshot builds the snapshot of generation gen of c's view with
// no lock held and queues it, unless a newer view superseded it (whose
// own snapshot follows). Live frames of generation gen queued meanwhile
// are held by the writer until this snapshot is written, so none of
// them reaches the console before it (write).
func (h *Hub) sendSnapshot(c *client, gen uint64, f snapshotFilter, now time.Time) {
	body := h.snapshotBody(f, now)
	fr, err := systemFrame(SchemaSnapshot, now, body)
	if err != nil {
		h.counters.Inc(CounterFramesNotEncoded)
		// An empty snapshot of the generation, so the held live frames
		// still flow and the console still replaces its store.
		empty := SnapshotBody{Tracks: []json.RawMessage{}, Alerts: []json.RawMessage{}, Manned: []json.RawMessage{}, Truncated: true}
		if fr, err = systemFrame(SchemaSnapshot, now, empty); err != nil {
			return
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return
	}
	c.pushSnapshot(fr, gen)
}

// ---- connections ----------------------------------------------------

// Serve runs one console on conn, whose session was checked, on a slot
// Reserve took, until the console goes, its session ends or the hub
// closes. It sends console/status/v1 and console/snapshot/v1 at once,
// then the live stream of the console's subscription.
func (h *Hub) Serve(conn Conn, sess Session, token string, sessions Checker) {
	now := h.cfg.Now()
	// Two lives: ctx ends when the console is detached (the writer and
	// the re-check stop); readCtx only once the close handshake is done,
	// because a read cancelled earlier drops the connection before the
	// close frame (4401, 1013, 1001) reaches the console.
	ctx, cancel := context.WithCancel(context.Background())
	readCtx, readCancel := context.WithCancel(context.Background())
	c := &client{
		id: bus.NewULID(now), sess: sess, token: token, conn: conn, hub: h, cancel: cancel, readCancel: readCancel, done: ctx.Done(),
		cells: map[cell.ID]struct{}{}, layers: map[string]bool{}, lastSent: map[string]time.Time{},
		data: make(chan queued, h.cfg.SendBuffer), wake: make(chan struct{}, 1), openedAt: now, subReady: make(chan struct{}, 1),
	}
	h.mu.Lock()
	h.reserved--
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	h.counters.Inc(CounterClientsOpened)
	h.cfg.Logger.Info("console connected", slog.String("connection_id", c.id), slog.String("realm", sess.Realm),
		slog.String("user", sess.Subject))

	parts := h.parts(now, h.sources.Snapshot(), 0, time.Time{})
	c.mu.Lock()
	if f, err := h.statusFrameLocked(c, &parts, now); err == nil {
		c.pushStatus(f)
	}
	gen := c.nextGenLocked()
	filter := snapshotFilter{cells: c.cells, layers: c.layers, console: c.sess.Console()}
	c.mu.Unlock()
	h.sendSnapshot(c, gen, filter, now)

	var wg sync.WaitGroup
	wg.Go(func() { h.write(ctx, c) })
	wg.Go(func() { h.read(readCtx, c) })
	wg.Go(func() { h.applySubscriptions(ctx, c) })
	if sessions != nil {
		wg.Go(func() { h.recheck(ctx, c, sessions) })
	}
	select {
	case <-ctx.Done():
	case <-h.ctx.Done():
		h.detach(c, CloseGoingAway, "the instance is stopping")
	}
	wg.Wait()
}

// detach removes c and closes its connection with code; once per
// console.
func (h *Hub) detach(c *client, code websocket.StatusCode, reason string) {
	c.gone.Do(func() {
		h.mu.Lock()
		delete(h.clients, c)
		for cl := range c.indexed {
			if set := h.byCell[cl]; set != nil {
				delete(set, c)
				if len(set) == 0 {
					delete(h.byCell, cl)
				}
			}
		}
		h.mu.Unlock()
		c.cancel()
		h.counters.Inc(CounterClientsClosed)
		h.cfg.Logger.Info("console disconnected", slog.String("connection_id", c.id), slog.Int("close_code", int(code)),
			slog.String("reason", reason), slog.Uint64("dropped_frames", c.dropped.Load()))
		// The reader keeps reading through the close handshake; a
		// console that does not answer it is dropped by the library's
		// own handshake timeout, and the reader ends after.
		go func() {
			_ = c.conn.Close(code, reason)
			c.readCancel()
		}()
	})
}

// write sends c's frames, status and snapshot first, each within
// WriteTimeout; a write that fails ends the console.
func (h *Hub) write(ctx context.Context, c *client) {
	send := func(f []byte) bool {
		wctx, cancel := context.WithTimeout(ctx, h.cfg.WriteTimeout)
		err := c.conn.Write(wctx, f)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				h.counters.Inc(CounterClosedWriteFailed)
				h.detach(c, CloseGoingAway, "write failed")
			}
			return false
		}
		h.counters.Inc(CounterFramesSent)
		return true
	}
	// written is the generation of the last snapshot written. A live
	// frame of a newer view waits in held until its snapshot is written;
	// one of an older view is dropped, because the snapshot written after
	// it holds that aircraft as new or newer.
	var written uint64
	var held []queued
	for {
		if f, gen, snap := c.takeControl(); f != nil {
			if !send(f) {
				return
			}
			if !snap {
				continue
			}
			written = gen
			keep := held[:0]
			for _, q := range held {
				switch {
				case q.gen == written:
					if !send(q.f) {
						return
					}
				case q.gen > written:
					keep = append(keep, q)
				}
			}
			clear(held[len(keep):])
			held = keep
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
		case q := <-c.data:
			switch {
			case q.any || q.gen == written:
				if !send(q.f) {
					return
				}
			case q.gen > written:
				if len(held) >= cap(c.data) {
					c.dropped.Add(1)
					h.counters.Inc(CounterFramesQueueFull)
					continue
				}
				held = append(held, q)
			}
		}
	}
}

// read takes the console's subscriptions until it goes. A frame that is
// not a console/subscribe/v1 closes the connection with 1007 and the
// field at fault; one larger than SubscribeMaxBytes with 1009 (the
// library's read limit).
func (h *Hub) read(ctx context.Context, c *client) {
	for {
		raw, err := c.conn.Read(ctx)
		if err != nil {
			h.detach(c, websocket.StatusNormalClosure, "")
			return
		}
		select {
		case <-c.done:
			continue // detached: read on through the close handshake
		default:
		}
		box, layers, err := ParseSubscribe(raw)
		if err != nil {
			h.counters.Inc(CounterClosedInvalid)
			h.detach(c, CloseInvalid, truncate(err.Error(), 120))
			return
		}
		c.postSubscription(pendingSub{box: box, layers: layers}, h.counters)
	}
}

// applySubscriptions applies c's subscriptions at most once per
// SubscribeMinInterval: one arriving sooner waits, and those superseded
// while it waits are never applied (counted subscribes_coalesced), so a
// console re-subscribing in a loop builds at most one snapshot per
// interval.
func (h *Hub) applySubscriptions(ctx context.Context, c *client) {
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.subReady:
		}
		if wait := h.cfg.SubscribeMinInterval - time.Since(last); wait > 0 && !last.IsZero() {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
			}
		}
		sub, ok := c.takeSubscription()
		if !ok {
			continue
		}
		last = time.Now()
		h.subscribe(c, sub.box, sub.layers, h.cfg.Now())
	}
}

// subscribe applies a new viewport: the cell index is moved, the live
// frames of the old viewport still queued are discarded, and the status
// and the snapshot of the new one are queued before any live frame of
// it. A viewport over MaxCells cells keeps the previous one and says so
// (degraded viewport_too_large).
func (h *Hub) subscribe(c *client, box geodesy.BBox, layers map[string]bool, now time.Time) {
	h.counters.Inc(CounterSubscribes)
	cells, err := ViewportCells(box, h.cfg.MaxCells)
	parts := h.parts(now, h.sources.Snapshot(), 0, time.Time{})
	c.mu.Lock()
	if err != nil {
		defer c.mu.Unlock()
		c.tooLarge = true
		if c.tooLargeAt.IsZero() {
			c.tooLargeAt = now
		}
		h.counters.Inc(CounterSubscribeTooLarge)
		h.cfg.Limiter.Limited("picture_viewport_too_large").Info("viewport refused; the connection keeps its previous one",
			slog.String("connection_id", c.id), slog.String("error", err.Error()))
		if f, err := h.statusFrameLocked(c, &parts, now); err == nil {
			c.pushStatus(f)
		}
		return
	}
	h.mu.Lock()
	for cl := range c.indexed {
		if _, keep := cells[cl]; keep {
			continue
		}
		if set := h.byCell[cl]; set != nil {
			delete(set, c)
			if len(set) == 0 {
				delete(h.byCell, cl)
			}
		}
	}
	for cl := range cells {
		set := h.byCell[cl]
		if set == nil {
			set = map[*client]struct{}{}
			h.byCell[cl] = set
		}
		set[c] = struct{}{}
	}
	h.mu.Unlock()
	c.indexed, c.cells, c.layers, c.lastBox = cells, cells, layers, box
	c.subscribed, c.tooLarge, c.tooLargeAt = true, false, time.Time{}
	gen := c.nextGenLocked()
	c.viewTracks = h.tracks.countIn(cells)
	clear(c.lastSent)
	if f, err := h.statusFrameLocked(c, &parts, now); err == nil {
		c.pushStatus(f)
	}
	filter := snapshotFilter{cells: cells, layers: layers, console: c.sess.Console()}
	c.mu.Unlock()
	// Built with no lock held: OfferTrack, on the one bus goroutine,
	// takes every watching console's lock in turn, so a snapshot built
	// under one would hold every console behind this one.
	h.sendSnapshot(c, gen, filter, now)
}

// recheck asks the session checker again every SessionRecheck: a session
// that has ended (logout, revocation, a disabled account, expiry, idle)
// closes the console with 4401; one that cannot be checked is kept for
// SessionGrace after its last good check, said on its status
// (session_unchecked), then closed with 1013.
func (h *Hub) recheck(ctx context.Context, c *client, sessions Checker) {
	t := time.NewTicker(h.cfg.SessionRecheck)
	defer t.Stop()
	var expiry <-chan time.Time
	if !c.sess.ExpiresAt.IsZero() {
		et := time.NewTimer(max(time.Until(c.sess.ExpiresAt), 0))
		defer et.Stop()
		expiry = et.C
	}
	lastGood := h.cfg.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiry:
			h.counters.Inc(CounterClosedRelogin)
			h.detach(c, CloseRelogin, "the session expired; sign in again")
			return
		case <-t.C:
		}
		_, err := sessions.Recheck(ctx, c.token)
		now := h.cfg.Now()
		switch {
		case err == nil:
			lastGood = now
			c.setUnchecked(time.Time{})
		case errors.Is(err, ErrRefused):
			h.counters.Inc(CounterClosedRelogin)
			h.counters.Inc(CounterSessionRevokedClosed)
			h.detach(c, CloseRelogin, "the session has ended; sign in again")
			return
		default:
			h.counters.Inc(CounterSessionRecheckFails)
			c.setUnchecked(lastGood)
			if now.Sub(lastGood) > h.cfg.SessionGrace {
				h.counters.Inc(CounterClosedUnavailable)
				h.counters.Inc(CounterSessionGraceClosed)
				h.detach(c, CloseTryAgainLater, "the session could not be checked; reconnect later")
				return
			}
		}
	}
}

// ---- one console ----------------------------------------------------

// client is one console connection.
type client struct {
	id         string
	sess       Session
	token      string
	conn       Conn
	hub        *Hub
	cancel     context.CancelFunc
	readCancel context.CancelFunc
	done       <-chan struct{}
	openedAt   time.Time

	mu         sync.Mutex
	cells      map[cell.ID]struct{}
	indexed    map[cell.ID]struct{}
	layers     map[string]bool
	subscribed bool
	tooLarge   bool
	tooLargeAt time.Time
	viewTracks int
	lastSent   map[string]time.Time
	lastBox    geodesy.BBox

	// gen is the generation of the view (c.mu): every subscription and
	// every snapshot of the same view takes a new one, and every live
	// frame is queued with the generation it was offered under.
	gen uint64

	data    chan queued
	wake    chan struct{}
	ctrlMu  sync.Mutex
	status  []byte
	snap    []byte
	snapGen uint64
	dropped atomic.Uint64

	subMu    sync.Mutex
	nextSub  *pendingSub
	subReady chan struct{}

	uncheckedMu sync.Mutex
	unchecked   time.Time

	gone sync.Once
}

func (c *client) uncheckedSince() time.Time {
	c.uncheckedMu.Lock()
	defer c.uncheckedMu.Unlock()
	return c.unchecked
}

func (c *client) setUnchecked(since time.Time) {
	c.uncheckedMu.Lock()
	defer c.uncheckedMu.Unlock()
	if since.IsZero() || c.unchecked.IsZero() {
		c.unchecked = since
	}
}

// queued is a live frame with the generation of the view it was offered
// under; any marks a frame of no view (source/status/v1), always sent.
type queued struct {
	f   []byte
	gen uint64
	any bool
}

// pendingSub is a parsed subscription not yet applied.
type pendingSub struct {
	box    geodesy.BBox
	layers map[string]bool
}

// postSubscription makes sub the next subscription to apply; one not
// yet applied is superseded and counted.
func (c *client) postSubscription(sub pendingSub, counters *core.Counters) {
	c.subMu.Lock()
	if c.nextSub != nil {
		counters.Inc(CounterSubscribesCoalesced)
	}
	c.nextSub = &sub
	c.subMu.Unlock()
	select {
	case c.subReady <- struct{}{}:
	default:
	}
}

func (c *client) takeSubscription() (pendingSub, bool) {
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if c.nextSub == nil {
		return pendingSub{}, false
	}
	s := *c.nextSub
	c.nextSub = nil
	return s, true
}

// nextGenLocked starts a new generation of the view; c.mu is held.
func (c *client) nextGenLocked() uint64 {
	c.gen++
	return c.gen
}

// enqueueAny queues a frame of no view (source/status/v1).
func (c *client) enqueueAny(f []byte) bool { return c.put(queued{f: f, any: true}) }

// enqueue queues a live frame of the current view; c.mu is held.
func (c *client) enqueue(f []byte) bool { return c.put(queued{f: f, gen: c.gen}) }

// put queues q without blocking; a full queue drops it and counts it in
// dropped_frames.
func (c *client) put(q queued) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.data <- q:
		return true
	default:
		c.dropped.Add(1)
		c.hub.counters.Inc(CounterFramesQueueFull)
		return false
	}
}

// offerTrack queues a track frame if the viewport still holds c5 and the
// track layer is on; above ThrottleAbove tracks in the viewport a track
// is sent at most once per ThrottleEvery and the rest is dropped and
// counted (05 §3, §5).
func (c *client) offerTrack(key string, c5 cell.ID, f []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.cells[c5]; !ok || !c.layers[LayerTracks] {
		return
	}
	if c.viewTracks > c.hub.cfg.ThrottleAbove {
		if last, ok := c.lastSent[key]; ok && now.Sub(last) < c.hub.cfg.ThrottleEvery {
			c.dropped.Add(1)
			c.hub.counters.Inc(CounterFramesThrottled)
			return
		}
	}
	if c.enqueue(f) {
		c.lastSent[key] = now
	}
}

// offerLayer queues a frame of layer if the viewport holds c5.
func (c *client) offerLayer(layer string, c5 cell.ID, f []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.cells[c5]; ok && c.layers[layer] {
		c.enqueue(f)
	}
}

// refreshViewLocked recounts the tracks of the viewport and forgets
// throttle marks older than the throttle period; c.mu is held.
func (c *client) refreshViewLocked(tracks *cache, now time.Time, every time.Duration) {
	c.viewTracks = tracks.countIn(c.cells)
	for k, at := range c.lastSent {
		if now.Sub(at) >= every {
			delete(c.lastSent, k)
		}
	}
}

// pushStatus queues the status; a status not yet written is replaced by
// the newer one.
func (c *client) pushStatus(f []byte) {
	c.ctrlMu.Lock()
	c.status = f
	c.ctrlMu.Unlock()
	c.wakeUp()
}

// pushSnapshot queues the snapshot of generation gen; one not yet
// written is replaced by the newer one (its subscription superseded the
// older).
func (c *client) pushSnapshot(f []byte, gen uint64) {
	c.ctrlMu.Lock()
	c.snap, c.snapGen = f, gen
	c.ctrlMu.Unlock()
	c.wakeUp()
}

func (c *client) wakeUp() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// takeControl is the next control frame: the status, then the snapshot
// (snap true, with its generation).
func (c *client) takeControl() (f []byte, gen uint64, snap bool) {
	c.ctrlMu.Lock()
	defer c.ctrlMu.Unlock()
	if f := c.status; f != nil {
		c.status = nil
		return f, 0, false
	}
	if f := c.snap; f != nil {
		c.snap = nil
		return f, c.snapGen, true
	}
	return nil, 0, false
}

// PolicyVersion renders a policy version as the status frame carries it.
func PolicyVersion(v int64) string { return strconv.FormatInt(v, 10) }
