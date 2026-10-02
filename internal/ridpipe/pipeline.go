package ridpipe

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"
	"github.com/rootxkit/uspace-core/timeplace"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// Counter names of the Pipeline (E-09): every refusal, fallback, drop
// and degraded state has one, on the status line and /metrics.
const (
	CounterRows                = "rows_observed"
	CounterDecodeRefused       = "decode_refused" // plus decode_refused_<phrase> per kind
	CounterDecodeRefusedOther  = "decode_refused_other"
	CounterFramesSkipped       = "frames_without_messages" // Self-ID, Authentication or undefined only (R-04)
	CounterRxTSMissing         = "rx_ts_missing"           // received at arrival (T-12)
	CounterRxSpacingClamped    = "rx_spacing_clamped"      // T-02 clamp
	CounterTrackerClockHeld    = "tracker_clock_held"      // a receive time behind the tracker's clock
	CounterPlacedBroadcast     = "placed_broadcast"
	CounterPlacedArrival       = "placed_arrival" // T-12 row whose broadcast time was not believed
	CounterTimeFallback        = "time_fallback_" // plus the timeplace.Fallback
	CounterPublished           = "tracks_published"
	CounterPublishFailed       = "track_publish_failed"
	CounterTrackInvalid        = "track_invalid"
	CounterNoPosition          = "observations_without_position"
	CounterAltGeodetic         = "alt_geodetic"
	CounterAltPressure         = "alt_pressure"
	CounterAltNone             = "alt_none"
	CounterAltNoGeoid          = "alt_amsl_unavailable_no_geoid"
	CounterGeoidFailed         = "geoid_failed"
	CounterVelocityUnknown     = "velocity_unknown"
	CounterStatusUnknown       = "status_unknown"
	CounterRegistryUnavailable = "identification_registry_unavailable"
	CounterIdentChanges        = "ident_changes_published"
	CounterIdentPublishFailed  = "ident_publish_failed"
	CounterIdentMemoryEvicted  = "ident_memory_evicted"
	CounterAltHoldsEvicted     = "altitude_holds_evicted"
	CounterPlacementsEvicted   = "placements_evicted"
	CounterPlacementMissed     = "placement_recomputed"
)

// Settings are the Pipeline's thresholds (INV-03). The identity and
// time values are authority_policy's (identity_ttl_s, max_gap_s,
// identify_within_s, broadcast_tolerance_s, max_latency_s); rid-ingest
// takes them from its configuration, whose defaults are the policy's.
type Settings struct {
	// Tracker is rid.Settings: identity TTL 15 s, max gap 3 s, identify
	// within 4 s, MaxTransmitters addresses (E-10).
	Tracker rid.Settings
	// Broadcast is timeplace.BroadcastPolicy: 1 s tolerance, 5 s latency.
	Broadcast timeplace.BroadcastPolicy
	// Altitude is rid.AltPolicy: accuracy code 2, the 10 s pressure hold.
	Altitude rid.AltPolicy
	// MaxBatchSpacing clamps a row's spacing within its batch (T-02,
	// 120 s).
	MaxBatchSpacing time.Duration
	// MaxTracks bounds the per-track memories: the altitude selectors
	// and the last identification published per track (E-10).
	MaxTracks int
	// Producer names the process in every envelope.
	Producer string
}

// DefaultSettings are the documented defaults: the policy's version 1.
func DefaultSettings() Settings {
	return Settings{
		Tracker: rid.DefaultSettings(), Broadcast: timeplace.DefaultBroadcastPolicy(), Altitude: rid.DefaultAltPolicy(),
		MaxBatchSpacing: timeplace.DefaultMaxBatchSpacing, MaxTracks: 50000, Producer: "authority/rid-ingest",
	}
}

// Deps are what the Pipeline judges with and publishes to.
type Deps struct {
	// Registry is the registry projection to resolve against (WP-3's
	// ProjectionReader.Lookup); it returns nil while the projection has
	// never loaded, which identify reads as registry_unavailable (SC-22).
	// A nil Registry is a projection that never loads.
	Registry func() identify.Lookup
	// Geoid converts HAE to AMSL (WP-11). Nil means no geoid: no AMSL
	// altitude, and such aircraft are not judged vertically (R-07).
	Geoid geoid.Undulator
	// Publisher sends trk.v1 and ident.v1 over core NATS.
	Publisher bus.Publisher
	Counters  *core.Counters
	Logger    *slog.Logger
	Limiter   *logging.Limiter
	// Now is the clock of the tick; nil is time.Now.
	Now func() time.Time
}

// trackerState is one rid.Tracker and its clock. Live and backlog rows
// have one each, so history never borrows a live identity nor moves the
// live clock (T-04).
type trackerState struct {
	t     *rid.Tracker
	nowS  float64
	memos *lru[memoKey, placement]
}

// trackKey is one track as one tracker publishes it: the live and the
// backlog tracker publish the same track ids, and neither's history may
// reach the other's altitude hold or announced identification (T-04).
type trackKey struct {
	backlog bool
	trackID string
}

// memoKey is one receiver's view of one transmitter.
type memoKey struct{ receiver, transmitter string }

// placement is where a Location row was placed and which row it was:
// the tracker may publish the Location later, when its identity
// arrives (I-02), and the track keeps the Location row's times.
type placement struct {
	rx      time.Time
	p       timeplace.Placement
	frameID string
}

// Pipeline is the Remote ID pipeline of one rid-ingest process (the
// Sink WP-7 hands each batch to): decode, identity per transmitter,
// time placement, altitude, velocity, identification, publish. Each step
// is a call into uspace-core; this package maps wire to core input and
// core output to the track message, and judges nothing itself.
type Pipeline struct {
	s     Settings
	d     Deps
	log   *slog.Logger
	lim   *logging.Limiter
	cnt   *core.Counters
	trk   *core.Counters
	bklog *core.Counters

	mu       sync.Mutex
	live     trackerState
	backlog  trackerState
	alts     *lru[trackKey, *rid.AltitudeSelector]
	idents   *lru[trackKey, core.Identification]
	refusals map[string]bool
}

var _ Sink = (*Pipeline)(nil)

// New returns a Pipeline with settings s. A part of s left zero takes
// its default (rid.NewTracker does the same for the tracker), so a
// missing value never disarms a rule (E-15).
func New(s Settings, d Deps) *Pipeline {
	def := DefaultSettings()
	if s.Broadcast == (timeplace.BroadcastPolicy{}) {
		s.Broadcast = def.Broadcast
	}
	if s.Altitude == (rid.AltPolicy{}) {
		s.Altitude = def.Altitude
	}
	if s.MaxBatchSpacing <= 0 {
		s.MaxBatchSpacing = def.MaxBatchSpacing
	}
	if s.MaxTracks <= 0 {
		s.MaxTracks = def.MaxTracks
	}
	if s.Producer == "" {
		s.Producer = def.Producer
	}
	if d.Counters == nil {
		d.Counters = &core.Counters{}
	}
	if d.Logger == nil {
		d.Logger = logging.Discard()
	}
	if d.Limiter == nil {
		d.Limiter = logging.NewLimiter(d.Logger, time.Minute, 0, d.Counters)
	}
	live, backlog := rid.NewTracker(s.Tracker), rid.NewTracker(s.Tracker)
	s.Tracker = live.Settings()
	memoMax := s.Tracker.MaxTransmitters
	return &Pipeline{
		s: s, d: d, log: d.Logger, lim: d.Limiter, cnt: d.Counters, trk: live.Counters(), bklog: backlog.Counters(),
		live:     trackerState{t: live, memos: newLRU[memoKey, placement](memoMax)},
		backlog:  trackerState{t: backlog, memos: newLRU[memoKey, placement](memoMax)},
		alts:     newLRU[trackKey, *rid.AltitudeSelector](s.MaxTracks),
		idents:   newLRU[trackKey, core.Identification](s.MaxTracks),
		refusals: map[string]bool{},
	}
}

// Settings returns the settings in use, after defaulting.
func (p *Pipeline) Settings() Settings { return p.s }

// Counters are the pipeline's own counters.
func (p *Pipeline) Counters() *core.Counters { return p.cnt }

// TrackerCounters are the live and the backlog tracker's counters
// (identity_changes, silences, unidentified, address_conflicts,
// evicted, held_replaced).
func (p *Pipeline) TrackerCounters() (live, backlog *core.Counters) { return p.trk, p.bklog }

func (p *Pipeline) now() time.Time {
	if p.d.Now != nil {
		return p.d.Now()
	}
	return time.Now()
}

// seconds is t on the trackers' clock: Unix seconds, this system's clock.
func seconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// Tick forgets the live transmitters silent for longer than the maximum
// gap (I-01), so a silence ends an identity even when nothing else is
// heard. It never moves a tracker's clock: the trackers run on placed
// receipt time (rx), and a batch placed up to MaxBatchSpacing before its
// arrival must keep its spacing (T-02), so the tick forgets at now -
// MaxBatchSpacing, a time no later row of a batch arriving now can
// precede. The backlog tracker is never driven by wall time: history is
// judged on its own clock (T-04); its transmitters are forgotten by its
// own rows and bounded by MaxTransmitters.
func (p *Pipeline) Tick(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live.t.Forget(seconds(now.Add(-p.s.MaxBatchSpacing)))
}

// Run ticks every period until ctx ends.
func (p *Pipeline) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Tick(p.now())
		}
	}
}

// StatusAttrs are the pipeline's status-line attributes (E-09, SC-22):
// whether a geoid is configured and what that means, and how many
// transmitters and tracks it holds.
func (p *Pipeline) StatusAttrs() []slog.Attr {
	p.mu.Lock()
	defer p.mu.Unlock()
	geo := "configured"
	if p.d.Geoid == nil {
		geo = "none: Remote ID aircraft have no AMSL altitude and are not judged vertically"
	}
	return []slog.Attr{
		slog.String("geoid", geo),
		slog.Int("rid_transmitters", p.live.t.Transmitters()),
		slog.Int("rid_backlog_transmitters", p.backlog.t.Transmitters()),
		slog.Int("rid_tracks_held", p.idents.len()),
	}
}

// Observe runs every row of b through the pipeline once (Sink). The
// decoded columns are written into b.Rows and the tracks rows of the
// observations published into b.Tracks before it returns, so the worker
// that stores the raw rows stores both, with the same retry and the same
// acknowledgement (B-05, SC-18); one track is published per observation
// the tracker completes. It never fails: what cannot be decoded or
// published is counted.
func (p *Pipeline) Observe(_ context.Context, b *Batch) error {
	rx, clamped := p.receipts(b)
	if clamped > 0 {
		p.cnt.Add(CounterRxSpacingClamped, uint64(clamped))
	}
	// The rows in the order they were heard, so the tracker's clock
	// moves forward through the batch and its spacing is kept (T-02).
	order := make([]int, len(b.Rows))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, c int) bool { return rx[order[a]].Before(rx[order[c]]) })
	var rows []track.Row
	p.mu.Lock()
	for _, i := range order {
		if row := p.observeRow(b, &b.Rows[i], rx[i]); row != nil {
			rows = append(rows, *row)
		}
	}
	p.mu.Unlock()
	b.Tracks = rows
	return nil
}

// receipts places each row's reception on this system's clock (T-02):
// rx = IngestTS - (newest ReceiverTS - ReceiverTS) for the rows that
// carry ReceiverTS (timeplace.PlaceBatch), and IngestTS for the rows
// that do not (T-12).
func (p *Pipeline) receipts(b *Batch) ([]time.Time, int) {
	rx := make([]time.Time, len(b.Rows))
	var idx []int
	var ts []time.Time
	for i := range b.Rows {
		r := &b.Rows[i]
		rx[i] = r.IngestTS
		if r.IngestTS.IsZero() {
			rx[i] = b.IngestTS
		}
		if r.ReceiverTS != nil {
			idx = append(idx, i)
			ts = append(ts, *r.ReceiverTS)
		}
	}
	placed, clamped := timeplace.PlaceBatch(b.IngestTS, ts, p.s.MaxBatchSpacing)
	for j, i := range idx {
		rx[i] = placed[j]
	}
	return rx, clamped
}

func strPtr(s string) *string { return &s }

// observeRow decodes one row, places it, feeds the tracker and, when the
// tracker completes an observation, publishes it. It returns the tracks
// row of a published observation.
func (p *Pipeline) observeRow(b *Batch, r *Row, rx time.Time) *track.Row {
	p.cnt.Inc(CounterRows)
	hasRx := r.ReceiverTS != nil
	if !hasRx {
		p.cnt.Inc(CounterRxTSMissing)
		p.lim.Limited("rid_rx_ts_missing:"+r.ReceiverID).Warn("observation without the receiver's rx_ts: received at its arrival (T-12)",
			slog.String("receiver_id", r.ReceiverID), slog.String("transmitter", r.Transmitter))
	}
	// Every row is placed: at its reception unless its Location's
	// broadcast time is believed below.
	at, src := rx, core.TimeSourceClock
	if !hasRx {
		src = core.TimeSystem
	}
	r.CapturedAt, r.TimeSource = &at, strPtr(string(src))

	d, err := decodeFrame(r)
	if err != nil {
		p.refused(r, err)
		return nil
	}
	if len(d.messages) == 0 {
		p.cnt.Inc(CounterFramesSkipped)
		return nil
	}
	backlog := b.Backlog || r.Backlog
	st := &p.live
	if backlog {
		st = &p.backlog
	}
	receiver := r.ReceiverID
	if receiver == "" {
		receiver = b.ReceiverID
	}
	if d.location != nil {
		pl := p.place(d.location, rx, hasRx)
		r.CapturedAt = &pl.CapturedAt
		r.TimeSource = strPtr(string(pl.Source))
		if pl.Fallback != timeplace.FallbackUnknown && pl.Fallback != timeplace.FallbackInvalid && pl.Source != core.TimeSystem {
			ts := pl.TS
			r.TSBroadcast = &ts
		}
		if st.memos.put(memoKey{receiver, r.Transmitter}, placement{rx: rx, p: pl, frameID: r.FrameID}) {
			p.cnt.Inc(CounterPlacementsEvicted)
		}
	}
	nowS := seconds(rx)
	if nowS < st.nowS {
		p.cnt.Inc(CounterTrackerClockHeld)
		nowS = st.nowS
	}
	st.nowS = nowS
	obs := st.t.Take(rid.Frame{Receiver: receiver, Transmitter: r.Transmitter, Messages: d.messages, NowS: nowS, RxTS: rx})
	if obs == nil {
		return nil
	}
	return p.publish(st, obs, backlog)
}

// place is the Location's placement (T-07, T-08): its broadcast time
// when timeplace believes it against rx, else rx. A row without the
// receiver's rx_ts was received at its arrival; when its broadcast time
// is not believed it is placed there with time_source system (T-12).
func (p *Pipeline) place(loc *odid.Location, rx time.Time, hasRx bool) timeplace.Placement {
	pl := timeplace.PlaceBroadcast(timestampTenths(loc), loc.TSAccuracy, rx, p.s.Broadcast)
	if pl.Source == core.TimeBroadcast {
		p.cnt.Inc(CounterPlacedBroadcast)
		return pl
	}
	p.cnt.Inc(CounterTimeFallback + string(pl.Fallback))
	if !hasRx {
		p.cnt.Inc(CounterPlacedArrival)
		return timeplace.PlaceArrival(rx)
	}
	return pl
}

// refused counts a frame the decoder refused, by phrase, and logs the
// first of each kind, then at most once a minute (E-09: a stream of bad
// frames must not fill the log).
func (p *Pipeline) refused(r *Row, err error) {
	msg := err.Error()
	r.DecodeError = &msg
	p.cnt.Inc(CounterDecodeRefused)
	key := refusalKey(err)
	if !p.refusals[key] && len(p.refusals) >= maxRefusalKinds {
		key = "other"
	} else {
		p.refusals[key] = true
	}
	if key == "other" {
		p.cnt.Inc(CounterDecodeRefusedOther)
	} else {
		p.cnt.Inc(CounterDecodeRefused + "_" + key)
	}
	p.lim.Limited("rid_decode_refused:"+key).Warn("Remote ID frame refused by the decoder; the raw frame is stored",
		slog.String("reason", msg), slog.String("receiver_id", r.ReceiverID), slog.String("transmitter", r.Transmitter),
		slog.String("frame_id", r.FrameID))
}

// publish builds the observation's track, publishes it and its
// identification change, and returns its tracks row.
func (p *Pipeline) publish(st *trackerState, obs *rid.Observation, backlog bool) *track.Row {
	loc := &obs.Location
	if loc.LatDeg == nil || loc.LonDeg == nil {
		p.cnt.Inc(CounterNoPosition)
		p.lim.Limited("rid_no_position:"+obs.Transmitter).Info("Location without a position: no track published (R-01)",
			slog.String("receiver_id", obs.Receiver), slog.String("transmitter", obs.Transmitter))
		st.memos.take(memoKey{obs.Receiver, obs.Transmitter})
		return nil
	}
	pl, ok := st.memos.take(memoKey{obs.Receiver, obs.Transmitter})
	if !ok || !pl.rx.Equal(obs.RxTS) {
		// Never expected: the tracker publishes the Location it held for
		// this (receiver, transmitter), which was memoised when heard.
		p.cnt.Inc(CounterPlacementMissed)
		pl = placement{rx: obs.RxTS, p: p.place(loc, obs.RxTS, true)}
	}
	times := timeplace.Times(pl.p, obs.RxTS, backlog)
	body := track.Body{
		TrackID: obs.DroneID, Trust: core.TrustBroadcast, Source: track.SourceDirectRID, SourceInstance: obs.Receiver,
		Position: track.Position{Lat: *loc.LatDeg, Lng: *loc.LonDeg}, AltWGS84M: loc.AltHAEM, AltPressureM: loc.AltBaroM,
		HeightM: loc.HeightM, Status: statusName(loc.Status), Emergency: loc.Status == odid.StatusEmergency,
	}
	if loc.HeightM != nil {
		body.HeightRef = heightRef(loc.HeightReference)
	}
	if body.Status == nil {
		p.cnt.Inc(CounterStatusUnknown)
	}
	p.altitude(&body, loc, trackKey{backlog, obs.DroneID}, st.nowS)
	p.velocity(&body, loc)
	body.Identification = p.identify(obs)

	m, err := track.New(p.s.Producer, times, body)
	if err != nil {
		p.cnt.Inc(CounterTrackInvalid)
		p.lim.Limited("rid_track_invalid").Error("track not built", slog.String("track_id", obs.DroneID), slog.String("error", err.Error()))
		return nil
	}
	if err := track.Publish(p.d.Publisher, m); err != nil {
		p.cnt.Inc(CounterPublishFailed)
		p.lim.Limited("rid_track_publish").Warn("track not published", slog.String("track_id", obs.DroneID), slog.String("error", err.Error()))
	} else {
		p.cnt.Inc(CounterPublished)
	}
	p.identChange(m, trackKey{backlog, obs.DroneID})
	airborne := rid.Airborne(loc.Status)
	dedupe := "direct_rid:" + pl.frameID
	if pl.frameID == "" {
		dedupe = "direct_rid:msg:" + m.MsgID
	}
	row := track.RowOf(m, times, dedupe, &airborne)
	return &row
}

// altitude fills the AMSL altitude through rid.AltitudeSelector with
// the geoid (R-07, R-08): a geodetic altitude is HAE minus the
// undulation; a pressure altitude stays in alt_pressure_m with
// alt_source pressure and never in alt_amsl_m; without a geoid there is
// no AMSL altitude.
func (p *Pipeline) altitude(b *track.Body, loc *odid.Location, key trackKey, nowS float64) {
	in := rid.AltInput{AltHAEM: loc.AltHAEM, AltPressureM: loc.AltBaroM, VertAccuracyCode: loc.VertAccuracy}
	if p.d.Geoid != nil {
		n, err := p.d.Geoid.UndulationM(core.LatLon{LatDeg: *loc.LatDeg, LonDeg: *loc.LonDeg})
		if err != nil {
			p.cnt.Inc(CounterGeoidFailed)
			p.lim.Limited("rid_geoid_failed").Warn("no geoid undulation at the position: no AMSL altitude",
				slog.Float64("lat_deg", *loc.LatDeg), slog.Float64("lon_deg", *loc.LonDeg), slog.String("error", err.Error()))
		} else {
			in.UndulationM = &n
		}
	}
	sel, ok := p.alts.get(key)
	if !ok {
		sel = rid.NewAltitudeSelector(p.s.Altitude)
		if p.alts.put(key, sel) {
			p.cnt.Inc(CounterAltHoldsEvicted)
		}
	}
	res := sel.Select(in, nowS)
	b.AltSource = res.Source
	switch res.Source {
	case core.AltGeodetic:
		p.cnt.Inc(CounterAltGeodetic)
		b.AltAMSLM = res.AltAMSLM
	case core.AltPressure:
		p.cnt.Inc(CounterAltPressure)
	case core.AltNone, core.AltNetwork:
		p.cnt.Inc(CounterAltNone)
		if p.d.Geoid == nil && loc.AltHAEM != nil {
			p.cnt.Inc(CounterAltNoGeoid)
		}
	}
}

// velocity maps rid.VelocityNED back to the track's speed, track and
// climb (R-10): a speed without a direction is no velocity, and all
// three are null rather than zero.
func (p *Pipeline) velocity(b *track.Body, loc *odid.Location) {
	vn, _, vd := rid.VelocityNED(loc.SpeedHorizontalMS, loc.DirectionDeg, loc.SpeedVerticalMS)
	if vn == nil {
		p.cnt.Inc(CounterVelocityUnknown)
		return
	}
	b.SpeedMS, b.TrackDeg = loc.SpeedHorizontalMS, loc.DirectionDeg
	if vd != nil {
		up := -*vd
		b.VSpeedMS = &up
	}
}

// identify resolves the observation against the registry projection on
// the broadcast basis (identify.ResolveRemoteID; G-01, G-02, G-05, I-05).
// Before the projection has ever loaded the lookup is nil and identify
// answers registry_unavailable (SC-22).
func (p *Pipeline) identify(obs *rid.Observation) core.Identification {
	var reg identify.Lookup
	if p.d.Registry != nil {
		reg = p.d.Registry()
	}
	id := identify.ResolveRemoteID(reg, identify.RemoteIDIdentity{
		Identified: obs.Identified, UAID: obs.UAID, IDType: obs.IDType, OperatorID: obs.OperatorID,
	})
	if id.Reason == core.ReasonRegistryUnavailable {
		p.cnt.Inc(CounterRegistryUnavailable)
	}
	return id
}

// identChange publishes the track's identification on ident.v1 when it
// differs from the last one published for the track id.
func (p *Pipeline) identChange(m *track.Message, key trackKey) {
	id := m.Body.Identification
	prev, ok := p.idents.get(key)
	var before *core.Identification
	if ok {
		before = &prev
	}
	if !track.IdentChanged(before, id) {
		return
	}
	if err := track.PublishIdent(p.d.Publisher, track.NewIdentChange(m, before, p.now())); err != nil {
		// Not remembered: the next observation of the track announces it
		// again.
		p.cnt.Inc(CounterIdentPublishFailed)
		p.lim.Limited("rid_ident_publish").Warn("identification change not published; retried with the track's next observation",
			slog.String("track_id", m.Body.TrackID), slog.String("error", err.Error()))
		return
	}
	p.cnt.Inc(CounterIdentChanges)
	if p.idents.put(key, id) {
		p.cnt.Inc(CounterIdentMemoryEvicted)
	}
}
