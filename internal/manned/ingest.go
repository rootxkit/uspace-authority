package manned

import (
	"container/list"
	"encoding/json"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/timeplace"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of the ingest (E-09). The brief's five are frames_received,
// aircraft_published, aircraft_refused_schema, placements_clamped and
// the client's reconnects.
const (
	CounterFrames            = "frames_received"
	CounterFramesMalformed   = "frames_malformed"
	CounterUnknownSchema     = "frames_unknown_schema_skipped"
	CounterStatusFrames      = "status_frames"
	CounterSnapshotFrames    = "snapshot_frames"
	CounterAircraft          = "aircraft_published"
	CounterRefusedSchema     = "aircraft_refused_schema"
	CounterRefusedDisabled   = "aircraft_refused_source_disabled"
	CounterPlacedAtArrival   = "placed_at_arrival_without_rx_ts"
	CounterWithoutTS         = "samples_without_ts"
	CounterClamped           = "placements_clamped"
	CounterWithoutAge        = "batches_without_age"
	CounterDuplicates        = "duplicates_skipped"
	CounterOlder             = "older_samples_skipped"
	CounterEvicted           = "aircraft_evicted"
	CounterAgedStale         = "aircraft_aged_stale"
	CounterAgedDisabled      = "aircraft_aged_source_disabled"
	CounterPublishFailed     = "publish_failed"
	CounterSnapshotTruncated = "snapshot_items_over_limit"
	CounterAdaptersRefused   = "adapters_refused"
)

// Gate is source control (internal/sources.Follower, WP-10).
type Gate interface {
	Query(sourceType string, instanceID *string) coresources.Decision
}

// Sink takes what the ingest publishes: the message on man.v1 (core
// NATS, never blocking) and its row towards tsdb-writer (queued).
type Sink interface {
	Publish(p Published) error
	Rows(rows []Row)
}

// Settings bound the ingest (E-10).
type Settings struct {
	// FeedInstance is the source instance of the feed itself (its
	// src.v1.ansp_feed.<instance> status and its source switch).
	FeedInstance string
	// MaxAircraft bounds the per-aircraft state map; past it the
	// aircraft updated longest ago is forgotten and counted.
	MaxAircraft int
	// MaxFrameBytes bounds one frame.
	MaxFrameBytes int
	// MaxSnapshotItems bounds the aircraft taken from one snapshot; the
	// rest are counted.
	MaxSnapshotItems int
	// MaxAdapters bounds the ANSP adapters followed.
	MaxAdapters int
	// MaxSpacing is PlaceBatch's bound (T-02).
	MaxSpacing time.Duration
}

// DefaultSettings are the configuration's defaults.
func DefaultSettings() Settings {
	return Settings{FeedInstance: "ansp", MaxAircraft: 10000, MaxFrameBytes: 4 << 20, MaxSnapshotItems: 10000, MaxAdapters: 64,
		MaxSpacing: timeplace.DefaultMaxBatchSpacing}
}

// instanceRe is the ANSP's adapter id (track/manned/v1
// source_instance).
var instanceRe = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// ValidInstance says whether s is an adapter id.
func ValidInstance(s string) bool { return len(s) <= 64 && instanceRe.MatchString(s) }

// Ingest maps the ANSP's frames onto this system: every frame is
// dispatched on schema (M12, M29); track/manned/v1 bodies are validated
// against the ANSP's schema, placed on this system's clock, deduplicated
// per aircraft and published; console/status/v1 and console/snapshot/v1
// feed the feed's state and the adapters' (an adapter the ANSP says is
// stale or disabled ages its aircraft, never removes them); an unknown
// schema is counted and skipped (additive rule). Safe for concurrent
// use.
type Ingest struct {
	S        Settings
	V        *Validator
	Gate     Gate
	Sink     Sink
	Feed     *Feed
	Counters *core.Counters
	Limiter  *logging.Limiter
	Now      func() time.Time

	once  sync.Once
	mu    sync.Mutex
	lru   *list.List // front: updated most recently; values *held
	byKey map[string]*list.Element
}

func (in *Ingest) init() {
	in.once.Do(func() {
		if in.Counters == nil {
			in.Counters = &core.Counters{}
		}
		if in.Limiter == nil {
			in.Limiter = logging.NewLimiter(logging.Discard(), time.Minute, 0, in.Counters)
		}
		if in.Feed == nil {
			in.Feed = NewFeed(DefaultFeedSettings(), time.Now())
		}
		d := DefaultSettings()
		if in.S.FeedInstance == "" {
			in.S.FeedInstance = d.FeedInstance
		}
		if in.S.MaxAircraft <= 0 {
			in.S.MaxAircraft = d.MaxAircraft
		}
		if in.S.MaxSnapshotItems <= 0 {
			in.S.MaxSnapshotItems = d.MaxSnapshotItems
		}
		if in.S.MaxAdapters <= 0 {
			in.S.MaxAdapters = d.MaxAdapters
		}
		if in.S.MaxSpacing <= 0 {
			in.S.MaxSpacing = d.MaxSpacing
		}
		in.lru, in.byKey = list.New(), map[string]*list.Element{}
	})
}

func (in *Ingest) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// Len is the aircraft held.
func (in *Ingest) Len() int {
	in.init()
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.lru.Len()
}

func (in *Ingest) enabled(instance string) bool {
	if in.Gate == nil {
		return true
	}
	if !in.Gate.Query(SourceType, &in.S.FeedInstance).Enabled {
		return false
	}
	return in.Gate.Query(SourceType, &instance).Enabled
}

// HandleFrame takes one frame of the stream received at arrival.
func (in *Ingest) HandleFrame(data []byte, arrival time.Time) {
	in.init()
	in.Counters.Inc(CounterFrames)
	env, err := decodeEnvelope(data, in.S.MaxFrameBytes)
	if err != nil {
		in.Counters.Inc(CounterFramesMalformed)
		in.Limiter.Limited("manned_frame_malformed").Warn("ANSP frame refused", slog.String("error", err.Error()))
		return
	}
	in.Feed.Frame(arrival)
	switch env.Schema {
	case SchemaTrack:
		in.handleTracks([]envelopeIn{env}, arrival)
	case SchemaStatus:
		in.Counters.Inc(CounterStatusFrames)
		var st statusIn
		if err := json.Unmarshal(env.Body, &st); err != nil {
			in.Counters.Inc(CounterFramesMalformed)
			in.Limiter.Limited("manned_status_malformed").Warn("ANSP status frame refused", slog.String("error", truncate(err.Error(), 200)))
			return
		}
		in.Feed.ANSPStatus(st, arrival)
		in.applyAdapters(st.Adapters, arrival)
	case SchemaSnapshot:
		in.Counters.Inc(CounterSnapshotFrames)
		in.HandleSnapshot(env.Body, arrival)
	default:
		in.Counters.Inc(CounterUnknownSchema)
		in.Limiter.Limited("manned_unknown_schema").Info("ANSP frame of an unknown schema skipped (additive rule)",
			slog.String("schema", truncate(env.Schema, 64)))
	}
}

// HandleSnapshot takes a console/snapshot/v1 body or the answer of GET
// /v1/manned-traffic/snapshot received at arrival: its aircraft are one
// batch (T-02), its adapters age theirs.
func (in *Ingest) HandleSnapshot(raw json.RawMessage, arrival time.Time) {
	in.init()
	var snap snapshotIn
	if err := json.Unmarshal(raw, &snap); err != nil {
		in.Counters.Inc(CounterFramesMalformed)
		in.Limiter.Limited("manned_snapshot_malformed").Warn("ANSP snapshot refused", slog.String("error", truncate(err.Error(), 200)))
		return
	}
	items := snap.Manned
	if len(items) > in.S.MaxSnapshotItems {
		in.Counters.Add(CounterSnapshotTruncated, uint64(len(items)-in.S.MaxSnapshotItems))
		in.Limiter.Limited("manned_snapshot_over_limit").Error("ANSP snapshot holds more aircraft than are taken; the rest are counted",
			slog.Int("aircraft", len(items)), slog.Int("max", in.S.MaxSnapshotItems))
		items = items[:in.S.MaxSnapshotItems]
	}
	envs := make([]envelopeIn, 0, len(items))
	for _, it := range items {
		env, err := decodeEnvelope(it, in.S.MaxFrameBytes)
		if err == nil && env.Schema != SchemaTrack {
			err = core.Fieldf("schema", "%q in manned[], want %s", truncate(env.Schema, 64), SchemaTrack)
		}
		if err != nil {
			in.Counters.Inc(CounterRefusedSchema)
			in.Limiter.Limited("manned_snapshot_item").Warn("ANSP snapshot aircraft refused", slog.String("error", err.Error()))
			continue
		}
		envs = append(envs, env)
	}
	in.handleTracks(envs, arrival)
	if snap.Degraded != nil {
		in.Feed.ANSPStatus(statusIn{Degraded: snap.Degraded, Adapters: snap.Adapters}, arrival)
	}
	in.applyAdapters(snap.Adapters, arrival)
}

// handleTracks validates, gates, places and publishes the samples of
// one frame.
func (in *Ingest) handleTracks(envs []envelopeIn, arrival time.Time) {
	samples := make([]sample, 0, len(envs))
	for _, env := range envs {
		body, err := in.V.Body(env.Body)
		if err != nil {
			in.Counters.Inc(CounterRefusedSchema)
			in.Limiter.Limited("manned_body_refused").Warn("ANSP aircraft refused by the ANSP's schema", slog.String("error", err.Error()))
			continue
		}
		if !in.enabled(body.SourceInstance) {
			in.Counters.Inc(CounterRefusedDisabled)
			continue
		}
		s := newSample(env, body)
		if s.ts == nil {
			in.Counters.Inc(CounterWithoutTS)
		}
		samples = append(samples, s)
	}
	if len(samples) == 0 {
		return
	}
	ps, count := placeBatch(samples, arrival, in.S.MaxSpacing)
	if count.AtArrival > 0 {
		in.Counters.Add(CounterPlacedAtArrival, uint64(count.AtArrival))
		in.Limiter.Limited("manned_at_arrival").Info("ANSP aircraft without rx_ts placed at arrival (T-12)", slog.Int("aircraft", count.AtArrival))
	}
	if count.Clamped > 0 {
		in.Counters.Add(CounterClamped, uint64(count.Clamped))
		in.Limiter.Limited("manned_clamped").Warn("ANSP aircraft older than the batch spacing bound placed at the bound (T-02)",
			slog.Int("clamped", count.Clamped), slog.Duration("max_spacing", in.S.MaxSpacing))
	}
	if count.WithoutAge > 0 {
		in.Counters.Add(CounterWithoutAge, uint64(count.WithoutAge))
	}
	var rows []Row
	in.mu.Lock()
	for _, p := range ps {
		if r, ok := in.acceptLocked(p); ok {
			rows = append(rows, r)
			if p.body.State == StateLive {
				in.Feed.LiveSample(secondsSince(p.rx, p.capturedAt), arrival)
			}
		}
	}
	in.mu.Unlock()
	if len(rows) > 0 && in.Sink != nil {
		in.Sink.Rows(rows)
	}
}

// acceptLocked publishes p unless it repeats or precedes what is held
// for its aircraft: an older sample is skipped; the same sample again
// is skipped unless it moves the aircraft's state forward (live, stale,
// source_disabled), in which case the held message is republished in
// the new state at its own placement.
func (in *Ingest) acceptLocked(p placed) (Row, bool) {
	icao := p.body.ICAO24
	if e, ok := in.byKey[icao]; ok {
		old, _ := e.Value.(*held)
		switch {
		case p.sourceAt.Before(old.sourceAt):
			in.Counters.Inc(CounterOlder)
			return Row{}, false
		case p.sourceAt.Equal(old.sourceAt):
			if stateRank(p.body.State) <= stateRank(old.msg.Body.State) {
				in.Counters.Inc(CounterDuplicates)
				return Row{}, false
			}
			return in.ageLocked(e, p.body.State, p.rx)
		}
		h, err := newHeld(p)
		if err != nil {
			in.Counters.Inc(CounterRefusedSchema)
			return Row{}, false
		}
		e.Value = h
		in.lru.MoveToFront(e)
		return in.publishLocked(h)
	}
	h, err := newHeld(p)
	if err != nil {
		in.Counters.Inc(CounterRefusedSchema)
		return Row{}, false
	}
	if in.lru.Len() >= in.S.MaxAircraft {
		if back := in.lru.Back(); back != nil {
			old, _ := back.Value.(*held)
			in.lru.Remove(back)
			delete(in.byKey, old.msg.Body.ICAO24)
			in.Counters.Inc(CounterEvicted)
			in.Limiter.Limited("manned_evicted").Warn("per-aircraft state full; the aircraft updated longest ago is forgotten",
				slog.Int("max", in.S.MaxAircraft))
		}
	}
	in.byKey[icao] = in.lru.PushFront(h)
	return in.publishLocked(h)
}

func (in *Ingest) publishLocked(h *held) (Row, bool) {
	pub, err := h.published()
	if err != nil {
		in.Counters.Inc(CounterPublishFailed)
		return Row{}, false
	}
	if in.Sink != nil {
		if err := in.Sink.Publish(pub); err != nil {
			in.Counters.Inc(CounterPublishFailed)
			in.Limiter.Limited("manned_publish").Warn("man.v1 not published", slog.String("error", err.Error()))
		}
	}
	in.Counters.Inc(CounterAircraft)
	return pub.Row, true
}

// ageLocked republishes the aircraft held at e in state (forward only)
// with a new msg_id, its placement unchanged.
func (in *Ingest) ageLocked(e *list.Element, state string, now time.Time) (Row, bool) {
	old, _ := e.Value.(*held)
	if stateRank(state) <= stateRank(old.msg.Body.State) {
		return Row{}, false
	}
	h := *old
	h.msg.Body.State = state
	h.msg.MsgID = bus.NewULID(now)
	age := secondsSince(now, old.capAt)
	h.msg.Body.AgeS = &age
	e.Value = &h
	switch state {
	case StateStale:
		in.Counters.Inc(CounterAgedStale)
	case StateSourceDisabled:
		in.Counters.Inc(CounterAgedDisabled)
	}
	return in.publishLocked(&h)
}

// Age moves every aircraft held of instance ("" for every adapter)
// forward to state, as a local source switch would: the aircraft stays
// on the picture with its age, never removed. It returns how many
// changed.
func (in *Ingest) Age(instance, state string, now time.Time) int {
	in.init()
	var rows []Row
	in.mu.Lock()
	for e := in.lru.Front(); e != nil; e = e.Next() {
		h, _ := e.Value.(*held)
		if instance != "" && h.msg.Body.SourceInstance != instance {
			continue
		}
		if r, ok := in.ageLocked(e, state, now); ok {
			rows = append(rows, r)
		}
	}
	in.mu.Unlock()
	if len(rows) > 0 && in.Sink != nil {
		in.Sink.Rows(rows)
	}
	return len(rows)
}

// ApplySwitches ages the aircraft of every switched-off adapter, or of
// every adapter when the feed itself is switched off (source_disabled).
func (in *Ingest) ApplySwitches(now time.Time) int {
	in.init()
	if in.Gate == nil {
		return 0
	}
	if !in.Gate.Query(SourceType, &in.S.FeedInstance).Enabled {
		return in.Age("", StateSourceDisabled, now)
	}
	in.mu.Lock()
	seen := map[string]bool{}
	for e := in.lru.Front(); e != nil; e = e.Next() {
		h, _ := e.Value.(*held)
		seen[h.msg.Body.SourceInstance] = true
	}
	in.mu.Unlock()
	n := 0
	for inst := range seen {
		if !in.Gate.Query(SourceType, &inst).Enabled {
			n += in.Age(inst, StateSourceDisabled, now)
		}
	}
	return n
}

// applyAdapters ages the aircraft of every adapter the ANSP says is
// stale or down (stale) or disabled (source_disabled).
func (in *Ingest) applyAdapters(adapters []AdapterState, now time.Time) {
	if len(adapters) > in.S.MaxAdapters {
		in.Counters.Add(CounterAdaptersRefused, uint64(len(adapters)-in.S.MaxAdapters))
		adapters = adapters[:in.S.MaxAdapters]
	}
	for _, a := range adapters {
		if !ValidInstance(a.ID) {
			in.Counters.Inc(CounterAdaptersRefused)
			continue
		}
		switch {
		case a.State == "disabled" || !a.Enabled:
			in.Age(a.ID, StateSourceDisabled, now)
		case a.State == "stale" || a.State == "down":
			in.Age(a.ID, StateStale, now)
		}
	}
}
