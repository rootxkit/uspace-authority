package detectsvc

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/alerting"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/intents"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// Counters of a worker (E-09). The monitor's own counters (rejected_*,
// zone_checks_not_evaluated, zone_limits_not_judged, conflict_checks_skipped,
// ...) are kept beside them, monotonic across rebuilds.
const (
	CounterTrackMalformed      = "track_malformed"         // a trk.v1 message that is not JSON: terminated, never judged
	CounterTrackRefused        = "track_refused"           // a track the schema refuses (incl. simulated, sitl; 06 T11): terminated, never judged
	CounterTrackObserved       = "track_observed"          // a track handed to the monitor
	CounterConflictIgnored     = "conflict_events_ignored" // a conflict raise or clear: the authority warns of no proximity (plan D5, Q-A9)
	CounterUSpacePresence      = "uspace_presence"         // a USPACE zone raise: recorded as in_uspace, not a violation
	CounterAlertKindUnknown    = "alert_kind_unknown"      // an alert of a kind this mapping does not know: logged at error level
	CounterClearUnmatched      = "clear_unmatched"         // a clear of a key with no open violation: logged at error level
	CounterEvidenceMissing     = "evidence_missing"        // a raise for an aircraft whose samples were evicted
	CounterRaised              = "violations_raised"       // violation/v1 raised
	CounterUpdated             = "violations_updated"      // violation/v1 updated (severity change, carried over a rebuild)
	CounterCleared             = "violations_cleared"      // violation/v1 cleared
	CounterClearedReconfigured = "violations_cleared_reconfigured"
	CounterRepublished         = "violations_republished" // active violations republished (C-08)
	CounterRepublishFailed     = "violations_republish_failed"
	CounterRepublishDeferred   = "violations_republish_deferred" // not republished this tick: the bus failed or the tick's budget ran out; the next tick starts with them
	CounterPublishFailed       = "alrt_publish_failed"           // a raise or clear not yet on ALRT: kept in the outbox and retried every tick
	CounterOutboxDropped       = "alrt_outbox_dropped"           // the outbox past its bound: the oldest dropped, logged at error level
	CounterMonitorRebuilt      = "monitor_rebuilt"               // a new zone set or policy: the monitor rebuilt, each aircraft's last sample re-observed
	CounterAircraftRefused     = "aircraft_refused"              // a new aircraft refused by the monitor's capacity: it goes unjudged
	CounterSourceSwitches      = "source_switches_applied"       // a source-control state handed to the monitor (B-11)
	CounterHeightLifted        = "height_lifted_authorised"      // a height_120m held (or cleared authorised) for an aircraft matched to an intent inside U-space airspace (WP-26)
	CounterHeightRestored      = "height_restored_unmatched"     // a held height_120m raised: the aircraft lost its match while still over the limit
	CounterNoAuthNotJudged     = "no_authorisation_not_judged"   // an aircraft entered U-space airspace and this detector has no DSS: no_authorisation is not judged for it
)

// Publisher writes one violation message to the ALRT stream.
type Publisher interface {
	PublishViolation(ctx context.Context, m *violation.Message) error
}

// ZoneSet is what a monitor is built with: the published zones and the
// dynamic restrictions in force, and what cannot be judged.
type ZoneSet struct {
	Zones []*zones.Zone
	// Versions is the zone_version of each published feature by its
	// identifier; a dynamic restriction has none.
	Versions map[string]int
	// Generation changes whenever the set judges differently.
	Generation [2]uint64
	// Loaded says each projection has been read at least once.
	ZonesLoaded, RestrictionsLoaded bool
}

// Inputs are what every worker judges with; safe for concurrent use.
type Inputs interface {
	Zones() ZoneSet
	Policy() (policy.Policy, bool)
	Sources() (coresources.State, bool)
	Env(p core.LatLon) zones.Env
	Elevation(p core.LatLon) *terrain.Elevation
	// Authorisations is the operational intents board of the
	// no_authorisation detector (WP-26); nil without a DSS.
	Authorisations() *intents.Board
}

// Settings bound a worker.
type Settings struct {
	// MaxAircraft is the monitor's cap (alerting.Config.MaxAircraft) and
	// the excerpt store's.
	MaxAircraft int
	// ExcerptWindowS is how far back a raise copies samples (10 s);
	// ExcerptMaxSamples bounds them per aircraft.
	ExcerptWindowS    float64
	ExcerptMaxSamples int
	// OutboxMax bounds the raises and clears waiting for ALRT.
	OutboxMax      int
	PublishTimeout time.Duration
	// TickBudget bounds the publishing one tick does (the outbox and the
	// republication together), so a bus that does not answer never
	// stalls the tick, whatever the number of active violations.
	TickBudget time.Duration
	// Now is the process clock; nil is time.Now.
	Now func() time.Time
}

// DefaultSettings are the defaults of config.Detect.
func DefaultSettings() Settings {
	return Settings{MaxAircraft: 50_000, ExcerptWindowS: 10, ExcerptMaxSamples: 64, OutboxMax: 10_000, PublishTimeout: 2 * time.Second,
		TickBudget: 500 * time.Millisecond}
}

// ConfigFor is the monitor configuration for zs under thresholds t
// (INV-03): uspace-core's defaults with the policy's hysteresis, ageing,
// live age, severities, pressure margin and height limit, conflicts
// skipped (plan D5, Q-A9), and the aircraft cap.
func ConfigFor(zs []*zones.Zone, t policy.Thresholds, maxAircraft int) alerting.Config {
	c := alerting.DefaultConfig()
	c.SkipConflicts = true
	c.Zones = zs
	c.ClearAfterS = t.ClearAfterS
	c.StaleAfterS = t.StaleAfterS
	c.LiveMaxAgeS = t.LiveMaxAgeS
	c.MismatchSeverity = t.MismatchSeverity
	c.IdentificationSeverity = t.IdentificationSeverity
	c.ZonePolicy.PressureUncertaintyM = t.PressureUncertaintyM
	c.ZonePolicy.ConditionalSeverity = t.ZoneConditionalSeverity
	limit := t.HeightLimitAGLM
	c.ZonePolicy.MaxHeightAGLM = &limit
	if maxAircraft > 0 {
		c.MaxAircraft = maxAircraft
	}
	return c
}

// open is a violation raised and not yet cleared: its last body
// (without samples) and how far its excerpt has been published.
type open struct {
	body         violation.Body
	excerptUpToS float64
}

// zoneRef is the zone an alert key names.
type zoneRef struct {
	zone    *zones.Zone
	country string
	id      string
}

// Worker judges the tracks of one cell3 (or every cell, CELLS=all) with
// one uspace-core alerting.Monitor, and publishes what it raises and
// clears as violation/v1 (plan D5). It is owned by one goroutine: every
// method but StatusAttrs is called from it.
type Worker struct {
	Name     string
	Counters *core.Counters
	// MonitorCounters are the monitor's counters, folded in every tick
	// and at every rebuild so they never go back.
	MonitorCounters *core.Counters

	in     Inputs
	set    Settings
	pub    Publisher
	logger *slog.Logger
	lim    *logging.Limiter

	mon       *alerting.Monitor
	monSnap   map[string]uint64
	zones     ZoneSet
	zoneByKey map[string]*zones.Zone
	policyVer int64
	// regnum is the policy's registration-number pattern: what is kept of
	// an operator number is its public part under it (G-04).
	regnum    *regnum.Validator
	lastWallS float64
	open      map[string]*open
	uspace    map[string]map[string]struct{}
	// noAuth are the no_authorisation cases, one per presence of an
	// aircraft in a U-space airspace (by the presence's alert key);
	// heldHeight the height_120m keys lifted for an authorised aircraft
	// (WP-26).
	noAuth     map[string]*naCase
	heldHeight map[string]bool
	// thresholds are the policy's, as of the last rebuild.
	thresholds policy.Thresholds
	excerpts   *Excerpts
	outbox     []*violation.Message
	rebuilding map[string]bool
	// republishFrom is where the next republication starts in the
	// active violations, so a tick cut short starves none of them.
	republishFrom int

	statMu sync.Mutex
	stats  workerStats
}

type workerStats struct {
	tracked, active, outbox int
	noAuth                  noAuthStats
	capacityExceeded        bool
	policyVersion           int64
}

// NewWorker returns a worker for name (a c3 cell name, or "all").
func NewWorker(name string, in Inputs, set Settings, pub Publisher, logger *slog.Logger, lim *logging.Limiter) *Worker {
	if logger == nil {
		logger = logging.Discard()
	}
	w := &Worker{
		Name: name, Counters: &core.Counters{}, MonitorCounters: &core.Counters{},
		in: in, set: set, pub: pub, logger: logger.With(slog.String("cell3", name)), lim: lim,
		open: map[string]*open{}, uspace: map[string]map[string]struct{}{},
		noAuth: map[string]*naCase{}, heldHeight: map[string]bool{},
	}
	w.excerpts = NewExcerpts(set.ExcerptWindowS, set.ExcerptMaxSamples, set.MaxAircraft, w.Counters)
	w.maybeRebuild()
	return w
}

func (w *Worker) now() time.Time {
	if w.set.Now != nil {
		return w.set.Now()
	}
	return time.Now()
}

// wallS is the monitor's clock: the process clock in seconds since the
// Unix epoch (the ingest's time base), never going back.
func (w *Worker) wallS() float64 {
	w.lastWallS = math.Max(w.lastWallS, seconds(w.now()))
	return w.lastWallS
}

func (w *Worker) warn(key, msg string, attrs ...any) {
	if w.lim != nil {
		w.lim.Limited(key).Warn(msg, attrs...)
		return
	}
	w.logger.Warn(msg, attrs...)
}

func (w *Worker) errorf(key, msg string, attrs ...any) {
	if w.lim != nil {
		w.lim.Limited(key).Error(msg, attrs...)
		return
	}
	w.logger.Error(msg, attrs...)
}

// HandleData decodes one trk.v1 message and judges it. It reports false
// for a message that will never be judged (malformed or refused by the
// schema), which the caller terminates rather than redelivers.
func (w *Worker) HandleData(data []byte) bool {
	var m track.Message
	if err := json.Unmarshal(data, &m); err != nil {
		w.Counters.Inc(CounterTrackMalformed)
		w.warn("detect_track_malformed", "trk.v1 message is not JSON: not judged")
		return false
	}
	if err := m.Validate(); err != nil {
		w.Counters.Inc(CounterTrackRefused)
		w.warn("detect_track_refused", "trk.v1 message refused by its schema: not judged", slog.String("error", err.Error()),
			slog.String("track_id", m.Body.TrackID))
		return false
	}
	return w.Observe(&m)
}

// Observe judges one validated track message.
func (w *Worker) Observe(m *track.Message) bool {
	w.maybeRebuild()
	t, err := TimesOf(m)
	if err != nil {
		w.Counters.Inc(CounterTrackRefused)
		w.warn("detect_track_refused", "trk.v1 message with an unreadable time: not judged", slog.String("error", err.Error()))
		return false
	}
	pos := core.LatLon{LatDeg: m.Body.Position.Lat, LonDeg: m.Body.Position.Lng}
	tr := ToTrack(m, t, w.in.Env(pos), w.Counters)
	if !m.Backlog {
		// History is recorded by tsdb-writer and never alerted (T-04); it
		// is neither evidence of a live condition nor re-observed.
		s := violation.SampleOf(m)
		s.Identification.OperatorReg = w.publicPart(s.Identification.OperatorReg)
		s.Identification.RegisteredOperatorReg = w.publicPart(s.Identification.RegisteredOperatorReg)
		w.excerpts.Add(tr.ID, tr.CapturedAtS, s)
	}
	wallS := w.wallS()
	if !m.Backlog {
		w.excerpts.SetLast(tr.ID, tr, wallS)
	}
	w.Counters.Inc(CounterTrackObserved)
	w.handle(w.mon.Observe(tr, wallS))
	if !m.Backlog {
		w.wantIntents(m, t.CapturedAt)
	}
	return true
}

// Tick runs once a second: a rebuild if the zones or the policy changed,
// the monitor's ageing (the end of a condition can be silence, T-10),
// the outbox, the republication of every active violation (C-08) and
// the counters.
//
// The publishing is bounded by TickBudget: the outbox goes first and
// stops at its first failure; the republication runs only if the outbox
// is empty (a bus that just failed is not asked again N times) and stops
// at its first failure or when the budget is spent, counting the rest
// deferred.
func (w *Worker) Tick(ctx context.Context) {
	w.maybeRebuild()
	wallS := w.wallS()
	w.handle(w.mon.Tick(wallS))
	w.judgeNoAuth(wallS)
	w.gateHeight()
	bctx, cancel := context.WithTimeout(ctx, w.tickBudget())
	w.flush(bctx)
	w.republish(bctx)
	w.republishNoAuth(bctx)
	cancel()
	w.fold()
	w.updateStats()
}

// SwitchSources hands the source-control state to the monitor: the
// aircraft of a source switched off are dropped and their violations
// cleared source_disabled at once (B-11, SC-08).
func (w *Worker) SwitchSources(ctx context.Context) {
	st, ok := w.in.Sources()
	if !ok {
		return
	}
	w.Counters.Inc(CounterSourceSwitches)
	w.handle(w.mon.SwitchSource(st, w.wallS()))
	w.flush(ctx)
	w.updateStats()
}

// maybeRebuild builds a new monitor when the zone set or the policy
// changed (INV-03, Z-12): uspace-core's Monitor takes its zones and
// thresholds at construction. The source-control state is applied, and
// every aircraft's last live sample is observed again at the wall time
// it was first observed (never now: a quiet aircraft's sample would be
// refused as late and its violation taken for reconfigured), then the
// new monitor is ticked to now, so that a condition still true carries
// its violation on (same violation_id, updated), an aircraft gone quiet
// past stale_after_s is cleared stale, and one the new configuration
// does not raise again is cleared as reconfigured, never left open and
// never called resolved. An open violation whose aircraft the excerpt
// store no longer holds (evicted) has nothing to be judged again on: it
// is cleared stale.
func (w *Worker) maybeRebuild() {
	zs := w.in.Zones()
	p, have := w.in.Policy()
	t, version := policy.Defaults(), int64(0)
	if have {
		t, version = p.Thresholds, p.Version
	}
	if w.mon != nil && zs.Generation == w.zones.Generation && version == w.policyVer {
		return
	}
	first := w.mon == nil
	w.fold()
	w.mon = alerting.NewMonitor(ConfigFor(zs.Zones, t, w.set.MaxAircraft))
	w.monSnap = nil
	w.zones, w.policyVer = zs, version
	if v, err := regnum.NewValidator(t.RegistrationNumberPattern); err == nil {
		w.regnum = v
	} else {
		// The policy validates its pattern; a fault here keeps the default
		// shape rather than the whole number.
		w.regnum, _ = regnum.NewValidator("")
		w.errorf("detect_regnum_pattern", "registration_number_pattern does not compile: operator numbers are cut under the default pattern",
			slog.String("error", err.Error()), slog.Int64("policy_version", version))
	}
	w.zoneByKey = make(map[string]*zones.Zone, len(zs.Zones))
	for _, z := range zs.Zones {
		if z == nil {
			continue
		}
		k := z.Country + "\x00" + z.Identifier
		if _, dup := w.zoneByKey[k]; !dup {
			w.zoneByKey[k] = z
		}
	}
	w.thresholds = t
	if t.HeightLimitInUspace == policy.HeightSkipWhenAuthorised && w.in.Authorisations() == nil {
		// Lifting the limit for an authorised flight needs the
		// operational intents (WP-26); without a DSS it is judged
		// everywhere.
		w.warn("detect_height_in_uspace", "height_limit_in_uspace skip_when_authorised has no effect without a DSS: the height limit is evaluated everywhere",
			slog.Int64("policy_version", version))
	}
	wallS := w.wallS()
	if st, ok := w.in.Sources(); ok {
		w.mon.SwitchSource(st, wallS)
	}
	if first {
		return
	}
	w.Counters.Inc(CounterMonitorRebuilt)
	w.logger.Info("monitor rebuilt for a new zone set or policy", slog.Int("zones", len(zs.Zones)),
		slog.Int64("policy_version", version), slog.Int("open_violations", len(w.open)))
	clear(w.uspace)
	clear(w.heldHeight)
	last := w.excerpts.Last()
	slices.SortFunc(last, func(a, b Observed) int {
		switch {
		case a.WallS != b.WallS:
			return cmpFloat(a.WallS, b.WallS)
		case a.Track.CapturedAtS != b.Track.CapturedAtS:
			return cmpFloat(a.Track.CapturedAtS, b.Track.CapturedAtS)
		}
		return strings.Compare(a.Track.ID, b.Track.ID)
	})
	w.rebuilding = map[string]bool{}
	for i := range last {
		w.handle(w.mon.Observe(last[i].Track, min(last[i].WallS, wallS)))
	}
	w.handle(w.mon.Tick(wallS))
	carried := w.rebuilding
	w.rebuilding = nil
	keys := slices.Sorted(maps.Keys(w.open))
	for _, key := range keys {
		ov := w.open[key]
		if carried[key] {
			continue
		}
		if _, held := w.excerpts.LastOf(ov.body.TrackRef); !held {
			w.closeViolation(ov, string(alerting.ClearStale), wallS, ov.body.Detail, nil)
			delete(w.open, key)
			continue
		}
		w.closeViolation(ov, violation.ClearReasonReconfigured, wallS, ov.body.Detail, nil)
		delete(w.open, key)
		w.Counters.Inc(CounterClearedReconfigured)
	}
	w.afterRebuildNoAuth(wallS)
}

func cmpFloat(a, b float64) int {
	if a < b {
		return -1
	}
	return 1
}

// fold adds what the monitor counted since the last fold to
// MonitorCounters.
func (w *Worker) fold() {
	if w.mon == nil {
		return
	}
	snap := w.mon.Counters().Snapshot()
	for name, v := range snap {
		if d := v - w.monSnap[name]; d > 0 {
			w.MonitorCounters.Add(name, d)
		}
	}
	w.monSnap = snap
}

// handle publishes what one monitor call raised and cleared.
func (w *Worker) handle(ev alerting.Events) {
	for i := range ev.Raised {
		w.raised(&ev.Raised[i])
	}
	for i := range ev.Cleared {
		w.cleared(&ev.Cleared[i])
	}
	for _, r := range ev.Refused {
		w.Counters.Add(CounterAircraftRefused, 1+r.Suppressed)
		w.errorf("detect_aircraft_refused", "aircraft refused by the monitor's capacity: it goes unjudged",
			slog.String("drone_id", r.ID), slog.String("source", r.Source), slog.String("station_id", r.Station),
			slog.String("reason", string(r.Reason)), slog.Uint64("suppressed", r.Suppressed),
			slog.Int("source_alert_holders", r.SourceAlertHolders))
	}
}

// parseKey splits an alert key into its kind and its parts, undoing
// uspace-core's escaping of ':' and '%' (alerting.Alert.Key).
func parseKey(key string) (kind string, parts []string) {
	fields := strings.Split(key, ":")
	unescape := strings.NewReplacer("%3A", ":", "%25", "%")
	for i := range fields {
		fields[i] = unescape.Replace(fields[i])
	}
	return fields[0], fields[1:]
}

// zoneOf is the zone a zone or identification key names.
func (w *Worker) zoneOf(parts []string) zoneRef {
	if len(parts) < 3 {
		return zoneRef{}
	}
	ref := zoneRef{country: parts[0], id: parts[1]}
	ref.zone = w.zoneByKey[ref.country+"\x00"+ref.id]
	if ref.zone == nil {
		// A duplicate key gets "#<i>" appended by the monitor.
		if i := strings.LastIndexByte(ref.id, '#'); i > 0 {
			ref.zone = w.zoneByKey[ref.country+"\x00"+ref.id[:i]]
		}
	}
	return ref
}

// kindOf maps an alert onto a violation kind (plan D5); ok is false for
// an alert that is not a violation (a conflict, presence in U-space).
func (w *Worker) kindOf(a *alerting.Alert) (violation.Kind, zoneRef, bool) {
	kind, parts := parseKey(a.Key)
	switch kind {
	case alerting.KindConflict:
		w.Counters.Inc(CounterConflictIgnored)
		return "", zoneRef{}, false
	case alerting.KindHeight:
		return violation.KindHeight120m, zoneRef{}, true
	case alerting.KindIdentificationMismatch:
		return violation.KindIdentificationMismatch, zoneRef{}, true
	case alerting.KindIdentification:
		return violation.KindUnregistered, w.zoneOf(parts), true
	case alerting.KindZone:
		ref := w.zoneOf(parts)
		if ref.zone != nil && ref.zone.Type == core.ZoneUSpace {
			return "", ref, false
		}
		return violation.KindZoneIncursion, ref, true
	}
	w.Counters.Inc(CounterAlertKindUnknown)
	w.errorf("detect_alert_kind_unknown", "alert of a kind this detector does not map: not published",
		slog.String("kind", a.Kind), slog.String("alert_key", a.Key))
	return "", zoneRef{}, false
}

// aircraftOf is the one aircraft of a violation's alert.
func aircraftOf(a *alerting.Alert) string {
	if len(a.Aircraft) == 0 {
		return ""
	}
	return a.Aircraft[0]
}

func stampS(s float64) string {
	sec, frac := math.Modf(s)
	return bus.Stamp(time.Unix(int64(sec), int64(math.Round(frac*1e9))).UTC())
}

func strp(s string) *string { return &s }

// noteUSpace reports whether a is presence in a U-space airspace, and
// keeps the aircraft's in_uspace state with it; a raise opens the
// aircraft's no_authorisation case for that airspace (WP-26).
func (w *Worker) noteUSpace(a *alerting.Alert, raised bool) bool {
	kind, parts := parseKey(a.Key)
	if kind != alerting.KindZone {
		return false
	}
	ref := w.zoneOf(parts)
	if ref.zone == nil || ref.zone.Type != core.ZoneUSpace {
		return false
	}
	id := aircraftOf(a)
	if raised {
		if w.uspace[id] == nil {
			w.uspace[id] = map[string]struct{}{}
		}
		w.uspace[id][a.Key] = struct{}{}
		w.Counters.Inc(CounterUSpacePresence)
		w.openCase(a.Key, id, ref)
	} else if keys := w.uspace[id]; keys != nil {
		delete(keys, a.Key)
		if len(keys) == 0 {
			delete(w.uspace, id)
		}
	}
	return true
}

// noteUSpaceCleared is noteUSpace for a clear: the aircraft left the
// U-space airspace (resolved, after the monitor's hysteresis), went
// stale, landed or its source was switched off, and its no_authorisation
// for that airspace clears with the same reason.
func (w *Worker) noteUSpaceCleared(c *alerting.Cleared) bool {
	if !w.noteUSpace(&c.Alert, false) {
		return false
	}
	atS := w.wallS()
	if c.Reason == alerting.ClearResolved && c.ShownFalse {
		atS = c.LastFalseS
	}
	w.closeCase(c.Key, string(c.Reason), atS)
	return true
}

// raised publishes a raise: a new violation, or an update of the open
// one (a severity change, C-07, or a condition carried over a rebuild).
func (w *Worker) raised(a *alerting.Alert) {
	if w.noteUSpace(a, true) {
		return
	}
	kind, ref, ok := w.kindOf(a)
	if !ok {
		return
	}
	id := aircraftOf(a)
	if ov, have := w.open[a.Key]; have {
		if w.rebuilding != nil {
			w.rebuilding[a.Key] = true
		}
		ov.body.Severity = a.Severity
		ov.body.Detail = a.Detail
		ov.body.PolicyVersion = w.policyVer
		ov.body.CapturedAt = stampS(a.LastTrueS)
		ov.body.InUSpace = w.uspace[id] != nil
		updatePeak(&ov.body, a.Detail)
		w.enqueue(ov, violation.StateUpdated, a.LastTrueS)
		w.Counters.Inc(CounterUpdated)
		return
	}
	if kind == violation.KindHeight120m && w.heightLifted(id) {
		// height_limit_in_uspace skip_when_authorised: the authorised
		// volume caps the height of an aircraft matched to an intent
		// inside U-space airspace (spec 01 §7); held, and raised the moment
		// the match is lost while the monitor still holds it (gateHeight).
		w.heldHeight[a.Key] = true
		w.Counters.Inc(CounterHeightLifted)
		return
	}
	b := w.bodyFor(kind, a.Key, id, ref, a.Severity, a.Detail, a.RaisedAtS, a.LastTrueS)
	updatePeak(&b, a.Detail)
	ov := &open{body: b, excerptUpToS: a.LastTrueS - w.set.ExcerptWindowS}
	w.open[a.Key] = ov
	if w.rebuilding != nil {
		w.rebuilding[a.Key] = true
	}
	w.enqueue(ov, violation.StateRaised, a.LastTrueS)
	w.Counters.Inc(CounterRaised)
}

// bodyFor is the body of a new violation of kind on aircraft id: the
// zone it names, the identification, trust, receiver or USSP, cell and
// (for height_120m) DEM of the aircraft's last sample.
func (w *Worker) bodyFor(kind violation.Kind, key, id string, ref zoneRef, sev core.Severity, detail map[string]any, raisedAtS, lastTrueS float64) violation.Body {
	b := violation.Body{
		ViolationID: bus.NewULID(w.now()), Kind: kind, State: violation.StateRaised, Severity: sev, AlertKey: key,
		TrackRef: id, CapturedAt: stampS(lastTrueS), OpenedAt: stampS(raisedAtS), PolicyVersion: w.policyVer,
		Detail: detail, InUSpace: w.uspace[id] != nil, EvidenceRefs: []violation.EvidenceRef{{Type: violation.RefTrack, ID: id}},
	}
	if ref.zone != nil || ref.id != "" {
		b.ZoneID = strp(ref.country + "/" + ref.id)
		if ref.zone != nil {
			b.ZoneType = strp(string(ref.zone.Type))
			feature, _, _ := strings.Cut(ref.zone.Identifier, "/")
			ver := w.zones.Versions[feature]
			if _, published := w.zones.Versions[feature]; published {
				v := int64(ver)
				b.ZoneVersion = &v
			}
		}
		b.EvidenceRefs = append(b.EvidenceRefs, violation.EvidenceRef{Type: violation.RefZone, ID: *b.ZoneID, Version: b.ZoneVersion})
	}
	last, have := w.excerpts.lastSample(id)
	if have {
		ident := last.Identification
		// The sample's operator numbers are already cut to their public
		// part (Observe); cutting again could take a public tail for a
		// secret one.
		b.Serial, b.OperatorReg, b.RegistryUASID = ident.Serial, ident.OperatorReg, ident.RegistryUASID
		b.EvidenceTrust = last.Trust
		ref := violation.RefReceiver
		if last.Source == track.SourceNetworkRID {
			ref = violation.RefUSSP
		}
		b.EvidenceRefs = append(b.EvidenceRefs, violation.EvidenceRef{Type: ref, ID: last.SourceInstance})
		if c5, err := cell.Of(core.LatLon{LatDeg: last.Lat, LonDeg: last.Lng}, cell.Level5); err == nil {
			b.Cell5 = c5.String()
		}
		if kind == violation.KindHeight120m {
			if e := w.in.Elevation(core.LatLon{LatDeg: last.Lat, LonDeg: last.Lng}); e != nil {
				b.TerrainSource = &violation.TerrainSource{Dataset: e.Dataset, SpacingM: e.SpacingM, Attribution: terrain.Attribution}
			}
		}
	} else {
		w.Counters.Inc(CounterEvidenceMissing)
		b.EvidenceTrust = core.TrustBroadcast
	}
	if b.Cell5 == "" {
		// No sample to place it: the cell of no position is the origin
		// cell, so the subject stays valid; evidence_missing says why.
		c5, _ := cell.Of(core.LatLon{}, cell.Level5)
		b.Cell5 = c5.String()
	}
	return b
}

// publicPart is an operator number as it may be kept: its public part
// only, never the secret part a broadcast may carry (G-04, 06 §5).
func (w *Worker) publicPart(num *string) *string {
	if num == nil {
		return nil
	}
	v := w.regnum
	if v == nil {
		v, _ = regnum.NewValidator("")
	}
	return strp(v.PublicPart(*num))
}

// updatePeak keeps the worst height over the ground a height violation
// has shown (03 §1 peak_value).
func updatePeak(b *violation.Body, detail map[string]any) {
	if b.Kind != violation.KindHeight120m {
		return
	}
	h, ok := detail["height_agl_m"].(float64)
	if !ok || !core.IsFinite(h) {
		return
	}
	if b.Peak == nil || h > b.Peak.Value {
		b.Peak = &violation.Peak{Name: "height_agl_m", Value: h}
	}
}

// cleared publishes a clear with its reason and the numbers at clearing
// (C-14).
func (w *Worker) cleared(c *alerting.Cleared) {
	if w.noteUSpaceCleared(c) {
		return
	}
	if w.heldHeight[c.Key] {
		// Lifted for an authorised aircraft and never published.
		delete(w.heldHeight, c.Key)
		return
	}
	kind, _ := parseKey(c.Key)
	if kind == alerting.KindConflict {
		w.Counters.Inc(CounterConflictIgnored)
		return
	}
	ov, have := w.open[c.Key]
	if !have {
		w.Counters.Inc(CounterClearUnmatched)
		w.errorf("detect_clear_unmatched", "a clear with no open violation: not published",
			slog.String("alert_key", c.Key), slog.String("clear_reason", string(c.Reason)))
		return
	}
	atS := w.wallS()
	if c.Reason == alerting.ClearResolved && c.ShownFalse {
		atS = c.LastFalseS
	}
	w.closeViolation(ov, string(c.Reason), atS, c.Detail, c.ClearingDetail)
	delete(w.open, c.Key)
}

func (w *Worker) closeViolation(ov *open, reason string, atS float64, detail, clearing map[string]any) {
	ov.body.State = violation.StateCleared
	ov.body.ClearReason = strp(reason)
	ov.body.ClosedAt = strp(stampS(atS))
	ov.body.CapturedAt = stampS(atS)
	ov.body.Detail = detail
	ov.body.ClearingDetail = clearing
	ov.body.PolicyVersion = w.policyVer
	updatePeak(&ov.body, detail)
	w.enqueue(ov, violation.StateCleared, atS)
	w.Counters.Inc(CounterCleared)
}

// message wraps the body of ov in state for publication, with the
// samples since the last publication up to toS.
func (w *Worker) message(ov *open, state violation.State, toS float64) *violation.Message {
	b := ov.body
	b.State = state
	if b.Detail == nil {
		b.Detail = map[string]any{}
	}
	b.EvidenceRefs = slices.Clone(b.EvidenceRefs)
	b.EvidenceExcerpt = w.excerpts.Window(b.TrackRef, ov.excerptUpToS, toS)
	if toS > ov.excerptUpToS {
		ov.excerptUpToS = toS
	}
	env := bus.SystemEnvelope(violation.Schema, violation.Producer, w.now(), b)
	env.CapturedAt = b.CapturedAt
	return &env
}

// enqueue puts a raise, update or clear in the outbox and tries to
// publish at once when nothing is waiting before it.
func (w *Worker) enqueue(ov *open, state violation.State, toS float64) {
	m := w.message(ov, state, toS)
	if err := violation.Validate(m); err != nil {
		// A mapping fault, never an input: said at error level.
		w.errorf("detect_violation_invalid", "violation message refused by its own schema: not published",
			slog.String("error", err.Error()), slog.String("alert_key", ov.body.AlertKey))
		return
	}
	if over := len(w.outbox) + 1 - w.set.OutboxMax; over > 0 && w.set.OutboxMax > 0 {
		w.outbox = slices.Delete(w.outbox, 0, over)
		w.Counters.Add(CounterOutboxDropped, uint64(over))
		w.errorf("detect_outbox_dropped", "violation outbox full: the oldest raises and clears were dropped",
			slog.Int("dropped", over), slog.Int("outbox_max", w.set.OutboxMax))
	}
	// With raises or clears already waiting the bus is failing: this one
	// waits for the tick too, rather than costing a publish timeout in
	// the track path.
	tryNow := len(w.outbox) == 0
	w.outbox = append(w.outbox, m)
	if tryNow {
		w.flush(context.Background())
	}
}

// flush publishes the outbox in order and stops at the first failure.
func (w *Worker) flush(ctx context.Context) {
	sent := 0
	for _, m := range w.outbox {
		pctx, cancel := context.WithTimeout(ctx, w.publishTimeout())
		err := w.pub.PublishViolation(pctx, m)
		cancel()
		if err != nil {
			w.Counters.Inc(CounterPublishFailed)
			w.warn("detect_publish_failed", "violation not published to ALRT; kept and retried every tick",
				slog.String("error", err.Error()), slog.Int("outbox", len(w.outbox)-sent))
			break
		}
		sent++
	}
	if sent > 0 {
		w.outbox = slices.Delete(w.outbox, 0, sent)
	}
}

func (w *Worker) tickBudget() time.Duration {
	if w.set.TickBudget > 0 {
		return w.set.TickBudget
	}
	return 500 * time.Millisecond
}

func (w *Worker) publishTimeout() time.Duration {
	if w.set.PublishTimeout > 0 {
		return w.set.PublishTimeout
	}
	return 2 * time.Second
}

// republish publishes every active violation with its current numbers
// and the samples since its last publication (C-08). It runs within
// ctx (the tick's budget): with raises or clears still in the outbox
// the bus is failing and nothing is republished; the first failure, or
// the budget spent, stops the round. What was not republished is counted
// deferred, and the next tick starts with it (republishFrom), so no
// violation is starved. Nothing is lost: the next successful round
// carries the current numbers and every sample since the last one.
func (w *Worker) republish(ctx context.Context) {
	var active []alerting.Alert
	for _, a := range w.mon.Active() {
		if _, have := w.open[a.Key]; have {
			active = append(active, a)
		}
	}
	n := len(active)
	if n == 0 {
		return
	}
	if len(w.outbox) > 0 {
		w.Counters.Add(CounterRepublishDeferred, uint64(n))
		return
	}
	start := w.republishFrom % n
	for i := range n {
		a := &active[(start+i)%n]
		if ctx.Err() != nil {
			w.deferRepublish(n-i, (start+i)%n)
			return
		}
		ov := w.open[a.Key]
		ov.body.Severity = a.Severity
		ov.body.Detail = a.Detail
		ov.body.CapturedAt = stampS(a.LastTrueS)
		ov.body.InUSpace = w.uspace[aircraftOf(a)] != nil
		updatePeak(&ov.body, a.Detail)
		upTo := ov.excerptUpToS
		m := w.message(ov, violation.StateUpdated, math.Inf(1))
		pctx, cancel := context.WithTimeout(ctx, w.publishTimeout())
		err := w.pub.PublishViolation(pctx, m)
		cancel()
		if err != nil {
			ov.excerptUpToS = upTo
			w.Counters.Inc(CounterRepublishFailed)
			w.warn("detect_republish_failed", "active violations not republished to ALRT; retried next tick",
				slog.String("error", err.Error()), slog.Int("active", n))
			w.deferRepublish(n-i-1, (start+i)%n)
			return
		}
		w.Counters.Inc(CounterRepublished)
	}
	w.republishFrom = start
}

// deferRepublish counts n violations left for the next tick, which
// starts at index from.
func (w *Worker) deferRepublish(n, from int) {
	if n > 0 {
		w.Counters.Add(CounterRepublishDeferred, uint64(n))
	}
	w.republishFrom = from
}

func (w *Worker) updateStats() {
	s := workerStats{tracked: w.mon.Tracked(), active: len(w.open) + w.openNoAuth(), outbox: len(w.outbox),
		capacityExceeded: w.mon.CapacityExceeded(), policyVersion: w.policyVer, noAuth: w.noAuthStats()}
	w.statMu.Lock()
	w.stats = s
	w.statMu.Unlock()
}

// StatusAttrs are the worker's status-line attributes; safe from any
// goroutine.
func (w *Worker) StatusAttrs() []slog.Attr {
	w.statMu.Lock()
	s := w.stats
	w.statMu.Unlock()
	return []slog.Attr{slog.Group("detect_"+strings.ReplaceAll(w.Name, ":", "_"),
		slog.Int("tracked", s.tracked), slog.Int("open_violations", s.active), slog.Int("outbox", s.outbox),
		slog.Bool("capacity_exceeded", s.capacityExceeded), slog.Int64("policy_version", s.policyVersion),
		slog.Int("uspace_aircraft", s.noAuth.cases), slog.Int("no_authorisation_open", s.noAuth.open),
		slog.Int("no_authorisation_unknown", s.noAuth.unknown), slog.Int("no_authorisation_matched", s.noAuth.matched),
		slog.Int("no_authorisation_grace_running", s.noAuth.grace), slog.Int("height_lifted", s.noAuth.heightLifted))}
}

// CapacityExceeded reports the monitor's state as of the last tick.
func (w *Worker) CapacityExceeded() bool {
	w.statMu.Lock()
	defer w.statMu.Unlock()
	return w.stats.capacityExceeded
}
