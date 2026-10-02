package detectsvc

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
	"github.com/rootxkit/uspace-authority/internal/violation"
	"github.com/rootxkit/uspace-authority/internal/zonesvc"
)

// LazyReader opens the telemetry database read-only on first use and
// again after an open failed, so detect starts with the database down
// and says the projections are not loaded until it can read (B-08,
// SC-22). It serves both projections.
type LazyReader struct {
	Opts store.PoolOptions

	mu sync.Mutex
	r  *ts.Reader
}

func (l *LazyReader) get(ctx context.Context) (*ts.Reader, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.r == nil {
		r, err := ts.OpenReader(ctx, l.Opts)
		if err != nil {
			return nil, err
		}
		l.r = r
	}
	return l.r, nil
}

// LoadZones implements zonesvc.ProjectionSource.
func (l *LazyReader) LoadZones(ctx context.Context) ([]zonesvc.ProjectedRow, error) {
	r, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return zonesvc.TSSource{R: r}.LoadZones(ctx)
}

// LoadRestrictions implements RestrictionSource.
func (l *LazyReader) LoadRestrictions(ctx context.Context) ([]reader.ProjRestriction, error) {
	r, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return TSRestrictions{R: r}.LoadRestrictions(ctx)
}

// Close closes the pool if one was opened.
func (l *LazyReader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.r != nil {
		l.r.Close()
		l.r = nil
	}
}

// Shared is every worker's Inputs: the zones projection, the dynamic
// restrictions, the policy, the source-control state and the ground.
// Each part may be nil (a test); a nil part answers as not loaded.
type Shared struct {
	ZoneReader   *zonesvc.ProjectionReader
	Restrictions *RestrictionReader
	PolicyF      *policy.Follower
	SourcesF     *sources.Follower
	Ground       *ground.Service

	mu  sync.Mutex
	set ZoneSet
}

var _ Inputs = (*Shared)(nil)

// Zones is the published zones and the restrictions in force, rebuilt
// only when either changes.
func (s *Shared) Zones() ZoneSet {
	var zs zonesvc.ZoneSet
	if s.ZoneReader != nil {
		zs = s.ZoneReader.ZoneSet()
	}
	var rz []*zones.Zone
	var rgen uint64
	var rloaded bool
	if s.Restrictions != nil {
		rz, rgen, rloaded, _ = s.Restrictions.Set()
	}
	gen := [2]uint64{zs.Generation, rgen}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set.Generation == gen && s.set.ZonesLoaded == zs.Loaded && s.set.RestrictionsLoaded == rloaded {
		return s.set
	}
	all := make([]*zones.Zone, 0, len(zs.Zones)+len(rz))
	all = append(all, zs.Zones...)
	all = append(all, rz...)
	s.set = ZoneSet{Zones: all, Versions: zs.Versions, Generation: gen, ZonesLoaded: zs.Loaded, RestrictionsLoaded: rloaded}
	return s.set
}

// Policy is the policy held, if any.
func (s *Shared) Policy() (policy.Policy, bool) {
	if s.PolicyF == nil {
		return policy.Policy{}, false
	}
	return s.PolicyF.Current()
}

// Sources is the source-control state held, if any.
func (s *Shared) Sources() (coresources.State, bool) {
	if s.SourcesF == nil {
		return coresources.State{}, false
	}
	return s.SourcesF.State()
}

// Env is the ground and the geoid at p; without a ground service,
// nothing is configured (never a ground of 0 m, D-04).
func (s *Shared) Env(p core.LatLon) zones.Env {
	if s.Ground == nil {
		return zones.Env{Ground: zones.GroundNotConfigured}
	}
	return s.Ground.Env(p)
}

// Elevation is the DEM sample at p with its dataset, or nil.
func (s *Shared) Elevation(p core.LatLon) *terrain.Elevation {
	if s.Ground == nil {
		return nil
	}
	return s.Ground.Elevation(p)
}

// Problems lists everything that keeps a violation from being judged,
// each naming what is not judged (Z-09, SC-13, SC-22, E-02): a
// projection never read, a zone or restriction in force that could not
// be built, no terrain (the height limit over the ground, height_120m,
// is then evaluated for no aircraft, D-04), and every PROHIBITED or
// REQ_AUTHORISATION zone with a limit that needs terrain or the geoid
// this process does not have. Empty when everything in force is judged.
func (s *Shared) Problems() []string {
	var zoneNJ, restrNJ []string
	if s.ZoneReader != nil {
		zoneNJ = s.ZoneReader.NotJudged()
	}
	if s.Restrictions != nil {
		_, _, _, restrNJ = s.Restrictions.Set()
	}
	noTerrain, noGeoid := true, true
	if s.Ground != nil {
		noTerrain, noGeoid = s.Ground.Ground() == nil, s.Ground.Undulator() == nil
	}
	return problems(s.Zones(), zoneNJ, restrNJ, noTerrain, noGeoid)
}

// problems is Problems over its inputs.
func problems(zs ZoneSet, zoneNotJudged, restrictionsNotJudged []string, noTerrain, noGeoid bool) []string {
	var out []string
	if !zs.ZonesLoaded {
		out = append(out, "zones projection not loaded: zone incursions and unregistered aircraft in zones are not judged")
	}
	if !zs.RestrictionsLoaded {
		out = append(out, "restrictions projection not loaded: dynamic restrictions are not judged")
	}
	if noTerrain {
		out = append(out, "terrain not configured: the height limit over the ground (height_120m) is not evaluated for any aircraft")
	}
	for _, n := range zoneNotJudged {
		out = append(out, "zone not judged: "+n)
	}
	for _, n := range restrictionsNotJudged {
		out = append(out, "restriction not judged: "+n)
	}
	for _, z := range zs.Zones {
		if z == nil || !z.Type.IncidentZone() {
			continue
		}
		var missing []string
		if noTerrain && z.NeedsTerrain() {
			missing = append(missing, "terrain")
		}
		if noGeoid && z.NeedsGeoid() {
			missing = append(missing, "geoid")
		}
		if len(missing) > 0 {
			out = append(out, fmt.Sprintf("%s zone %s/%s needs %s, not configured: it warns limit_not_judged instead of its own severity",
				z.Type, z.Country, z.Identifier, strings.Join(missing, " and ")))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Level is error while anything is not judged (Problems), including the
// height limit without terrain, and info otherwise: every status line
// says it (Z-09, SC-13, E-02).
func (s *Shared) Level() slog.Level { return levelOf(s.Problems()) }

// levelOf is the status level of problems.
func levelOf(problems []string) slog.Level {
	if len(problems) > 0 {
		return slog.LevelError
	}
	return slog.LevelInfo
}

// StatusAttrs are the shared inputs' status-line attributes: what is not
// judged, and the policy judged with (0 and "defaults" before one).
func (s *Shared) StatusAttrs() []slog.Attr {
	out := []slog.Attr{slog.Any("not_judged", s.Problems())}
	if _, ok := s.Policy(); !ok {
		out = append(out, slog.String("detect_policy", "defaults: no policy received yet (policy_version 0)"))
	}
	return out
}

// JSPublisher writes violations to the ALRT stream; the message id is
// msg_id, so a retried write is stored once.
type JSPublisher struct{ JS jetstream.JetStream }

// PublishViolation implements Publisher.
func (p JSPublisher) PublishViolation(ctx context.Context, m *violation.Message) error {
	subject, err := violation.Subject(&m.Body)
	if err != nil {
		return err
	}
	_, err = bus.PublishJS(ctx, p.JS, subject, *m)
	return err
}

// ConsumerSettings bound a worker's consumer of trk.v1.
type ConsumerSettings struct {
	WorkerID      string
	MaxAckPending int
	AckWait       time.Duration
	FetchMax      int
	Timeout       time.Duration
	Retry         time.Duration
}

// FilterOf is the trk.v1 filter of a worker: trk.v1.<cell3>.> or every
// track for CELLS=all.
func FilterOf(c3 *cell.ID) (string, error) {
	if c3 == nil {
		return bus.SubjectTrkAll, nil
	}
	tok, err := bus.Token("cell3", cell.Token(*c3))
	if err != nil {
		return "", err
	}
	return "trk.v1." + tok + ".>", nil
}

// durableOf names the durable of a worker for a filter: one per worker
// and cell, so two workers never split one cell's tracks between them.
func durableOf(workerID string, c3 *cell.ID) string {
	name := "all"
	if c3 != nil {
		name = cell.Token(*c3)
	}
	clean := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			return r
		}
		return '_'
	}, workerID)
	return "detect_" + clean + "_" + name
}

// Pull feeds out with the worker's tracks until ctx ends: it opens the
// TRK and ALRT streams (creating what is missing), the durable pull
// consumer (explicit ack, bounded pending, new messages only at its
// creation: history is never alerted, T-04), and re-establishes each
// after a failure, saying so at a bounded rate (B-08).
func Pull(ctx context.Context, bp *bus.Process, c3 *cell.ID, s ConsumerSettings, out chan<- jetstream.Msg, lim *logging.Limiter) {
	filter, err := FilterOf(c3)
	if err != nil {
		return
	}
	durable := durableOf(s.WorkerID, c3)
	retry := s.Retry
	if retry <= 0 {
		retry = time.Second
	}
	warn := func(msg string, err error) {
		if lim != nil && ctx.Err() == nil {
			lim.Limited("detect_pull_"+durable).Warn(msg, slog.String("durable", durable), slog.String("error", err.Error()))
		}
	}
	wait := func() {
		select {
		case <-ctx.Done():
		case <-time.After(retry):
		}
	}
	for ctx.Err() == nil {
		cctx, cancel := context.WithTimeout(ctx, s.Timeout)
		trkCfg, _ := bp.Topology.Stream(bus.StreamTRK)
		alrtCfg, _ := bp.Topology.Stream(bus.StreamALRT)
		var stream jetstream.Stream
		stream, err = bus.OpenStream(cctx, bp.JS, trkCfg)
		if err == nil {
			_, err = bus.OpenStream(cctx, bp.JS, alrtCfg)
		}
		var cons jetstream.Consumer
		if err == nil {
			cons, err = bus.PullConsumer(cctx, stream, bus.PullSpec{
				Durable: durable, FilterSubject: filter, MaxAckPending: s.MaxAckPending, AckWait: s.AckWait,
				DeliverPolicy: jetstream.DeliverNewPolicy,
			})
		}
		cancel()
		if err != nil {
			warn("track consumer not available; violations are not judged for these cells until it is", err)
			wait()
			continue
		}
		it, err := cons.Messages(jetstream.PullMaxMessages(max(s.FetchMax, 1)))
		if err != nil {
			warn("track consumer not readable; retrying", err)
			wait()
			continue
		}
		stop := context.AfterFunc(ctx, it.Stop)
		for {
			m, err := it.Next()
			if err != nil {
				if ctx.Err() == nil {
					warn("track consumer interrupted; re-establishing", err)
				}
				break
			}
			select {
			case out <- m:
			case <-ctx.Done():
			}
		}
		stop()
		it.Stop()
		wait()
	}
}

// RunWorker is a worker's goroutine: every message from msgs, a source-control
// change from switches, and a tick every second, until ctx ends; the
// outbox gets a last bounded flush.
func RunWorker(ctx context.Context, w *Worker, msgs <-chan jetstream.Msg, switches <-chan struct{}, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.flush(context.WithoutCancel(ctx))
			return
		case m := <-msgs:
			if w.HandleData(m.Data()) {
				_ = m.Ack()
			} else {
				_ = m.Term()
			}
		case <-switches:
			w.SwitchSources(ctx)
		case <-t.C:
			w.Tick(ctx)
		}
	}
}

// FanOut hands every source-control change of f to each channel (each
// of capacity one: a signal not yet read stands for every later one),
// until ctx ends.
func FanOut(ctx context.Context, f *sources.Follower, outs []chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.Changes():
			for _, ch := range outs {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}
}
