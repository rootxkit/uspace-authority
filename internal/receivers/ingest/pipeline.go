package ingest

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/rid"
	"github.com/rootxkit/uspace-core/timeplace"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// PipelineSettings are the ridpipe settings of the configuration.
func PipelineSettings(t config.RIDPipelineTuning) ridpipe.Settings {
	s := ridpipe.DefaultSettings()
	s.Tracker = rid.Settings{
		IdentityTTLS: t.IdentityTTLS, MaxGapS: t.MaxGapS, IdentifyWithinS: t.IdentifyWithinS, MaxTransmitters: t.MaxTransmitters,
	}
	s.Broadcast = timeplace.BroadcastPolicy{ToleranceS: t.BroadcastToleranceS, MaxLatencyS: t.MaxLatencyS}
	s.Altitude.MinVerticalAccuracy = uint8(t.MinVerticalAccuracy)
	s.Altitude.PressureHoldS = t.PressureHoldS
	s.MaxBatchSpacing = time.Duration(t.MaxBatchSpacingS * float64(time.Second))
	s.MaxTracks = t.MaxTracks
	s.Producer = Producer
	return s
}

// lazyProjection reads the registry projection as authority_ts_reader,
// opening the telemetry database on first use and again after an open
// failed, so rid-ingest starts with the database down and resolves
// registry_unavailable until it can read (B-08, SC-22).
type lazyProjection struct {
	opts store.PoolOptions

	mu sync.Mutex
	r  *ts.Reader
}

// LoadProjection implements registry.ProjectionSource.
func (l *lazyProjection) LoadProjection(ctx context.Context) (registry.Loaded, error) {
	l.mu.Lock()
	if l.r == nil {
		r, err := ts.OpenReader(ctx, l.opts)
		if err != nil {
			l.mu.Unlock()
			return registry.Loaded{}, err
		}
		l.r = r
	}
	r := l.r
	l.mu.Unlock()
	return registry.TSSource{R: r}.LoadProjection(ctx)
}

func (l *lazyProjection) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.r != nil {
		l.r.Close()
	}
}

// startPipeline builds the Remote ID pipeline of the process (WP-8): the
// registry projection reader (re-read every RID_PROJECTION_REFRESH_S and
// on registry.v1.changed), the geoid of o or else GEOID_FILE's (WP-11), the
// trackers' tick, and the status-line attributes. The returned function
// runs the background work until ctx ends.
func startPipeline(rt *proc.Runtime, cfg *config.RIDIngest, bp *bus.Process, o Options) (*ridpipe.Pipeline, func(context.Context)) {
	t := cfg.RIDPipelineTuning
	regCounters := &core.Counters{}
	rt.AddCounters("registry_projection", regCounters)
	src := &lazyProjection{opts: store.PoolOptions{
		URL: cfg.TSURL, MaxConns: 2, StatementTimeout: 10 * time.Second, ApplicationName: "uspace-authority-rid-ingest",
	}}
	reader := &registry.ProjectionReader{Source: src, Counters: regCounters, Logger: rt.Logger}
	rt.AddStatus(reader.StatusAttrs)

	geo := o.Geoid
	if geo == nil {
		geo = loadGeoid(rt, cfg.Geoid)
	}
	counters := &core.Counters{}
	rt.AddCounters("ridpipe", counters)
	s := PipelineSettings(t)
	p := ridpipe.New(s, ridpipe.Deps{
		Registry: reader.Lookup, Geoid: geo, Publisher: bp.NC, Counters: counters, Logger: rt.Logger, Limiter: rt.Limiter,
	})
	live, backlog := p.TrackerCounters()
	rt.AddCounters("rid_tracker", live)
	rt.AddCounters("rid_tracker_backlog", backlog)
	rt.AddStatus(p.StatusAttrs)
	s = p.Settings()
	rt.Logger.Info("Remote ID pipeline thresholds (policy defaults; KV policy is not published to the hot path yet)",
		slog.Float64("identity_ttl_s", s.Tracker.IdentityTTLS), slog.Float64("max_gap_s", s.Tracker.MaxGapS),
		slog.Float64("identify_within_s", s.Tracker.IdentifyWithinS), slog.Int("max_transmitters", s.Tracker.MaxTransmitters),
		slog.Float64("broadcast_tolerance_s", s.Broadcast.ToleranceS), slog.Float64("max_latency_s", s.Broadcast.MaxLatencyS),
		slog.Int("min_vertical_accuracy", int(s.Altitude.MinVerticalAccuracy)), slog.Float64("pressure_hold_s", s.Altitude.PressureHoldS),
		slog.Int("max_tracks", s.MaxTracks))
	if geo == nil {
		// R-07, SC-05 step 3, SC-22: said at start and on every status line.
		rt.Logger.Warn("no geoid configured: Remote ID aircraft have no AMSL altitude and are not judged vertically (R-07)")
	}
	rt.Logger.Warn("registry projection not loaded yet: Remote ID tracks are identified registry_unavailable until it is (SC-22)")

	run := func(ctx context.Context) {
		defer src.close() // after every reader below has stopped
		var wg sync.WaitGroup
		defer wg.Wait()
		wg.Go(func() { p.Run(ctx, time.Duration(t.TickMS)*time.Millisecond) })
		changed := make(chan *nats.Msg, 1)
		if sub, err := bp.NC.ChanSubscribe(bus.SubjectRegistryChanged, changed); err != nil {
			rt.Logger.Warn("registry.v1.changed not followed; the projection is re-read periodically only",
				slog.String("error", err.Error()))
		} else {
			defer func() { _ = sub.Unsubscribe() }()
			wg.Go(func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-changed:
						reader.Notify()
					}
				}
			})
		}
		loaded := false
		wg.Go(func() { reader.Run(ctx, time.Duration(t.ProjectionRefreshS)*time.Second) })
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for !loaded {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if reader.Lookup() != nil {
					loaded = true
					rt.Logger.Info("registry projection loaded: Remote ID tracks are identified against it",
						slog.Int64("registry_version", reader.Version()))
				}
			}
		}
		<-ctx.Done()
	}
	return p, run
}

// loadGeoid reads GEOID_FILE through internal/ground (WP-11). It returns
// a nil interface when the file is not configured or cannot be read, so
// that the pipeline publishes no AMSL altitude (HAE only, R-07) rather
// than a guess; an unreadable grid is said at start with its reason and
// on every status line.
func loadGeoid(rt *proc.Runtime, cfg config.Geoid) geoid.Undulator {
	if cfg.GeoidFile == "" {
		return nil
	}
	g := ground.New(ground.FromGeoidConfig(cfg))
	g.Log(rt.Logger)
	problems := g.Problems()
	rt.AddStatus(func() []slog.Attr {
		if len(problems) != 0 {
			return []slog.Attr{slog.String("geoid_grid", problems[0].State+": "+problems[0].Reason)}
		}
		return []slog.Attr{slog.String("geoid_grid", g.GeoidDescription()), slog.Bool("geoid_mapped", g.GeoidMapped())}
	})
	return g.Undulator()
}
