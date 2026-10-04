package detectsvc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/intents"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/tokens"
	"github.com/rootxkit/uspace-authority/internal/zonesvc"
)

// IntentsBoard is the no_authorisation detector's board over the DSS
// of c, or nil (said at error level) without a DSS or a client secret.
func IntentsBoard(rt *proc.Runtime, c *config.DetectIntents, zs func() []*zones.Zone) (*intents.Board, error) {
	if c.DSSBaseURL == "" || c.ClientSecretFile == "" {
		rt.Logger.Error("no DSS for the detector: no_authorisation is not judged and height_limit_in_uspace skip_when_authorised has no effect while a U-space airspace is in force",
			slog.Bool("dss_base_url_set", c.DSSBaseURL != ""), slog.Bool("client_secret_set", c.ClientSecretFile != ""))
		return nil, nil
	}
	raw, err := os.ReadFile(c.ClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("DETECT_CLIENT_SECRET_FILE: cannot be read: %w", err)
	}
	tc, err := tokens.NewClient(tokens.ClientConfig{TokenURL: c.TokenURL(), ClientID: c.ClientID, ClientSecret: strings.TrimSpace(string(raw))})
	if err != nil {
		return nil, err
	}
	rt.AddCounters("detect_token_client", tc.Counters())
	return NewIntentsBoard(rt, c, &intents.Client{Tokens: tc, DSS: c.DSSBaseURL, MaxBody: int64(c.IntentMaxBodyBytes), MaxRefs: c.IntentMaxRefs}, zs), nil
}

// NewIntentsBoard is the board of c over dss, its counters on the status
// line.
func NewIntentsBoard(rt *proc.Runtime, c *config.DetectIntents, dss intents.DSS, zs func() []*zones.Zone) *intents.Board {
	s := intents.DefaultSettings()
	s.Requery, s.Horizon = time.Duration(c.IntentRequeryS)*time.Second, time.Duration(c.IntentHorizonS)*time.Second
	s.Recheck, s.ChecksPerStep = time.Duration(c.IntentRecheckMS)*time.Millisecond, c.IntentChecksPerS
	s.CheckRadiusM, s.VerticalMarginM = c.IntentRadiusM, c.IntentVMarginM
	s.OutcomeMaxAge = time.Duration(c.IntentOutcomeMaxS) * time.Second
	s.MaxTracks, s.MaxZones, s.MaxCached = c.IntentMaxAircraft, c.IntentMaxZones, c.IntentMaxCached
	s.Timeout = time.Duration(c.IntentTimeoutMS) * time.Millisecond
	counters := &core.Counters{}
	rt.AddCounters("intents", counters)
	b := intents.NewBoard(s, dss, zs, counters)
	b.Logger, b.Limiter = rt.Logger, rt.Limiter
	rt.Logger.Info("no_authorisation detector reads the DSS (utm.conformance_monitoring_sa, Q-A5)",
		slog.Duration("requery", s.Requery), slog.Duration("horizon", s.Horizon), slog.Int("checks_per_s", s.ChecksPerStep),
		slog.Float64("check_radius_m", s.CheckRadiusM), slog.Int("max_aircraft", s.MaxTracks), slog.Int("max_cached", s.MaxCached))
	return b
}

// Run is detect's body once the bus, the ground and the claim are in
// hand (cmd/detect): it follows the source switches, the zones and
// restrictions projections and the active policy, starts one worker per
// claimed cell3 (one for CELLS=all), and blocks until ctx ends.
func Run(ctx context.Context, rt *proc.Runtime, cfg *config.Detect, bp *bus.Process, g *ground.Service, claim cell.Claim) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	// Source control: a switch clears the violations of the
	// aircraft of a source switched off at once (B-11, SC-08).
	srcF, followSources := sources.Follow(ctx, rt, bp, cfg.Bus)
	wg.Go(func() { followSources(ctx) })

	// The projections, read-only from the telemetry database, opened
	// lazily so detect starts with the database down (B-08, SC-22).
	tsReader := &LazyReader{Opts: store.PoolOptions{
		URL: cfg.TSURL, MaxConns: cfg.TSMaxConns, StatementTimeout: 10 * time.Second, ApplicationName: "uspace-authority-detect",
	}}
	defer tsReader.Close()
	zoneCounters, restrCounters := &core.Counters{}, &core.Counters{}
	rt.AddCounters("zones_projection", zoneCounters)
	rt.AddCounters("restrictions_projection", restrCounters)
	zr := &zonesvc.ProjectionReader{Source: tsReader, Daylight: ground.Daylight(), Counters: zoneCounters, Logger: rt.Logger}
	rr := &RestrictionReader{Source: tsReader, Daylight: ground.Daylight(), Counters: restrCounters}
	rt.AddStatus(zr.StatusAttrs)
	rt.AddStatus(rr.StatusAttrs)
	wg.Go(func() { zr.Run(ctx, time.Duration(cfg.ZonesRefreshS)*time.Second) })
	wg.Go(func() { zonesvc.Follow(ctx, bp.NC, zr, rt.Logger) })
	wg.Go(func() { rr.Run(ctx, time.Duration(cfg.RestrictionsRefresh)*time.Second, rt.Logger) })
	wg.Go(func() { FollowRestrictions(ctx, bp.NC, rr, rt.Logger) })

	// The active policy from KV policy (INV-03); until one arrives the
	// documented defaults are judged with, as policy_version 0, and
	// every status line says so.
	policyCounters := &core.Counters{}
	rt.AddCounters("policy", policyCounters)
	pf := policy.NewFollower(policyCounters)
	rt.AddStatus(pf.StatusAttrs)
	kv := policy.KVOf(bp, time.Duration(cfg.NATSTimeoutMS)*time.Millisecond, "", policyCounters)
	wg.Go(func() { kv.Follow(ctx, pf, time.Duration(cfg.PolicyRereadS)*time.Second, rt.Logger) })

	shared := &Shared{ZoneReader: zr, Restrictions: rr, PolicyF: pf, SourcesF: srcF, Ground: g}
	// no_authorisation (WP-26): the operational intents of every U-space
	// airspace in force, read from the DSS; without one the detector is
	// unconfigured and says so while an airspace is in force (E-02).
	board, err := IntentsBoard(rt, &cfg.DetectIntents, func() []*zones.Zone { return shared.Zones().Zones })
	if err != nil {
		return err
	}
	if board != nil {
		shared.Intents = board
		rt.AddStatus(board.StatusAttrs)
		wg.Go(func() { board.Run(ctx, time.Second) })
	}
	rt.AddStatus(shared.StatusAttrs)
	rt.AddStatusLevel(shared.Level)

	set := Settings{
		MaxAircraft: cfg.MaxAircraft, ExcerptWindowS: float64(cfg.ExcerptWindowS), ExcerptMaxSamples: cfg.ExcerptMaxSamples,
		OutboxMax: cfg.OutboxMax, PublishTimeout: time.Duration(cfg.PublishTimeoutMS) * time.Millisecond,
		TickBudget: time.Duration(cfg.TickBudgetMS) * time.Millisecond,
	}
	cs := ConsumerSettings{
		WorkerID: cfg.WorkerID, MaxAckPending: cfg.MaxAckPending, AckWait: time.Duration(cfg.AckWaitS) * time.Second,
		FetchMax: cfg.FetchMax, Timeout: time.Duration(cfg.NATSTimeoutMS) * time.Millisecond,
	}
	pub := JSPublisher{JS: bp.JS}
	var targets []*cell.ID
	if claim.All {
		targets = []*cell.ID{nil}
	} else {
		for i := range claim.Cells {
			targets = append(targets, &claim.Cells[i])
		}
	}
	switches := make([]chan struct{}, 0, len(targets))
	for _, c3 := range targets {
		name := "all"
		if c3 != nil {
			name = c3.String()
		}
		w := NewWorker(name, shared, set, pub, rt.Logger, rt.Limiter)
		rt.AddCounters("detect/"+name, w.Counters)
		rt.AddCounters("monitor/"+name, w.MonitorCounters)
		rt.AddStatus(w.StatusAttrs)
		sw := make(chan struct{}, 1)
		switches = append(switches, sw)
		msgs := make(chan jetstream.Msg, cfg.FetchMax)
		wg.Go(func() { Pull(ctx, bp, c3, cs, msgs, rt.Limiter) })
		wg.Go(func() { RunWorker(ctx, w, msgs, sw, time.Second) })
	}
	wg.Go(func() { FanOut(ctx, srcF, switches) })

	// Z-09, SC-13: what cannot be judged is said at error level once
	// the first projection reads are in, and on every status line
	// while it lasts (Shared.Level).
	wg.Go(func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		if p := shared.Problems(); len(p) > 0 {
			rt.Logger.Error("violations not judged in full", slog.Any("not_judged", p))
		} else {
			rt.Logger.Info("every zone and restriction in force is judged")
		}
	})
	rt.Logger.Info("detecting", slog.Int("workers", len(targets)))
	<-ctx.Done()
	return nil
}
