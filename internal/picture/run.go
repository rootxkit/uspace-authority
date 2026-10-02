package picture

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
)

// busPending bounds what one bus subscription holds for the hub; past
// it NATS drops messages, which are counted (bus_messages_dropped).
const (
	busPendingMsgs  = 100_000
	busPendingBytes = 256 << 20
)

// Options are what Run needs beyond the configuration (tests).
type Options struct {
	// Sessions replaces the session check (nil: APIChecker with the
	// LazyVerifier of this issuer).
	Sessions Checker
	// BusCheckEvery is the bus state poll (default 250 ms).
	BusCheckEvery time.Duration
}

// Run is picture-ws's process body: it follows the switches, the
// adapters' statuses, the policy and the projections, subscribes to
// trk.v1, man.v1 and alrt.v1, reads the active violations back from
// ALRT, and serves /v1/picture/* until ctx ends.
func Run(ctx context.Context, rt *proc.Runtime, cfg *config.PictureWS, o Options) error {
	bp, err := bus.OpenProcess(ctx, cfg.NATSURL, cfg.Bus, "picture-ws", "", rt.Logger)
	if err != nil {
		return err
	}
	defer bp.Close()
	rt.AddStatus(bus.StatusAttrs(bp.NC))

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	// Source control (WP-10) and the adapters' statuses (src.v1).
	srcF, followSources := sources.Follow(ctx, rt, bp, cfg.Bus)
	wg.Go(func() { followSources(ctx) })
	statuses := sources.NewStatusStore(cfg.SourceStatusMax)
	rt.AddCounters("source_status", statuses.Counters)
	wg.Go(func() { statuses.Run(ctx, bp.NC, rt.Logger) })
	sv := &SourceView{Statuses: statuses, Switches: srcF, StaleAfter: time.Duration(cfg.SourceStatusStaleS) * time.Second, Types: sources.Types}

	// The active policy from KV policy (INV-03).
	policyCounters := &core.Counters{}
	rt.AddCounters("policy", policyCounters)
	pf := policy.NewFollower(policyCounters)
	rt.AddStatus(pf.StatusAttrs)
	kv := policy.KVOf(bp, time.Duration(cfg.NATSTimeoutMS)*time.Millisecond, "", policyCounters)
	wg.Go(func() { kv.Follow(ctx, pf, time.Duration(cfg.PolicyRereadS)*time.Second, rt.Logger) })

	// The projection ages and versions, read-only, opened lazily.
	projCounters := &core.Counters{}
	rt.AddCounters("projections", projCounters)
	lr := &LazyReader{Opts: store.PoolOptions{
		URL: cfg.TSURL, MaxConns: cfg.TSMaxConns, StatementTimeout: 5 * time.Second, ApplicationName: "uspace-authority-picture-ws",
	}}
	defer lr.Close()
	proj := &Projections{Load: lr.Load, Counters: projCounters, Logger: rt.Logger}
	rt.AddStatus(proj.StatusAttrs)
	wg.Go(func() { proj.Run(ctx, time.Duration(cfg.ProjectionRefreshS)*time.Second) })

	// The session check: core's verifier on this issuer's JWKS, then
	// api's sessions table (no relational connection here, B-15).
	checker := o.Sessions
	verifierReady := func() bool { return true }
	if checker == nil {
		lv := &LazyVerifier{Logger: rt.Logger, Config: auth.Config{
			Issuers:   map[string]auth.IssuerConfig{cfg.Issuer(): {JWKSURL: cfg.JWKS()}},
			Audiences: cfg.AudienceList(), StrictSessionClaims: true,
		}}
		lv.Start(ctx)
		rt.AddCounters("session_verifier", lv.Counters())
		sessionCounters := &core.Counters{}
		rt.AddCounters("sessions", sessionCounters)
		checker = &APIChecker{
			Verifier: lv, URL: cfg.SessionURL, Client: NoRedirectClient(),
			Timeout: time.Duration(cfg.SessionTimeoutMS) * time.Millisecond, Counters: sessionCounters,
		}
		verifierReady = lv.Ready
	}

	busCounters := &core.Counters{}
	rt.AddCounters("bus", busCounters)
	watch := &BusWatch{Status: bp.NC.Status, Counters: busCounters, Logger: rt.Logger}

	hub := NewHub(Config{
		MaxClients: cfg.MaxClients, SendBuffer: cfg.SendBuffer, WriteTimeout: time.Duration(cfg.WriteTimeoutS) * time.Second,
		StatusInterval: time.Duration(cfg.StatusIntervalMS) * time.Millisecond, MaxCells: cfg.MaxCells,
		MaxTracks: cfg.MaxTracks, MaxManned: cfg.MaxManned, MaxAlerts: cfg.MaxAlerts,
		ThrottleAbove: cfg.ThrottleAboveTracks, ThrottleEvery: time.Duration(float64(time.Second) / cfg.ThrottleHz),
		AlertSilent: time.Duration(cfg.AlertSilentS) * time.Second, AlertForget: time.Duration(cfg.AlertForgetS) * time.Second,
		SubscribeMaxBytes: int64(cfg.SubscribeMaxBytes), SubscribeMinInterval: time.Duration(cfg.SubscribeMinIntervalMS) * time.Millisecond,
		SessionRecheck: time.Duration(cfg.SessionRecheckS) * time.Second, SessionGrace: time.Duration(cfg.SessionGraceS) * time.Second,
		Logger: rt.Logger, Limiter: rt.Limiter,
	}, Inputs{
		Policy: PolicyOf(pf), Projections: proj.View, Bus: watch.View, VerifierReady: verifierReady, SwitchesKnown: srcF.Known,
	}, sv, nil)
	rt.AddCounters("picture", hub.Counters())
	rt.AddStatus(func() []slog.Attr {
		t, m, a := hub.Sizes()
		return []slog.Attr{slog.Int("consoles", hub.Len()), slog.Int("tracks", t), slog.Int("manned", m), slog.Int("active_violations", a)}
	})

	// The active violations read back from ALRT: at start, and from the
	// instant the bus was lost when it is back.
	replay := func(since time.Time) {
		hub.SetReplaying(true)
		defer hub.SetReplaying(false)
		n, truncated, err := ReplayAlerts(ctx, bp.JS, since, cfg.AlertReplayMax, hub.OfferViolation)
		busCounters.Add(CounterAlertsReplayed, uint64(n))
		switch {
		case err != nil && ctx.Err() == nil:
			busCounters.Inc(CounterAlertsReplayFailed)
			rt.Logger.Error("active violations not read back from ALRT; they appear with their next republish (C-08)",
				slog.String("since", stamp(since)), slog.String("error", err.Error()))
		case truncated:
			busCounters.Inc(CounterAlertsReplayTruncated)
			rt.Logger.Error("ALRT read-back cut at its bound; later messages appear with their next republish",
				slog.Int("read", n), slog.Int("max", cfg.AlertReplayMax))
		default:
			rt.Logger.Info("active violations read back from ALRT", slog.Int("messages", n), slog.String("since", stamp(since)))
		}
	}
	watch.OnLost = func(time.Time) { hub.Poke() }
	watch.OnBack = func(lostAt time.Time) {
		hub.Poke()
		wg.Go(func() { replay(lostAt.Add(-2 * time.Second)) })
	}
	busEvery := o.BusCheckEvery
	if busEvery <= 0 {
		busEvery = 250 * time.Millisecond
	}
	wg.Go(func() { watch.Run(ctx, busEvery) })
	wg.Go(func() { replay(time.Now().Add(-time.Duration(cfg.AlertReplayS) * time.Second)) })

	subs, err := subscribeBus(bp.NC, hub)
	if err != nil {
		return err
	}
	defer func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
	}()
	rt.AddStatus(func() []slog.Attr {
		var dropped int
		for _, s := range subs {
			if d, err := s.Dropped(); err == nil {
				dropped += d
			}
		}
		return []slog.Attr{slog.Int(CounterBusDropped, dropped)}
	})
	wg.Go(func() { hub.Run(ctx) })

	h := &Handler{
		Hub: hub, Sessions: checker, Origins: cfg.Origins(), SessionTimeout: time.Duration(cfg.SessionTimeoutMS) * time.Millisecond,
		SourcesState: func(now time.Time) SourcesExtras {
			v, b := proj.View(now), watch.View()
			e := SourcesExtras{RegistryAgeS: v.RegistryAgeS, ZonesVersion: v.ZonesVersion, CISVersion: v.CISVersion, CISAgeS: v.CISAgeS, NATS: NATSConnected}
			if !b.Connected {
				e.NATS = NATSUnavailable
				if !b.Since.IsZero() {
					e.NATSSince = ptr(stamp(b.Since))
				}
			}
			return e
		},
	}
	rt.Logger.Info("picture serving", slog.Any("allowed_origins", cfg.Origins()), slog.String("session_url", cfg.SessionURL),
		slog.String("issuer", cfg.Issuer()))
	mux := http.NewServeMux()
	h.Mount(mux)
	return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, mux)
}

// subscribeBus subscribes the hub to trk.v1, man.v1 and alrt.v1 over
// core NATS (each handler runs on its own goroutine, in order); the
// subscriptions survive reconnects. The picture takes every cell and
// routes by cell in memory, so the cache and the HTTP snapshot hold
// every cell, watched or not (docs/runbooks/picture.md).
func subscribeBus(nc *nats.Conn, hub *Hub) ([]*nats.Subscription, error) {
	var subs []*nats.Subscription
	add := func(subject string, fn nats.MsgHandler) error {
		s, err := nc.Subscribe(subject, fn)
		if err != nil {
			return err
		}
		if err := s.SetPendingLimits(busPendingMsgs, busPendingBytes); err != nil {
			return err
		}
		subs = append(subs, s)
		return nil
	}
	if err := add(bus.SubjectTrkAll, func(m *nats.Msg) { hub.OfferTrack(m.Data, time.Now()) }); err != nil {
		return nil, err
	}
	if err := add(bus.SubjectManAll, func(m *nats.Msg) { hub.OfferManned(m.Subject, m.Data) }); err != nil {
		return nil, err
	}
	if err := add(bus.SubjectAlrtAll, func(m *nats.Msg) { hub.OfferViolation(m.Data, time.Now()) }); err != nil {
		return nil, err
	}
	return subs, nil
}
