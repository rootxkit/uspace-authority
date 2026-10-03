package dp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/timeplace"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/picture"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Options are what Run needs beyond the configuration; tests give their
// own. A nil Tokens is DP_CLIENT_SECRET_FILE's client; a nil Verifier is
// this issuer's (and the lab's) through uspace-core; a nil Geoid is
// GEOID_FILE's grid; HTTPClient nil is a client that follows no
// redirect.
type Options struct {
	Tokens     Tokens
	Verifier   Verifier
	Geoid      geoid.Undulator
	HTTPClient *http.Client
	// Engine receives the engine once built (tests read it).
	Engine func(*Engine)
}

// SettingsOf are the engine's settings of the configuration.
func SettingsOf(t config.DPPollerTuning) Settings {
	s := DefaultSettings()
	s.RequestTimeout = time.Duration(t.RequestTimeoutMS) * time.Millisecond
	s.MaxFlights, s.MaxTilesPerSP = t.MaxFlights, t.MaxTilesPerSP
	s.MaxDetailsPerPoll, s.DetailsConcurrency = t.MaxDetailsPerPoll, t.DetailsConcurrency
	s.UnavailableAfter = time.Duration(t.UnavailableAfterS) * time.Second
	s.SlowPollHz, s.MaxSplitDepth = t.SlowPollHz, t.MaxSplitDepth
	s.MaxViews, s.MaxTiles, s.MaxProviders = t.MaxViews, t.MaxTiles, t.MaxProviders
	return s
}

// issuerVerifier routes a token to the verifier of its (unverified)
// issuer: this system's or the lab's; any other iss reaches this
// system's verifier and is refused there (rejected_issuer).
type issuerVerifier struct {
	self  *picture.LazyVerifier
	peers map[string]*picture.LazyVerifier
}

// Verify implements Verifier.
func (v issuerVerifier) Verify(ctx context.Context, token string) (auth.Claims, error) {
	if iss := tokens.UnverifiedIssuer(token); iss != "" {
		if p, ok := v.peers[iss]; ok {
			return p.Verify(ctx, token)
		}
	}
	return v.self.Verify(ctx, token)
}

func (v issuerVerifier) ready() bool { return v.self.Ready() }

// lazyProjection reads the registry projection as authority_ts_reader,
// opening the telemetry database on first use and again after an open
// failed, so dp-poller starts with the database down and identifies
// registry_unavailable until it can read (B-08, SC-22).
type lazyProjection struct {
	opts store.PoolOptions
	mu   sync.Mutex
	r    *ts.Reader
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

// Run is dp-poller's process body.
func Run(ctx context.Context, rt *proc.Runtime, cfg *config.DPPoller, o Options) error {
	t := cfg.DPPollerTuning
	natsTimeout := time.Duration(t.NATSTimeoutMS) * time.Millisecond
	bp, err := bus.OpenProcess(ctx, cfg.NATSURL, cfg.Bus, "dp-poller", "", rt.Logger)
	if err != nil {
		return err
	}
	defer bp.Close()
	rt.Ready.Add("nats", bus.Ready(bp.NC))
	rt.AddStatus(bus.StatusAttrs(bp.NC))
	limiter := logging.NewLimiter(rt.Logger, time.Minute, logging.DefaultLimiterKeys, rt.Counters)

	follower, followSources := sources.Follow(ctx, rt, bp, cfg.Bus)

	policyCounters := &core.Counters{}
	rt.AddCounters("policy", policyCounters)
	pf := policy.NewFollower(policyCounters)
	rt.AddStatus(pf.StatusAttrs)
	pkv := policy.KVOf(bp, natsTimeout, "", policyCounters)
	policyValues := func() (float64, float64) {
		p, ok := pf.Current()
		if !ok {
			d := policy.Defaults()
			return d.DPPollHz, d.DPViewDiagonalKM
		}
		return p.DPPollHz, p.DPViewDiagonalKM
	}

	regCounters := &core.Counters{}
	rt.AddCounters("registry_projection", regCounters)
	src := &lazyProjection{opts: store.PoolOptions{URL: cfg.TSURL, MaxConns: 2, StatementTimeout: 10 * time.Second,
		ApplicationName: "uspace-authority-dp-poller"}}
	defer src.close()
	reader := &registry.ProjectionReader{Source: src, Counters: regCounters, Logger: rt.Logger}
	rt.AddStatus(reader.StatusAttrs)

	geo := o.Geoid
	if geo == nil {
		geo = loadGeoid(rt, cfg.Geoid)
	}
	if geo == nil {
		rt.Logger.Warn("no geoid configured: Display Provider flights have no AMSL altitude and are not judged vertically (R-07)")
	}

	tok := o.Tokens
	if tok == nil && cfg.DPClientSecretFile != "" {
		raw, err := os.ReadFile(cfg.DPClientSecretFile)
		if err != nil {
			return fmt.Errorf("DP_CLIENT_SECRET_FILE: cannot be read: %w", err)
		}
		tc, err := tokens.NewClient(tokens.ClientConfig{TokenURL: cfg.TokenURL(), ClientID: cfg.DPClientID, ClientSecret: strings.TrimSpace(string(raw))})
		if err != nil {
			return err
		}
		rt.AddCounters("dp_token_client", tc.Counters())
		tok = tc
	}
	if tok == nil {
		rt.Logger.Error("no client secret: every call to the DSS and to Service Providers is refused locally; nothing is discovered or polled",
			slog.String("variable", "DP_CLIENT_SECRET_FILE"))
	}
	hc := o.HTTPClient
	if hc == nil {
		hc = NoRedirectClient()
	}
	client := &Client{HTTP: hc, Tokens: tok, MaxBody: int64(t.MaxBodyBytes), DSS: cfg.DSSBaseURL}

	counters := &core.Counters{}
	rt.AddCounters("dp", counters)
	mapCounters := &core.Counters{}
	rt.AddCounters("dp_mapping", mapCounters)
	discCounters := &core.Counters{}
	rt.AddCounters("dp_discovery", discCounters)
	isas := &ISAs{Max: t.MaxISAs, Counters: discCounters}
	disc := &Discovery{ISAs: isas, USSBaseURL: cfg.SubscriberURL(), Reread: time.Duration(t.DiscoveryRereadS) * time.Second,
		MaxSubscriptions: t.MaxTiles, Timeout: time.Duration(t.RequestTimeoutMS) * time.Millisecond, Counters: discCounters, Limiter: limiter}
	if cfg.DSSBaseURL != "" {
		disc.DSS = client
	} else {
		rt.Logger.Error("no DSS: no identification service area is discovered and nothing is polled (dss_unconfigured)",
			slog.String("variable", "DSS_BASE_URL"))
	}

	viewCounters := &core.Counters{}
	rt.AddCounters("dp_views", viewCounters)
	oversightCfg, consoleCfg := dpviews.OversightBucketConfig(t.OversightBucket), dpviews.ConsoleBucketConfig(t.ViewsBucket)
	views := &ViewReader{
		Oversight:   func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, bp.JS, oversightCfg) },
		Consoles:    func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, bp.JS, consoleCfg) },
		MaxConsoles: t.MaxViews, Timeout: natsTimeout, Counters: viewCounters, Limiter: limiter,
	}

	certCounters := &core.Counters{}
	rt.AddCounters("dp_certificates", certCounters)
	certCfg := certkv.BucketConfig(t.CertificatesBucket)
	certs := &CertificateReader{
		Open:    func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, bp.JS, certCfg) },
		Timeout: natsTimeout, Counters: certCounters, Limiter: limiter,
	}
	rt.AddStatus(certs.StatusAttrs)

	sinkCounters := &core.Counters{}
	rt.AddCounters("dp_rows", sinkCounters)
	sink := &BusSink{NC: bp.NC, Writer: ts.BusWriter{JS: bp.JS, Timeout: natsTimeout}, Counters: sinkCounters,
		Logger: rt.Logger, Limiter: limiter}
	memCounters := &core.Counters{}
	rt.AddCounters("dp_memory", memCounters)
	s := SettingsOf(t)
	s.Network = timeplace.DefaultNetworkPolicy()
	e := &Engine{
		S: s, SP: client, ISAs: isas, Discovery: disc, Views: func(context.Context) []Box { return views.Boxes() },
		Gate: follower, Policy: policyValues, Registry: reader.Lookup, Certified: certs.Certified, Geoid: geo, Sink: sink,
		Memory: NewMemory(t.MaxFlightsHeld, memCounters), Counters: counters, MapCounters: mapCounters,
		Logger: rt.Logger, Limiter: limiter,
	}
	if o.Engine != nil {
		o.Engine(e)
	}
	status := &Status{Engine: e, Pub: bp.NC, Who: follower.DisabledByWho, Logger: rt.Logger, Limiter: limiter}
	rt.AddStatus(func() []slog.Attr {
		st, since := disc.State()
		ov, cons := views.Counts()
		attrs := []slog.Attr{
			slog.String("dss", st), slog.Int("oversight_areas", ov), slog.Int("console_viewports", cons),
			slog.Int("tiles", len(e.Tiles())), slog.Int("isas", isas.Len()), slog.Int("subscriptions", disc.Subscriptions()),
			slog.Int("providers", len(e.Providers())), slog.Int("pollers", e.Pollers()), slog.Int("flights_held", e.Memory.Len()),
			slog.Int("rows_queue", sink.Depth()),
		}
		if st == DSSUnavailable {
			attrs = append(attrs, slog.Time("dss_unavailable_since", since))
		}
		return attrs
	})

	verifier := o.Verifier
	if verifier == nil {
		self := &picture.LazyVerifier{Logger: rt.Logger, Config: auth.Config{
			Issuers:   map[string]auth.IssuerConfig{cfg.Issuer(): {JWKSURL: cfg.JWKS()}},
			Audiences: cfg.AudienceList(), StrictSessionClaims: true,
		}}
		self.Start(ctx)
		rt.AddCounters("dp_verifier", self.Counters())
		iv := issuerVerifier{self: self, peers: map[string]*picture.LazyVerifier{}}
		if cfg.LabIssuerURL != "" && cfg.LabJWKSURL != "" {
			lab := &picture.LazyVerifier{Logger: rt.Logger, Config: auth.Config{
				Issuers:   map[string]auth.IssuerConfig{strings.TrimSuffix(cfg.LabIssuerURL, "/"): {JWKSURL: cfg.LabJWKSURL}},
				Audiences: cfg.AudienceList(), StrictSessionClaims: true,
			}}
			lab.Start(ctx)
			rt.AddCounters("dp_verifier_lab", lab.Counters())
			iv.peers[strings.TrimSuffix(cfg.LabIssuerURL, "/")] = lab
		}
		rt.AddStatus(func() []slog.Attr { return []slog.Attr{slog.Bool("token_verifier_ready", iv.ready())} })
		verifier = iv
	}

	wake := make(chan struct{}, 1)
	poke := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	notifyCounters := &core.Counters{}
	rt.AddCounters("dp_notifications", notifyCounters)
	notes := &Notifications{Verifier: verifier, ISAs: isas, Known: disc.Known, MaxBytes: int64(t.MaxNotificationBytes),
		Changed: poke, Counters: notifyCounters, Limiter: limiter}
	obsCounters := &core.Counters{}
	rt.AddCounters("dp_observations", obsCounters)
	obs := &Observations{Verifier: verifier, Memory: e.Memory, Counters: obsCounters}

	rt.Logger.Info("Display Provider limits (R-14)",
		slog.Duration("request_timeout", s.RequestTimeout), slog.Int("max_body_bytes", t.MaxBodyBytes),
		slog.Int("max_flights_per_response", s.MaxFlights), slog.Int("max_tiles_per_sp", s.MaxTilesPerSP),
		slog.Int("max_details_per_poll", s.MaxDetailsPerPoll), slog.Int("details_concurrency", s.DetailsConcurrency),
		slog.Float64("slow_poll_hz", s.SlowPollHz), slog.Duration("unavailable_after", s.UnavailableAfter),
		slog.Int("max_split_depth", s.MaxSplitDepth), slog.String("certificates_bucket", certCfg.Bucket))

	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() { followSources(runCtx) })
	wg.Go(func() { pkv.Follow(runCtx, pf, time.Duration(t.PolicyRereadS)*time.Second, rt.Logger) })
	wg.Go(func() { reader.Run(runCtx, time.Duration(t.ProjectionRefreshS)*time.Second) })
	wg.Go(func() { followRegistry(runCtx, bp.NC, reader, rt.Logger) })
	wg.Go(func() { views.Run(runCtx, time.Duration(t.ViewsRereadS)*time.Second) })
	wg.Go(func() { certs.Run(runCtx, time.Duration(t.CertificatesRereadS)*time.Second) })
	wg.Go(func() { sink.Run(runCtx) })
	wg.Go(func() { status.Run(runCtx, time.Duration(t.StatusIntervalMS)*time.Millisecond) })
	changes := make(chan struct{}, 1)
	wg.Go(func() {
		for {
			select {
			case <-runCtx.Done():
				return
			case <-follower.Changes():
			case <-wake:
			}
			select {
			case changes <- struct{}{}:
			default:
			}
		}
	})
	wg.Go(func() { e.Run(runCtx, changes) })
	wg.Go(func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			disc.Sync(runCtx, e.Tiles())
			select {
			case <-runCtx.Done():
				dctx, dcancel := context.WithTimeout(context.WithoutCancel(runCtx), rt.DrainTimeout()/2)
				disc.Close(dctx)
				dcancel()
				return
			case <-tick.C:
			}
		}
	})

	mux := http.NewServeMux()
	notes.Mount(mux)
	obs.Mount(mux)
	err = rt.ServePublic(runCtx, cfg.HTTP, cfg.Addr, mux)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// followRegistry re-reads the projection on registry.v1.changed.
func followRegistry(ctx context.Context, nc *nats.Conn, reader *registry.ProjectionReader, logger *slog.Logger) {
	ch := make(chan *nats.Msg, 1)
	sub, err := nc.ChanSubscribe(bus.SubjectRegistryChanged, ch)
	if err != nil {
		logger.Warn("registry.v1.changed not followed; the projection is re-read periodically only", slog.String("error", err.Error()))
		return
	}
	defer func() { _ = sub.Unsubscribe() }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			reader.Notify()
		}
	}
}

// loadGeoid reads GEOID_FILE through internal/ground (WP-11): nil when
// unset or unreadable, said at start and on every status line.
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
		return []slog.Attr{slog.String("geoid_grid", g.GeoidDescription())}
	})
	return g.Undulator()
}
