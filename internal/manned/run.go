package manned

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Options are what Run needs beyond the configuration; tests give their
// own. A nil Tokens is MANNED_CLIENT_SECRET_FILE's client; RootCAs nil
// trusts the system's roots (a test trusts its fake ANSP's).
type Options struct {
	Tokens  Tokens
	RootCAs *x509.CertPool
	// Ingest receives the ingest once built (tests read it).
	Ingest func(*Ingest)
}

// TLSConfig is the client TLS configuration towards the ANSP: with
// AUTHORITY_MTLS_MODE=required this system's client certificate from
// MANNED_CLIENT_CERT and MANNED_CLIENT_KEY (refused when it cannot be
// read: the feed fails closed, never connecting without it); with off
// none.
func TLSConfig(cfg *config.MannedIngest) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.MTLSMode != "required" {
		return c, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("MANNED_CLIENT_CERT: the client certificate towards the ANSP cannot be loaded: %w", err)
	}
	c.Certificates = []tls.Certificate{cert}
	return c, nil
}

// Run is manned-ingest's process body.
func Run(ctx context.Context, rt *proc.Runtime, cfg *config.MannedIngest, o Options) error {
	t := cfg.MannedTuning
	tc, err := TLSConfig(cfg)
	if err != nil {
		return err
	}
	tc.RootCAs = o.RootCAs
	base, _ := http.DefaultTransport.(*http.Transport)
	transport := base.Clone()
	transport.TLSClientConfig = tc
	if cfg.MTLSMode == "off" {
		// M25: said at error level at start and on every status line.
		rt.Logger.Error("AUTHORITY_MTLS_MODE=off: no client certificate is presented to the ANSP (lab and staging only)")
		rt.AddStatusLevel(func() slog.Level { return slog.LevelError })
	}
	// The transport is what the base URL makes it: plain http presents
	// no client certificate whatever the mode says (audit B-S8).
	transportName := "tls"
	if strings.HasPrefix(strings.ToLower(cfg.ANSPBaseURL), "http://") {
		transportName = "plaintext"
		rt.Logger.Error("ANSP_BASE_URL is plain http: no TLS and no client certificate towards the ANSP (loopback or lab only)")
		rt.AddStatusLevel(func() slog.Level { return slog.LevelError })
	}
	rt.AddStatus(func() []slog.Attr {
		return []slog.Attr{slog.String("mtls_mode", cfg.MTLSMode), slog.String("transport", transportName)}
	})

	bp, err := bus.OpenProcess(ctx, cfg.NATSURL, cfg.Bus, "manned-ingest", "", rt.Logger)
	if err != nil {
		return err
	}
	defer bp.Close()
	rt.Ready.Add("nats", bus.Ready(bp.NC))
	rt.AddStatus(bus.StatusAttrs(bp.NC))
	limiter := logging.NewLimiter(rt.Logger, time.Minute, logging.DefaultLimiterKeys, rt.Counters)
	follower, followSources := sources.Follow(ctx, rt, bp, cfg.Bus)

	v, err := NewValidator()
	if err != nil {
		return err
	}
	tok := o.Tokens
	if tok == nil && cfg.MannedClientSecretFile != "" && cfg.TokenURL() != "" {
		raw, err := os.ReadFile(cfg.MannedClientSecretFile)
		if err != nil {
			return fmt.Errorf("MANNED_CLIENT_SECRET_FILE: cannot be read: %w", err)
		}
		tc, err := tokens.NewClient(tokens.ClientConfig{TokenURL: cfg.TokenURL(), ClientID: cfg.MannedClientID,
			ClientSecret: strings.TrimSpace(string(raw))})
		if err != nil {
			return err
		}
		rt.AddCounters("manned_token_client", tc.Counters())
		tok = tc
	}
	if tok == nil {
		rt.Logger.Error("no client secret or token endpoint: every connection to the ANSP is refused locally; manned traffic is shown unavailable",
			slog.String("variables", "MANNED_CLIENT_SECRET_FILE, MANNED_TOKEN_URL or ISSUER_URL"))
	}
	if cfg.ANSPBaseURL == "" {
		rt.Logger.Error("no ANSP: nothing is connected; manned traffic is shown unavailable (ansp_unconfigured)",
			slog.String("variable", "ANSP_BASE_URL"))
	}

	counters := &core.Counters{}
	rt.AddCounters("manned", counters)
	sinkCounters := &core.Counters{}
	rt.AddCounters("manned_rows", sinkCounters)
	clientCounters := &core.Counters{}
	rt.AddCounters("manned_client", clientCounters)
	natsTimeout := time.Duration(t.NATSTimeoutMS) * time.Millisecond
	sink := &BusSink{NC: bp.NC, Writer: ts.BusWriter{JS: bp.JS, Timeout: natsTimeout}, QueueSize: t.RowsQueue,
		Counters: sinkCounters, Logger: rt.Logger, Limiter: limiter}
	feed := NewFeed(FeedSettings{StaleAfter: time.Duration(t.StaleAfterS) * time.Second, LagAfter: time.Duration(t.LagAfterS) * time.Second}, time.Now())
	s := DefaultSettings()
	s.FeedInstance, s.MaxAircraft, s.MaxFrameBytes = t.FeedInstance, t.MaxAircraft, t.MaxFrameBytes
	s.MaxSourceAhead = time.Duration(t.MaxSourceAheadMS) * time.Millisecond
	s.MaxSnapshotItems, s.MaxAdapters = t.MaxSnapshotItems, t.MaxAdapters
	in := &Ingest{S: s, V: v, Gate: follower, Sink: sink, Feed: feed, Counters: counters, Limiter: limiter}
	if o.Ingest != nil {
		o.Ingest(in)
	}
	changes := make(chan struct{}, 1)
	client := &Client{
		BaseURL: cfg.ANSPBaseURL, BBox: cfg.MannedBBox, Tokens: tok, HTTP: NoRedirectClient(transport), Ingest: in, Changes: changes,
		MaxSnapshotBytes: int64(t.MaxSnapshotBytes), RequestTimeout: time.Duration(t.RequestTimeoutMS) * time.Millisecond,
		SilentAfter: time.Duration(t.SilentReconnectS) * time.Second, BackoffMin: time.Duration(t.BackoffMinMS) * time.Millisecond,
		BackoffMax: time.Duration(t.BackoffMaxMS) * time.Millisecond, Counters: clientCounters, Logger: rt.Logger, Limiter: limiter,
	}
	status := &Status{Ingest: in, Pub: bp.NC, Gate: follower, Who: follower.DisabledByWho, MTLSMode: cfg.MTLSMode,
		Logger: rt.Logger, Limiter: limiter}
	rt.AddStatus(func() []slog.Attr {
		fv := feed.View(time.Now())
		attrs := []slog.Attr{slog.String("feed_state", fv.State), slog.Int("aircraft_held", in.Len()), slog.Int("rows_queue", sink.Depth())}
		if fv.State == FeedUnavailable {
			attrs = append(attrs, slog.Time("unavailable_since", fv.UnavailableSince), slog.String("reason", fv.Reason))
		}
		return attrs
	})
	rt.Logger.Info("manned traffic ingest limits", slog.String("ansp", cfg.ANSPBaseURL), slog.String("bbox", cfg.MannedBBox),
		slog.String("feed_instance", t.FeedInstance), slog.Int("stale_after_s", t.StaleAfterS), slog.Int("lag_after_s", t.LagAfterS),
		slog.Int("max_aircraft", t.MaxAircraft), slog.Int("max_frame_bytes", t.MaxFrameBytes))

	runCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() { followSources(runCtx) })
	wg.Go(func() { sink.Run(runCtx) })
	wg.Go(func() { status.Run(runCtx, time.Duration(t.StatusIntervalMS)*time.Millisecond) })
	wg.Go(func() {
		reapply := time.NewTicker(time.Duration(t.SwitchesReapplyS) * time.Second)
		defer reapply.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-follower.Changes():
				select {
				case changes <- struct{}{}:
				default:
				}
			case <-reapply.C:
			}
			in.ApplySwitches(time.Now())
		}
	})
	wg.Go(func() { client.Run(runCtx) })
	<-ctx.Done()
	return nil
}
