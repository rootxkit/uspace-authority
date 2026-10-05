package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cisp"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// assembleCISP builds the CISP client (WP-6) from the configuration:
// the publication key of the token service signs, the authority's own
// client (authority-01) asks its own token service for the CISP's
// tokens, and AUTHORITY_CIS_NOTIFY_ISSUERS is the receiver's allow-list.
// What is missing is said at error level and on every status line; the
// control plane still starts.
func assembleCISP(ctx context.Context, cfg *config.API, rt *proc.Runtime, tok *tokens.Parts, db *pg.DB, w *audit.Writer,
	reg *registry.Parts, bp *bus.Process, follower *policy.Follower) (*cisp.Parts, error) {
	ring, err := tok.Keys.PublicationRing()
	if err != nil {
		return nil, err
	}
	if ring == nil {
		rt.Logger.Error("no publication key: every publication to the CISP is refused (503 publication_key_missing)",
			slog.String("variable", "PUBLICATION_KEY_FILE"))
	}
	if cfg.CISPBaseURL == "" {
		rt.Logger.Error("no CISP: publications are queued and never sent, nothing is pulled; the console shows their ages",
			slog.String("variable", "CISP_BASE_URL"))
	}
	var src cisp.TokenSource
	if cfg.CISPClientSecretFile != "" {
		raw, err := os.ReadFile(cfg.CISPClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("CISP_CLIENT_SECRET_FILE: cannot be read: %w", err)
		}
		tc, err := tokens.NewClient(tokens.ClientConfig{
			TokenURL: cfg.TokenURL(), ClientID: cfg.CISPClientID, ClientSecret: strings.TrimSpace(string(raw)),
		})
		if err != nil {
			return nil, err
		}
		rt.AddCounters("cisp_token_client", tc.Counters())
		src = tc
	} else if cfg.CISPBaseURL != "" {
		rt.Logger.Error("no client secret for the CISP: every call to it is refused locally and counted",
			slog.String("variable", "CISP_CLIENT_SECRET_FILE"))
	}
	list, err := cfg.NotifyIssuerList()
	if err != nil {
		return nil, err
	}
	issuers := make([]cisp.NotifyIssuer, 0, len(list))
	for _, n := range list {
		issuers = append(issuers, cisp.NotifyIssuer{Issuer: n.Issuer, JWKSURL: n.JWKSURL, ANSP: n.ANSP})
	}
	bbox, err := cfg.SubscriptionBBox()
	if err != nil {
		return nil, err
	}
	ansp := cfg.CISANSPJWKSURL
	if ansp == "" {
		ansp = cfg.ANSPJWKSURL
	}
	return cisp.Assemble(ctx, cisp.Setup{
		DB: db, Audit: w, Projector: reg.Projector, JS: bp.JS, NATSTimeout: time.Duration(cfg.NATSTimeoutMS) * time.Millisecond,
		PublicationRing: ring, Tokens: src, BaseURL: cfg.CISPBaseURL, CallbackURL: cfg.CISCallbackURL, BBox: bbox,
		Audiences: cfg.AudienceList(), NotifyIssuers: issuers, ANSPPublisherJWKSURL: ansp,
		PublisherSigMaxAge: time.Duration(cfg.CISPublisherSigMaxAgeS) * time.Second,
		ReconcileInterval:  time.Duration(cfg.CISReconcileS) * time.Second,
		HeartbeatInterval:  time.Duration(cfg.CISHeartbeatS) * time.Second,
		BackoffMin:         time.Duration(cfg.CISSendBackoffMinS) * time.Second,
		BackoffMax:         time.Duration(cfg.CISSendBackoffMaxS) * time.Second,
		GiveUp:             time.Duration(cfg.CISSendGiveUpS) * time.Second,
		MaxLiveJTIs:        int64(cfg.CISJTIMaxLive),
		DirectMax:          cfg.CISDirectMax,
		DirectKeep:         time.Duration(cfg.CISDirectKeepS) * time.Second,
		StaleBoundS: func() float64 {
			if p, ok := follower.Current(); ok && p.CISStaleBoundS > 0 {
				return p.CISStaleBoundS
			}
			return cisp.DefaultStaleBoundS
		},
		Logger: rt.Logger, Limiter: rt.Limiter,
	})
}
