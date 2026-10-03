package certs

import (
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/policy"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Setup is what Assemble needs.
type Setup struct {
	DB      *pgstore.DB
	Audit   *audit.Writer
	Clients *tokens.Registry
	// Outbox is WP-6's (*cisp.Outbox); nil leaves every list pending.
	Outbox ListOutbox
	// JS is the bus; nil publishes no register to KV.
	JS        jetstream.JetStream
	Bucket    string
	KVTimeout time.Duration
	Policy    func() (policy.Policy, bool)
	Issuer    string
	// OwnHost and CISPHost are the audiences a holder's client may name
	// for its national scopes; CISPHost empty when no CISP is
	// configured.
	OwnHost, CISPHost string
	TokenTTL          time.Duration
	// RegisterPerMin, RegisterBurst and RegisterMaxIPs bound the public
	// register per client address.
	RegisterPerMin, RegisterBurst, RegisterMaxIPs int
	Logger                                        *slog.Logger
	Limiter                                       *logging.Limiter
}

// Parts are the assembled certificates.
type Parts struct {
	Service  *Service
	Handler  Handler
	Counters *core.Counters
}

// Assemble builds the service and its handler.
func Assemble(s Setup) *Parts {
	counters := &core.Counters{}
	auds := []string{s.OwnHost}
	if s.CISPHost != "" && !slices.Contains(auds, s.CISPHost) {
		auds = append(auds, s.CISPHost)
	}
	svc := &Service{
		DB: s.DB, Audit: s.Audit, Clients: s.Clients, Outbox: s.Outbox, KVTimeout: s.KVTimeout, Policy: s.Policy,
		Issuer: s.Issuer, Audiences: auds, TokenTTL: s.TokenTTL, Counters: counters, Logger: s.Logger, Limiter: s.Limiter,
	}
	if s.JS != nil {
		cfg := certkv.BucketConfig(s.Bucket)
		svc.KV = func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, s.JS, cfg) }
	}
	limit := httpx.NewRateLimiter(float64(s.RegisterPerMin)/60, s.RegisterBurst, s.RegisterMaxIPs, counters)
	return &Parts{Service: svc, Handler: Handler{Service: svc, Limit: limit}, Counters: counters}
}
