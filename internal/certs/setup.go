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
	// OwnHost, CISPHost and ANSPHost are the audiences a holder's
	// client may name for its national scopes (ClientAudiences);
	// CISPHost or ANSPHost empty when that system is not configured.
	OwnHost, CISPHost, ANSPHost string
	TokenTTL                    time.Duration
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
	svc := &Service{
		DB: s.DB, Audit: s.Audit, Clients: s.Clients, Outbox: s.Outbox, KVTimeout: s.KVTimeout, Policy: s.Policy,
		Issuer: s.Issuer, Audiences: ClientAudiences(s.OwnHost, s.CISPHost, s.ANSPHost), TokenTTL: s.TokenTTL, Counters: counters, Logger: s.Logger, Limiter: s.Limiter,
	}
	if s.JS != nil {
		cfg := certkv.BucketConfig(s.Bucket)
		svc.KV = func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, s.JS, cfg) }
	}
	limit := httpx.NewRateLimiter(float64(s.RegisterPerMin)/60, s.RegisterBurst, s.RegisterMaxIPs, counters)
	return &Parts{Service: svc, Handler: Handler{Service: svc, Limit: limit}, Counters: counters}
}

// ClientAudiences is the allowed-audience list of a certificate's
// client (M18: the host of each target's base URL): this system's
// host, the CISP's (cis.read, F3) and the ANSP's (ansp.traffic F4,
// ansp.coordination F13), distinct, in that order; an empty host is
// left out. The token service refuses a national scope for any other
// audience, so a host missing here is a target the client cannot call.
func ClientAudiences(own string, peers ...string) []string {
	out := []string{own}
	for _, h := range peers {
		if h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}
