package dpadmin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Assemble builds the Display Provider's administration of api: the
// oversight areas published to KV dp_oversight, dp-poller's statuses,
// and the arbitration client towards the DSS with this system's own
// client (authority-01). What is missing is said at start; the control
// plane still starts.
func Assemble(cfg *config.API, rt *proc.Runtime, db *pg.DB, w *audit.Writer, bp *bus.Process) (*Service, error) {
	counters := &core.Counters{}
	rt.AddCounters("dp_admin", counters)
	statusCounters := &core.Counters{}
	rt.AddCounters("dp_provider_status", statusCounters)
	bucket := dpviews.OversightBucketConfig(cfg.DPOversightBucket)
	s := &Service{
		DB: db, Audit: w, KVTimeout: time.Duration(cfg.NATSTimeoutMS) * time.Millisecond,
		Oversight:  func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, bp.JS, bucket) },
		DSS:        cfg.DSSBaseURL,
		Providers:  &Providers{Max: cfg.DPProvidersMax, Counters: statusCounters},
		StaleAfter: time.Duration(cfg.SourceStatusStaleS) * time.Second,
		Counters:   counters, Logger: rt.Logger, Limiter: rt.Limiter,
	}
	if cfg.DPClientSecretFile != "" {
		raw, err := os.ReadFile(cfg.DPClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("DP_CLIENT_SECRET_FILE: cannot be read: %w", err)
		}
		tc, err := tokens.NewClient(tokens.ClientConfig{
			TokenURL: cfg.Issuer() + "/oauth/token", ClientID: cfg.DPClientID, ClientSecret: strings.TrimSpace(string(raw)),
		})
		if err != nil {
			return nil, err
		}
		rt.AddCounters("dp_token_client", tc.Counters())
		s.Tokens = tc
	}
	if cfg.DSSBaseURL == "" || s.Tokens == nil {
		rt.Logger.Warn("USS availability arbitration is refused until a DSS and a client secret are configured",
			slog.String("variables", "DSS_BASE_URL, DP_CLIENT_SECRET_FILE"))
	}
	return s, nil
}
