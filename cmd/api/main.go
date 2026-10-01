// Command api is the control plane: the national API, the registry,
// zones, certificates, the token service and the jobs. It is started as
// `uspace-authority api`; --help lists the configuration variables.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.API{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

// spec is the production process: no console session exists until WP-2,
// so every /v1 route answers 401 unauthenticated.
func spec(cfg *config.API) proc.Spec { return specWith(cfg, apiserver.NoSession) }

func specWith(cfg *config.API, identify apiserver.IdentifyFunc) proc.Spec {
	return proc.Spec{Name: "api", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		if cfg.MTLSMode == "off" {
			rt.Logger.Error("mTLS is off on machine routes; allowed only in the lab and on staging",
				slog.String("variable", "AUTHORITY_MTLS_MODE"))
		}
		db, err := pg.Open(ctx, store.PoolOptions{
			URL:              cfg.PGURL,
			MaxConns:         cfg.PGMaxConns,
			StatementTimeout: time.Duration(cfg.PGStatementTimeoutS) * time.Second,
			ApplicationName:  "uspace-authority-api",
			Role:             cfg.PGRole,
		})
		if err != nil {
			return err
		}
		defer db.Close()
		rt.Ready.Add("relational", db.Ping)

		// api follows the policy it serves: its own activations reach the
		// follower at once, and the re-read repairs anything missed.
		follower := policy.NewFollower(nil)
		counters := follower.Counters()
		rt.AddCounters("policy", counters)
		rt.AddStatus(follower.StatusAttrs)
		auditWriter := audit.NewWriter(db)
		svc := &policy.Service{DB: db, Audit: auditWriter, Publisher: follower, Logger: rt.Logger, Counters: counters}
		var wg sync.WaitGroup
		wg.Go(func() {
			follower.Run(ctx, svc.Active, time.Duration(cfg.PolicyRefreshS)*time.Second, rt.Logger)
		})
		defer wg.Wait()

		mux := http.NewServeMux()
		apiserver.Mount(mux, apiserver.Server{
			PolicyHandler: policy.Handler{Service: svc},
			AuditHandler:  audit.Handler{Writer: auditWriter},
		}, apiserver.Options{
			Logger:      rt.Logger,
			Middlewares: []apiserver.Middleware{apiserver.RequireRole(identify, apiserver.Roles)},
			Keep:        apiserver.PathPrefix("/v1/"),
		})
		return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, mux)
	}}
}
