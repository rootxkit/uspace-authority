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
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.API{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.API) proc.Spec {
	return proc.Spec{Name: "api", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		if cfg.MTLSMode == "off" {
			rt.Logger.Error("mTLS is off on machine routes; allowed only in the lab and on staging",
				slog.String("variable", "AUTHORITY_MTLS_MODE"))
		}
		// Route groups are added here by their work packages (WP-1 on);
		// until then every path answers with a not_found problem.
		return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, http.NewServeMux())
	}}
}
