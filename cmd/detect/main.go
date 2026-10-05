// Command detect is the per-cell violation detector (WP-12). It is
// started as `uspace-authority detect`; --help lists the configuration
// variables. It loads the terrain and the geoid (GROUND_DIR, GEOID_FILE;
// WP-11), claims its cells from the ownership map (or CELLS=all), follows
// the zones and restrictions projections, the active policy and the
// source switches, and runs one uspace-core alerting.Monitor per cell3
// over trk.v1, publishing violation/v1 on alrt.v1 (internal/detectsvc).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/detectsvc"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.Detect{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.Detect) proc.Spec {
	return proc.Spec{Name: "detect", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return detectsvc.RunProcess(ctx, rt, cfg)
	}}
}
