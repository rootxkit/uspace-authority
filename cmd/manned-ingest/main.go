// Command manned-ingest is the F4 client of the ANSP manned feed. It is started as `uspace-authority manned-ingest`;
// --help lists the configuration variables.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/sources"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.MannedIngest{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.MannedIngest) proc.Spec {
	return proc.Spec{Name: "manned-ingest", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		// Until WP-15: connected to the bus, following source control
		// like every process (WP-10), and waiting.
		return sources.Idle("manned-ingest", "WP-15", cfg.NATSURL, cfg.Bus)(ctx, rt)
	}}
}
