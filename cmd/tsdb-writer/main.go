// Command tsdb-writer is the only writer of the telemetry hypertables. It is started as `uspace-authority tsdb-writer`;
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
	code := proc.Main(ctx, spec(&config.TSDBWriter{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.TSDBWriter) proc.Spec {
	return proc.Spec{Name: "tsdb-writer", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		// Until WP-9: connected to the bus, following source control
		// like every process (WP-10), and waiting.
		return sources.Idle("tsdb-writer", "WP-9", cfg.NATSURL, cfg.Bus)(ctx, rt)
	}}
}
