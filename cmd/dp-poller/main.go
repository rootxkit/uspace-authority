// Command dp-poller is the F3411 Display Provider. It is started as `uspace-authority dp-poller`;
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
	code := proc.Main(ctx, spec(&config.DPPoller{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.DPPoller) proc.Spec {
	return proc.Spec{Name: "dp-poller", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		// Until WP-14: connected to the bus, following source control
		// like every process (WP-10), and waiting.
		return sources.Idle("dp-poller", "WP-14", cfg.NATSURL, cfg.Bus)(ctx, rt)
	}}
}
