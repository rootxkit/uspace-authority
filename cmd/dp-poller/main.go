// Command dp-poller is the F3411 Display Provider (WP-14). It is started
// as `uspace-authority dp-poller`; --help lists the configuration
// variables.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.DPPoller{}, dp.Options{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.DPPoller, o dp.Options) proc.Spec {
	return proc.Spec{Name: "dp-poller", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return dp.Run(ctx, rt, cfg, o)
	}}
}
