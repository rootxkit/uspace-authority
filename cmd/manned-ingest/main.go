// Command manned-ingest is the F4 client of the ANSP manned feed. It is started as `uspace-authority manned-ingest`;
// --help lists the configuration variables.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/manned"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.MannedIngest{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.MannedIngest) proc.Spec {
	return proc.Spec{Name: "manned-ingest", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return manned.Run(ctx, rt, cfg, manned.Options{})
	}}
}
