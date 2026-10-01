// Command rid-ingest is the F9 Remote ID receiver ingest. It is started as `uspace-authority rid-ingest`;
// --help lists the configuration variables.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.RIDIngest{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.RIDIngest) proc.Spec {
	return proc.Spec{Name: "rid-ingest", Config: cfg, Run: proc.Idle("WP-7")}
}
