// Command picture-ws is the console picture feed. It is started as `uspace-authority picture-ws`;
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
	code := proc.Main(ctx, spec(&config.PictureWS{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.PictureWS) proc.Spec {
	return proc.Spec{Name: "picture-ws", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		// Until WP-13: connected to the bus, following source control
		// like every process (WP-10), and waiting.
		return sources.Idle("picture-ws", "WP-13", cfg.NATSURL, cfg.Bus)(ctx, rt)
	}}
}
