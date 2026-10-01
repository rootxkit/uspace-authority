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
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.PictureWS{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.PictureWS) proc.Spec {
	return proc.Spec{Name: "picture-ws", Config: cfg, Run: proc.Idle("WP-13")}
}
