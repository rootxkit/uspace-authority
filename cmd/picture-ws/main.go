// Command picture-ws is the console picture feed (WP-13): GET
// /v1/picture/ws, the common console frame over a WebSocket opened
// same-origin with the uspace_session cookie, and GET
// /v1/picture/snapshot and /v1/picture/sources. It is started as
// `uspace-authority picture-ws`; --help lists the configuration
// variables, and docs/runbooks/picture.md is the frame contract.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/picture"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.PictureWS{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.PictureWS) proc.Spec {
	return specWith(cfg, picture.Options{})
}

// specWith is spec with the session check given (tests).
func specWith(cfg *config.PictureWS, o picture.Options) proc.Spec {
	return proc.Spec{Name: "picture-ws", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return picture.Run(ctx, rt, cfg, o)
	}}
}
