// Command detect is the per-cell violation detector. It is started as `uspace-authority detect`;
// --help lists the configuration variables. Until WP-12 it claims its
// cells from the ownership map (or CELLS=all) and waits.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/sources"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.Detect{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.Detect) proc.Spec {
	return proc.Spec{Name: "detect", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		bp, err := bus.OpenProcess(ctx, cfg.NATSURL, cfg.Bus, "detect", "", rt.Logger)
		if err != nil {
			return err
		}
		defer bp.Close()
		rt.AddStatus(bus.StatusAttrs(bp.NC))
		// The cells this worker judges (05 §3): the ownership map's, or
		// every cell with CELLS=all; none is a refusal to start.
		claim, err := cell.LoadClaim(ctx, cell.StoreOf(bp), cfg.WorkerID, cfg.Cells == "all",
			cfg.NATSStartAttempts, time.Duration(cfg.NATSStartBackoffMS)*time.Millisecond)
		if err != nil {
			return err
		}
		cells := make([]string, 0, len(claim.Cells))
		for _, c := range claim.Cells {
			cells = append(cells, c.String())
		}
		rt.Logger.Info("cells claimed", slog.String("worker_id", cfg.WorkerID), slog.Bool("all", claim.All),
			slog.Any("cells", cells), slog.Uint64("ownership_version", claim.Version))
		// detect clears the alerts of a disabled source as source_disabled
		// (WP-12); it follows the switches from the start.
		_, followSources := sources.Follow(ctx, rt, bp, cfg.Bus)
		done := make(chan struct{})
		go func() { defer close(done); followSources(ctx) }()
		defer func() { <-done }()
		return proc.Idle("WP-12")(ctx, rt)
	}}
}
