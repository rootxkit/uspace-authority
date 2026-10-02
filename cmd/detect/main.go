// Command detect is the per-cell violation detector (WP-12). It is
// started as `uspace-authority detect`; --help lists the configuration
// variables. It loads the terrain and the geoid (GROUND_DIR, GEOID_FILE;
// WP-11), claims its cells from the ownership map (or CELLS=all), follows
// the zones and restrictions projections, the active policy and the
// source switches, and runs one uspace-core alerting.Monitor per cell3
// over trk.v1, publishing violation/v1 on alrt.v1 (internal/detectsvc).
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
	"github.com/rootxkit/uspace-authority/internal/detectsvc"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/proc"
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
		// Terrain and geoid (WP-11): what is loaded, and what therefore
		// cannot be judged, at start and on every status line (Z-09).
		g := ground.New(ground.FromConfig(cfg.Ground))
		g.Log(rt.Logger)
		rt.AddStatus(g.StatusAttrs)
		rt.AddCounters("ground", g.Counters())
		if tc := g.TerrainCounters(); tc != nil {
			rt.AddCounters("terrain", tc)
		}
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

		return detectsvc.Run(ctx, rt, cfg, bp, g, claim)
	}}
}
