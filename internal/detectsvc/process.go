package detectsvc

import (
	"context"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

// RunProcess is detect's whole process body, the Run of cmd/detect's
// proc.Spec: it opens the bus, loads the terrain and the geoid
// (GROUND_DIR, GEOID_FILE; WP-11), claims its cells from the ownership
// map (or CELLS=all) and runs Run. The scenario harness
// (internal/ltest, WP-25) starts detect in process through it, so a
// scenario runs exactly the wiring the binary runs.
func RunProcess(ctx context.Context, rt *proc.Runtime, cfg *config.Detect) error {
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

	return Run(ctx, rt, cfg, bp, g, claim)
}
