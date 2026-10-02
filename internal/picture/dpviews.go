package picture

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of the viewport report (E-09, E-10).
const (
	CounterViewportsReported     = "dp_viewports_reported"
	CounterViewportsReportFailed = "dp_viewports_report_failed"
	CounterViewportsOverCap      = "dp_viewports_over_cap"
)

// Viewports lists the viewports the connected consoles subscribed to,
// snapped outwards to 1e-4 degrees and without duplicates, at most limit
// (the rest are counted): what the Display Provider (WP-14) is asked to
// show besides the oversight areas.
func (h *Hub) Viewports(limit int) (boxes []dpviews.BBox, over int) {
	seen := map[dpviews.BBox]bool{}
	for _, c := range h.snapshotClients() {
		c.mu.Lock()
		subscribed, b := c.subscribed, c.lastBox
		c.mu.Unlock()
		if !subscribed {
			continue
		}
		box := dpviews.Round(dpviews.BBox{b.MinLon, b.MinLat, b.MaxLon, b.MaxLat})
		if box.Check() != nil || seen[box] {
			continue // a viewport across the antimeridian is not reported
		}
		seen[box] = true
		if len(boxes) >= limit {
			over++
			continue
		}
		boxes = append(boxes, box)
	}
	return boxes, over
}

// ViewportReporter writes this instance's console viewports to KV
// bucket dp_views every dpviews.ConsoleEvery; the bucket's TTL drops
// them when no console reports them any more, so an idle console stops
// the Display Provider polling for it (WP-14).
type ViewportReporter struct {
	Hub      *Hub
	Open     func(ctx context.Context) (jetstream.KeyValue, error)
	Instance string
	Timeout  time.Duration
	Counters *core.Counters
	Limiter  *logging.Limiter
}

// Report writes the viewports once; with none it writes nothing and the
// last report expires.
func (r *ViewportReporter) Report(ctx context.Context, now time.Time) error {
	boxes, over := r.Hub.Viewports(dpviews.MaxConsoleBoxes)
	if over > 0 && r.Counters != nil {
		r.Counters.Add(CounterViewportsOverCap, uint64(over))
	}
	if len(boxes) == 0 {
		return nil
	}
	data, err := json.Marshal(dpviews.Console{Instance: r.Instance, At: now.UTC(), BBoxes: boxes})
	if err != nil {
		return err
	}
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	kv, err := r.Open(ctx)
	if err != nil {
		return err
	}
	_, err = kv.Put(ctx, dpviews.ConsoleKey(r.Instance), data)
	return err
}

// Run reports every dpviews.ConsoleEvery until ctx ends.
func (r *ViewportReporter) Run(ctx context.Context) {
	t := time.NewTicker(dpviews.ConsoleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if err := r.Report(ctx, now); err != nil {
				if r.Counters != nil {
					r.Counters.Inc(CounterViewportsReportFailed)
				}
				if r.Limiter != nil && ctx.Err() == nil {
					r.Limiter.Limited("dp_viewports").Warn("console viewports not reported to the Display Provider; it shows the oversight areas only until they are",
						slog.String("error", err.Error()))
				}
			} else if r.Counters != nil {
				r.Counters.Inc(CounterViewportsReported)
			}
		}
	}
}
