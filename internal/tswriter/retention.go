package tswriter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
)

// RetentionCheck is a table that must hold nothing older than MaxAge on
// Column: the F3411 Display Provider cache (ussp_flights, 24 h; spec
// 05 §4, docs/PLAN.md §4.2). The retention policy removes whole chunks
// late by up to a chunk; the check says loudly when anything older
// remains, which is a breach of the 24 h disposal (CLAUDE.md rule 7).
type RetentionCheck struct {
	Table  string
	Column string
	MaxAge time.Duration
}

// RetentionChecks are the tables with a retention period: ussp_flights
// (WP-14, timeseries 00011, whose policy drops its one-hour chunks well
// inside the 24 h; F3411 NetDpMaxDataRetentionPeriodSeconds).
var RetentionChecks = []RetentionCheck{
	{Table: "ussp_flights", Column: "rx_ts", MaxAge: f3411.NetDpMaxDataRetentionPeriodSeconds * time.Second},
}

// UncheckedRetention are the hypertables with personal data whose
// retention tsdb-writer does not check: api's archive job (WP-27,
// internal/retention) archives and drops them after the online window
// and reports them on api's status line and GET /v1/retention/status.
// They are named here as unchecked, so this line is never read as
// covering them (audit B-N4).
var UncheckedRetention = []string{"tracks", "rid_observations", "manned_tracks"}

// OlderThaner counts rows older than an age (ts.WriterPool.OlderThan).
type OlderThaner interface {
	OlderThan(ctx context.Context, table, column string, age time.Duration) (int64, error)
}

// Counter names of the retention check.
const (
	CounterRetentionChecks     = "retention_checks"
	CounterRetentionViolations = "retention_violations"
	CounterRetentionFailed     = "retention_check_failed"
)

// Retention results on the status line.
const (
	RetentionClean    = "clean"
	RetentionViolated = "violated"
	RetentionUnknown  = "unknown"
	// RetentionUnchecked names a table with personal data whose
	// retention no check verifies yet (audit B-N4).
	RetentionUnchecked = "unchecked"
)

// Retention runs the checks at start and every Interval.
type Retention struct {
	Store  OlderThaner
	Checks []RetentionCheck
	// Unchecked are named on the status line as unchecked.
	Unchecked []string
	Interval  time.Duration
	Counters  *core.Counters
	Logger    *slog.Logger

	mu   sync.Mutex
	last map[string]string
}

// Check runs every check once and returns each table's result: clean,
// violated (rows older than MaxAge remain; logged at error level) or
// unknown (the check could not run; logged too: an unanswered check is
// not a clean one).
func (r *Retention) Check(ctx context.Context) map[string]string {
	out := make(map[string]string, len(r.Checks))
	for _, c := range r.Checks {
		r.Counters.Inc(CounterRetentionChecks)
		n, err := r.Store.OlderThan(ctx, c.Table, c.Column, c.MaxAge)
		switch {
		case err != nil:
			out[c.Table] = RetentionUnknown
			r.Counters.Inc(CounterRetentionFailed)
			r.Logger.Error("retention check could not run; the table's disposal is unverified",
				slog.String("table", c.Table), slog.String("error", err.Error()))
		case n > 0:
			out[c.Table] = RetentionViolated
			r.Counters.Inc(CounterRetentionViolations)
			r.Logger.Error("retention violated: rows older than the table's retention period remain",
				slog.String("table", c.Table), slog.String("column", c.Column),
				slog.Float64("max_age_s", c.MaxAge.Seconds()), slog.Int64("rows_at_least", n))
		default:
			out[c.Table] = RetentionClean
			r.Logger.Info("retention check: nothing older than the retention period",
				slog.String("table", c.Table), slog.Float64("max_age_s", c.MaxAge.Seconds()))
		}
	}
	r.mu.Lock()
	r.last = out
	r.mu.Unlock()
	return out
}

// Last is the result of the last Check, with the unchecked tables named.
func (r *Retention) Last() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.last)+len(r.Unchecked))
	for _, t := range r.Unchecked {
		out[t] = RetentionUnchecked
	}
	for k, v := range r.last {
		out[k] = v
	}
	return out
}

// Run checks at once and then every Interval until ctx ends.
func (r *Retention) Run(ctx context.Context) {
	if len(r.Checks) == 0 {
		r.Logger.Info("no table with a retention period is registered")
		return
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		r.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
