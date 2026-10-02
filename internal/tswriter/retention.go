package tswriter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
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

// RetentionChecks are the tables with a retention period. ussp_flights
// is added by WP-14 together with its migration, which adds the policy
// with authority_hypertable_policies (timeseries 00005).
var RetentionChecks []RetentionCheck

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
)

// Retention runs the checks at start and every Interval.
type Retention struct {
	Store    OlderThaner
	Checks   []RetentionCheck
	Interval time.Duration
	Counters *core.Counters
	Logger   *slog.Logger

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

// Last is the result of the last Check.
func (r *Retention) Last() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.last))
	for k, v := range r.last {
		out[k] = v
	}
	return out
}

// Run checks at once and then every Interval until ctx ends.
func (r *Retention) Run(ctx context.Context) {
	if len(r.Checks) == 0 {
		r.Logger.Info("no table with a retention period is registered yet (ussp_flights arrives with WP-14)")
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
