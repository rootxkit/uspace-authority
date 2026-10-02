package tswriter

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

type olderThan map[string]struct {
	n   int64
	err error
}

func (o olderThan) OlderThan(_ context.Context, table, _ string, _ time.Duration) (int64, error) {
	r := o[table]
	return r.n, r.err
}

// E-01: the check says clean, violated and unknown, each by name, and
// the violation and the unanswered check are error lines.
func TestRetentionCheckReportsCleanViolatedAndUnknown(t *testing.T) {
	logs := &syncBuf{}
	c := &core.Counters{}
	r := &Retention{
		Store: olderThan{"clean": {}, "old": {n: 3}, "down": {err: errors.New("connection refused")}},
		Checks: []RetentionCheck{
			{Table: "clean", Column: "rx_ts", MaxAge: 24 * time.Hour}, {Table: "old", Column: "rx_ts", MaxAge: 24 * time.Hour},
			{Table: "down", Column: "rx_ts", MaxAge: 24 * time.Hour},
		},
		Counters: c, Logger: slog.New(slog.NewJSONHandler(logs, nil)), Interval: time.Hour,
	}
	got := r.Check(context.Background())
	if got["clean"] != RetentionClean || got["old"] != RetentionViolated || got["down"] != RetentionUnknown {
		t.Fatalf("%v", got)
	}
	if last := r.Last(); last["old"] != RetentionViolated {
		t.Fatalf("last %v", last)
	}
	s := c.Snapshot()
	if s[CounterRetentionChecks] != 3 || s[CounterRetentionViolations] != 1 || s[CounterRetentionFailed] != 1 {
		t.Fatalf("counters %v", s)
	}
	out := logs.String()
	if !strings.Contains(out, `"level":"ERROR","msg":"retention violated: rows older than the table's retention period remain"`) ||
		!strings.Contains(out, `"rows_at_least":3`) || !strings.Contains(out, `"level":"ERROR","msg":"retention check could not run`) ||
		!strings.Contains(out, "nothing older than the retention period") {
		t.Fatal(out)
	}
}

func TestRetentionRunWithNoChecksSaysSo(t *testing.T) {
	logs := &syncBuf{}
	r := &Retention{Counters: &core.Counters{}, Logger: slog.New(slog.NewJSONHandler(logs, nil)), Interval: time.Hour}
	r.Run(context.Background())
	if !strings.Contains(logs.String(), "no table with a retention period is registered") {
		t.Fatal(logs.String())
	}
}

// WP-14: the Display Provider's cache is registered with the F3411 24 h
// (NetDpMaxDataRetentionPeriodSeconds) on its receive time, so Run checks
// it at start and hourly; the run with no checks above is its absence.
func TestUSSPFlightsIsCheckedForTwentyFourHours(t *testing.T) {
	if len(RetentionChecks) != 1 {
		t.Fatalf("checks %+v", RetentionChecks)
	}
	c := RetentionChecks[0]
	if c.Table != "ussp_flights" || c.Column != "rx_ts" || c.MaxAge != 24*time.Hour {
		t.Fatalf("check %+v", c)
	}
}

func TestRetentionRunChecksAtOnceAndEveryInterval(t *testing.T) {
	c := &core.Counters{}
	r := &Retention{Store: olderThan{}, Checks: []RetentionCheck{{Table: "t", Column: "c", MaxAge: time.Hour}},
		Counters: c, Logger: slog.New(slog.DiscardHandler), Interval: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	eventually(t, "three checks", func() bool { return c.Snapshot()[CounterRetentionChecks] >= 3 })
	cancel()
	<-done
}
