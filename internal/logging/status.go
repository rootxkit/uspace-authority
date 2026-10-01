package logging

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Source is one named set of counters on the status line (a component:
// "http", "ridpipe", "process").
type Source struct {
	Name     string
	Counters *core.Counters
}

// Status emits one status line per interval with a snapshot of every
// source's counters, so that silence is distinguishable from health
// (E-09): a counter that never moved is absent from its snapshot, and a
// source with no counters still appears, empty.
type Status struct {
	Logger   *slog.Logger
	Interval time.Duration
	Sources  []Source
	// Extra adds attributes to each line (projection ages, degraded
	// states); may be nil.
	Extra func() []slog.Attr

	mu      sync.Mutex
	started time.Time
}

// Add puts one more source on the line; safe while Run is running.
func (s *Status) Add(src Source) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Sources = append(s.Sources, src)
}

// Emit writes one status line now.
func (s *Status) Emit(ctx context.Context) {
	s.mu.Lock()
	if s.started.IsZero() {
		s.started = time.Now()
	}
	started := s.started
	counters := make(map[string]map[string]uint64, len(s.Sources))
	for _, src := range s.Sources {
		counters[src.Name] = src.Counters.Snapshot()
	}
	s.mu.Unlock()
	attrs := []slog.Attr{
		slog.Int64("uptime_s", int64(time.Since(started).Seconds())),
		slog.Any("counters", counters),
	}
	if s.Extra != nil {
		attrs = append(attrs, s.Extra()...)
	}
	s.Logger.LogAttrs(ctx, slog.LevelInfo, "status", attrs...)
}

// Run emits a status line at once, then every Interval, until ctx ends.
func (s *Status) Run(ctx context.Context) {
	s.mu.Lock()
	s.started = time.Now()
	s.mu.Unlock()
	s.Emit(ctx)
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Emit(ctx)
		}
	}
}
