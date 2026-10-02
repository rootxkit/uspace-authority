package registry

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// Counters of a ProjectionReader.
const (
	CounterReaderLoaded     = "registry_projection_loaded"      // projection reads applied
	CounterReaderReadFailed = "registry_projection_read_failed" // a read failed; the last snapshot is kept (SC-17 step 6)
)

// DefaultRefresh is the readers' re-read period (G-08: 5 s).
const DefaultRefresh = 5 * time.Second

// Loaded is one whole read of the projection.
type Loaded struct {
	Operators []identify.OperatorFacts
	UAS       []identify.UASFacts
	// Version is the highest registry_version read.
	Version int64
}

// ProjectionSource reads the whole projection.
type ProjectionSource interface {
	LoadProjection(ctx context.Context) (Loaded, error)
}

// TSSource reads the projection tables as authority_ts_reader, in one
// repeatable-read transaction so operators and aircraft are one state.
type TSSource struct {
	R *ts.Reader
}

// LoadProjection reads every projected operator and aircraft.
func (s TSSource) LoadProjection(ctx context.Context) (Loaded, error) {
	var out Loaded
	err := s.R.ReadTx(ctx, func(q *reader.Queries) error {
		ops, err := q.ProjectedOperators(ctx)
		if err != nil {
			return err
		}
		uas, err := q.ProjectedUAS(ctx)
		if err != nil {
			return err
		}
		out = toLoaded(ops, uas)
		return nil
	})
	return out, err
}

// toLoaded maps projection rows onto exactly what identify.NewSnapshot
// takes (identify.OperatorFacts, identify.UASFacts): the judgement on
// them is uspace-core's.
func toLoaded(ops []reader.ProjRegistryOperator, uas []reader.ProjRegistryUAS) Loaded {
	out := Loaded{Operators: make([]identify.OperatorFacts, 0, len(ops)), UAS: make([]identify.UASFacts, 0, len(uas))}
	for _, o := range ops {
		out.Operators = append(out.Operators, identify.OperatorFacts{
			OperatorID: o.OperatorID, RegistrationNumber: o.RegistrationNumberPublic, Status: o.Status,
		})
		out.Version = max(out.Version, o.RegistryVersion)
	}
	for i := range uas {
		u := &uas[i]
		var op *string
		if u.OperatorID != nil {
			id := *u.OperatorID
			op = &id
		}
		out.UAS = append(out.UAS, identify.UASFacts{
			DroneID: u.UasID, Label: u.Label, Serial: u.Serial, RegistrationStatus: u.RegistrationStatus,
			OperatorID: op, InRegistry: u.InRegistry,
		})
		out.Version = max(out.Version, u.RegistryVersion)
	}
	return out
}

// ProjectionReader holds the registry snapshot a resolver judges with
// (G-08): it re-reads the projection every period and when told a new
// version exists, replaces the snapshot whole on a good read, and keeps
// the one it holds when a read fails, so a database hiccup never turns
// every aircraft unknown. Before the first good read Lookup is nil,
// which identify reads as registry_unavailable.
type ProjectionReader struct {
	Source   ProjectionSource
	Counters *core.Counters
	Logger   *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu       sync.RWMutex
	snap     *identify.Snapshot
	loadedAt time.Time
	version  int64
	rows     int

	notifyOnce sync.Once
	notify     chan struct{}
}

func (r *ProjectionReader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *ProjectionReader) notifications() chan struct{} {
	r.notifyOnce.Do(func() { r.notify = make(chan struct{}, 1) })
	return r.notify
}

// Notify says a newer registry version exists (registry.v1.changed);
// Run re-reads at once.
func (r *ProjectionReader) Notify() {
	select {
	case r.notifications() <- struct{}{}:
	default:
	}
}

// Refresh reads the projection once. On success the snapshot is
// replaced; on failure the held snapshot stays and the failure is
// counted and returned.
func (r *ProjectionReader) Refresh(ctx context.Context) error {
	l, err := r.Source.LoadProjection(ctx)
	if err != nil {
		if r.Counters != nil {
			r.Counters.Inc(CounterReaderReadFailed)
		}
		return err
	}
	snap := identify.NewSnapshot(l.Operators, l.UAS)
	r.mu.Lock()
	r.snap, r.loadedAt, r.version, r.rows = snap, r.now(), l.Version, len(l.Operators)+len(l.UAS)
	r.mu.Unlock()
	if r.Counters != nil {
		r.Counters.Inc(CounterReaderLoaded)
	}
	return nil
}

// Run refreshes at once, then every period and on Notify, until ctx
// ends. A failed refresh is logged and the snapshot held is kept.
func (r *ProjectionReader) Run(ctx context.Context, every time.Duration) {
	logger := r.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	refresh := func() {
		if err := r.Refresh(ctx); err != nil && ctx.Err() == nil {
			logging.Error(ctx, logger, "registry projection not read; the snapshot held is kept", err,
				slog.Int64("registry_version", r.Version()))
		}
	}
	refresh()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		case <-r.notifications():
			refresh()
		}
	}
}

// Lookup is the snapshot to resolve against, or nil before the first
// good read (identify treats a nil Lookup as registry_unavailable).
func (r *ProjectionReader) Lookup() identify.Lookup {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.snap == nil {
		return nil
	}
	return r.snap
}

// Version is the highest registry_version of the snapshot held.
func (r *ProjectionReader) Version() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// StatusAttrs are the reader's status-line attributes (E-09): the age of
// the snapshot held, its rows and its version; projection_loaded false
// until the first good read.
func (r *ProjectionReader) StatusAttrs() []slog.Attr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.snap == nil {
		return []slog.Attr{slog.Bool("projection_loaded", false)}
	}
	return []slog.Attr{
		slog.Bool("projection_loaded", true),
		slog.Float64("projection_age_s", r.now().Sub(r.loadedAt).Seconds()),
		slog.Int("projection_rows", r.rows),
		slog.Int64("registry_version", r.version),
	}
}
