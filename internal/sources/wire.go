package sources

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

// Bucket is the source-control bucket of a process's bus.
func Bucket(bp *bus.Process) jetstream.KeyValueConfig {
	cfg, _ := bp.Topology.Bucket(bp.Limits.SourceControlBucket)
	return cfg
}

// Source is where a follower reads the state.
type Source struct {
	// Open returns the bucket.
	Open func(ctx context.Context) (jetstream.KeyValue, error)
	// Conn and Subject are the push; a nil Conn has none.
	Conn    *nats.Conn
	Subject string
	// Timeout bounds one read.
	Timeout time.Duration
}

// SourceOf is the source of a process's bus under c.
func SourceOf(bp *bus.Process, c config.Bus) Source {
	cfg := Bucket(bp)
	return Source{
		Open:    func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, bp.JS, cfg) },
		Conn:    bp.NC,
		Subject: c.SourceControlSubject,
		Timeout: time.Duration(c.NATSTimeoutMS) * time.Millisecond,
	}
}

// Read reads the stored document; published is false when nothing has
// been published yet (every source enabled).
func (s Source) Read(ctx context.Context) (raw []byte, published bool, err error) {
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	kv, err := s.Open(ctx)
	if err != nil {
		return nil, false, err
	}
	e, err := kv.Get(ctx, StateKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return e.Value(), true, nil
}

// Options configure Start.
type Options struct {
	Source Source
	// Attempts and Backoff bound the read at start (NATS_START_ATTEMPTS,
	// NATS_START_BACKOFF_MS; the backoff doubles).
	Attempts int
	Backoff  time.Duration
	// Reread is the periodic re-read (SOURCE_CONTROL_REREAD_S).
	Reread  time.Duration
	Logger  *slog.Logger
	Limiter *logging.Limiter
}

// OptionsOf are the options of a process's bus under c.
func OptionsOf(bp *bus.Process, c config.Bus, logger *slog.Logger, lim *logging.Limiter) Options {
	return Options{
		Source: SourceOf(bp, c), Attempts: c.NATSStartAttempts, Backoff: time.Duration(c.NATSStartBackoffMS) * time.Millisecond,
		Reread: time.Duration(c.SourceControlRereadS) * time.Second, Logger: logger, Limiter: lim,
	}
}

func (o Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return logging.Discard()
}

// reload reads the stored state and applies it; a failure keeps the
// state held, counted and logged at a bounded rate (E-09).
func (f *Follower) reload(ctx context.Context, o Options) error {
	raw, published, err := o.Source.Read(ctx)
	switch {
	case err != nil:
		f.counters.Inc(CounterReadFailed)
		return err
	case !published:
		f.counters.Inc(CounterNotPublished)
		return nil
	}
	f.Offer(raw)
	return nil
}

// Start returns a follower that has read the state, and the loop that
// keeps it current (the KV watch, the push subject and the re-read),
// which the caller runs until its context ends.
//
// The read at start is tried Attempts times with a doubling backoff.
// When every attempt fails the follower starts anyway with every source
// enabled and says that the switch state is unknown (B-09, SC-08 step
// 8); it applies the state as soon as it can be read.
func Start(ctx context.Context, o Options) (*Follower, func(context.Context)) {
	f := NewFollower()
	logger := o.logger()
	attempts, backoff := max(o.Attempts, 1), o.Backoff
	var err error
	for i := 1; i <= attempts; i++ {
		if err = f.reload(ctx, o); err == nil {
			break
		}
		if i < attempts {
			logger.Warn("source-control state not readable; retrying", slog.Int("attempt", i), slog.Int("attempts", attempts),
				slog.Duration("backoff", backoff), slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				i = attempts
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	switch {
	case err != nil:
		logger.Warn("source-control state unknown: every source is enabled until it can be read (B-09)",
			slog.Int("attempts", attempts), slog.String("error", err.Error()))
	case !f.Known():
		logger.Info("no source-control state published yet: every source is enabled")
	default:
		logger.Info("source-control state applied", f.StatusAttrsAny()...)
	}
	run := func(ctx context.Context) {
		bus.Follow{
			Open: o.Source.Open, Key: StateKey, Conn: o.Source.Conn, Subject: o.Source.Subject,
			OnValue: func(raw []byte) { f.Offer(raw) },
			Reload: func(ctx context.Context) {
				if err := f.reload(ctx, o); err != nil && ctx.Err() == nil && o.Limiter != nil {
					o.Limiter.Limited("source_control_read").Warn("source-control state not re-read; keeping the state held",
						slog.String("error", err.Error()))
				}
			},
			Reread: o.Reread, Logger: logger,
		}.Run(ctx)
	}
	return f, run
}

// StatusAttrsAny is StatusAttrs as log arguments.
func (f *Follower) StatusAttrsAny() []any {
	attrs := f.StatusAttrs()
	out := make([]any, len(attrs))
	for i, a := range attrs {
		out[i] = a
	}
	return out
}

// Attach puts the follower's counters and state on rt's status line and
// /metrics.
func Attach(rt *proc.Runtime, f *Follower) {
	rt.AddCounters("source_control", f.CoreCounters())
	rt.AddCounters("source_control_reads", f.Counters())
	rt.AddStatus(f.StatusAttrs)
}

// Follow is the whole wiring of a process: Start with the process's bus
// and configuration, attached to rt; the returned loop runs until ctx
// ends.
func Follow(ctx context.Context, rt *proc.Runtime, bp *bus.Process, c config.Bus) (*Follower, func(context.Context)) {
	f, run := Start(ctx, OptionsOf(bp, c, rt.Logger, rt.Limiter))
	Attach(rt, f)
	return f, run
}

// Idle is the body of a process whose adapter has not landed yet: it
// connects to the bus, follows source control (every process does) and
// waits for the signal.
func Idle(name, owner string, natsURL string, c config.Bus) func(context.Context, *proc.Runtime) error {
	return func(ctx context.Context, rt *proc.Runtime) error {
		bp, err := bus.OpenProcess(ctx, natsURL, c, name, "", rt.Logger)
		if err != nil {
			return err
		}
		defer bp.Close()
		rt.AddStatus(bus.StatusAttrs(bp.NC))
		_, run := Follow(ctx, rt, bp, c)
		done := make(chan struct{})
		go func() { defer close(done); run(ctx) }()
		defer func() { <-done }()
		return proc.Idle(owner)(ctx, rt)
	}
}
