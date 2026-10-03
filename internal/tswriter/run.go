package tswriter

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// ConsumerPrefix names each table's durable consumer:
// tsdb-writer-<table>.
const ConsumerPrefix = "tsdb-writer-"

// ErrDatabaseUnavailable is every write's error until the writer pool
// opens.
var ErrDatabaseUnavailable = errors.New("telemetry database not connected yet")

// Options are what Run takes beyond the configuration (tests).
type Options struct {
	// Tables overrides ts.Tables.
	Tables []ts.Table
	// RetentionChecks overrides RetentionChecks.
	RetentionChecks []RetentionCheck
	// DatabaseRetry is the wait between attempts to open the writer
	// pool (default 2 s).
	DatabaseRetry time.Duration
}

// LazyStore is the writer pool, opened in the background: tsdb-writer
// starts with the database down and says so (B-08, E-02); until the pool
// opens every write fails and is retried, and the rows wait in
// JetStream.
type LazyStore struct {
	mu   sync.Mutex
	pool *ts.WriterPool
}

func (l *LazyStore) get() *ts.WriterPool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pool
}

// Write implements Store.
func (l *LazyStore) Write(ctx context.Context, parts ...ts.Part) ([]ts.Written, error) {
	p := l.get()
	if p == nil {
		return nil, ErrDatabaseUnavailable
	}
	return p.Write(ctx, parts...)
}

// Position implements Store.
func (l *LazyStore) Position(ctx context.Context, table, stream string) (uint64, bool, error) {
	p := l.get()
	if p == nil {
		return 0, false, ErrDatabaseUnavailable
	}
	return p.Position(ctx, table, stream)
}

// OlderThan implements OlderThaner.
func (l *LazyStore) OlderThan(ctx context.Context, table, column string, age time.Duration) (int64, error) {
	p := l.get()
	if p == nil {
		return 0, ErrDatabaseUnavailable
	}
	return p.OlderThan(ctx, table, column, age)
}

// Ready is the readiness check of the database.
func (l *LazyStore) Ready(ctx context.Context) error {
	p := l.get()
	if p == nil {
		return ErrDatabaseUnavailable
	}
	return p.Ping(ctx)
}

// Close closes the pool when it is open.
func (l *LazyStore) Close() {
	if p := l.get(); p != nil {
		p.Close()
	}
}

// Open opens the pool, retrying every wait until it opens or ctx ends.
// A schema older than this build is returned at once: no retry mends it
// (D7).
func (l *LazyStore) Open(ctx context.Context, o store.PoolOptions, wait time.Duration, logger *slog.Logger, lim *logging.Limiter) error {
	first := true
	for ctx.Err() == nil {
		p, err := ts.OpenWriterPool(ctx, o)
		if err == nil {
			l.mu.Lock()
			l.pool = p
			l.mu.Unlock()
			logger.Info("telemetry database connected", slog.String("role", ts.WriterRole))
			return nil
		}
		if store.IsSchemaError(err) {
			return err
		}
		if first {
			logger.Warn("telemetry database unavailable at start: writes are retried and rows wait in JetStream",
				slog.String("error", err.Error()))
			first = false
		} else {
			lim.Limited("tsw_database_open").Warn("telemetry database still unavailable", slog.String("error", err.Error()))
		}
		sleep(ctx, wait)
	}
	return nil
}

// PipelineConfig is the pipeline configuration of cfg.
func PipelineConfig(t config.TSDBWriterTuning) Config {
	return Config{
		BatchMaxRows: t.BatchMaxRows, BatchMaxWait: time.Duration(t.BatchMaxWaitMS) * time.Millisecond,
		QueueMaxRows: t.QueueMaxRows, QueueMaxAge: time.Duration(t.QueueMaxAgeS) * time.Second,
		FetchMax: t.FetchMax, FetchWait: 200 * time.Millisecond,
		WriteTimeout: time.Duration(t.WriteTimeoutS) * time.Second,
		RetryMin:     time.Duration(t.RetryMinMS) * time.Millisecond, RetryMax: time.Duration(t.RetryMaxMS) * time.Millisecond,
		AckWait: time.Duration(t.AckWaitS) * time.Second,
	}
}

// Status is the writer on the status line: the overall state (ok,
// spilling when any table is, else write_failing when any table is),
// each table, and each retention result.
func Status(pipes []*Pipeline, ret *Retention) func() []slog.Attr {
	return func() []slog.Attr {
		state := StateOK
		tables := make([]Snapshot, 0, len(pipes))
		var unrecorded uint64
		for _, p := range pipes {
			s := p.Snapshot()
			tables = append(tables, s)
			unrecorded += s.RejectedUnrecorded
			switch {
			case s.State == StateSpilling:
				state = StateSpilling
			case s.State == StateWriteFailing && state == StateOK:
				state = StateWriteFailing
			}
		}
		attrs := []slog.Attr{slog.String("writer_state", state), slog.Any("tables", tables)}
		if ret != nil {
			attrs = append(attrs, slog.Any("retention", ret.Last()))
		}
		if unrecorded > 0 {
			attrs = append(attrs, slog.Uint64("rejected_unrecorded", unrecorded))
		}
		return attrs
	}
}

// StatusLevel is error once a hole has no record (rejected_unrecorded),
// so it is seen before it scrolls away (audit B-S9).
func StatusLevel(pipes []*Pipeline) func() slog.Level {
	return func() slog.Level {
		for _, p := range pipes {
			if p.Snapshot().RejectedUnrecorded > 0 {
				return slog.LevelError
			}
		}
		return slog.LevelInfo
	}
}

// Run is tsdb-writer's process body.
func Run(ctx context.Context, rt *proc.Runtime, cfg *config.TSDBWriter, o Options) error {
	bp, err := bus.OpenProcess(ctx, cfg.NATSURL, cfg.Bus, "tsdb-writer", "", rt.Logger)
	if err != nil {
		return err
	}
	defer bp.Close()
	rt.Ready.Add("nats", bus.Ready(bp.NC))
	rt.AddStatus(bus.StatusAttrs(bp.NC))
	_, followSources := sources.Follow(ctx, rt, bp, cfg.Bus)

	counters := &core.Counters{}
	rt.AddCounters("tsdb_writer", counters)
	t := cfg.TSDBWriterTuning
	db := &LazyStore{}
	defer db.Close()
	rt.Ready.Add("timescaledb", db.Ready)

	tables := o.Tables
	if tables == nil {
		for _, tb := range ts.Tables {
			tables = append(tables, tb)
		}
		slices.SortFunc(tables, func(a, b ts.Table) int {
			switch {
			case a.Name < b.Name:
				return -1
			case a.Name > b.Name:
				return 1
			}
			return 0
		})
	}
	streamCfg, _ := bp.Topology.Stream(bus.StreamTSW)
	pcfg := PipelineConfig(t)
	source := func(table string) *JetSource {
		return &JetSource{MaxDeletedDetails: 100000, Open: func(ctx context.Context) (jetstream.Stream, jetstream.Consumer, error) {
			s, err := bus.OpenStream(ctx, bp.JS, streamCfg)
			if err != nil {
				return nil, nil, err
			}
			subject, err := bus.Subjects.Tsw(table)
			if err != nil {
				return nil, nil, err
			}
			c, err := bus.PullConsumer(ctx, s, bus.PullSpec{
				Durable: ConsumerPrefix + table, FilterSubject: subject, MaxAckPending: t.MaxAckPending,
				AckWait: time.Duration(t.AckWaitS) * time.Second,
			})
			return s, c, err
		}}
	}
	pipe := func(tb ts.Table, dec Decoder) *Pipeline {
		return &Pipeline{
			Table: tb, Decode: dec, Source: source(tb.Name), Store: db, Config: pcfg,
			Counters: counters, Logger: rt.Logger, Limiter: rt.Limiter,
		}
	}
	pipes := make([]*Pipeline, 0, len(tables)+1)
	names := make([]string, 0, len(tables)+1)
	for _, tb := range tables {
		pipes = append(pipes, pipe(tb, RowsDecoder(tb)))
		names = append(names, tb.Name)
	}
	pipes = append(pipes, pipe(ts.WriterGaps, GapsDecoder))
	names = append(names, ts.WriterGaps.Name)

	checks := o.RetentionChecks
	if checks == nil {
		checks = RetentionChecks
	}
	ret := &Retention{Store: db, Checks: checks, Interval: time.Duration(t.RetentionCheckS) * time.Second,
		Counters: counters, Logger: rt.Logger}
	rt.AddStatus(Status(pipes, ret))
	rt.AddStatusLevel(StatusLevel(pipes))
	rt.Logger.Info("tsdb-writer consuming", slog.Any("tables", names), slog.Int("batch_max_rows", t.BatchMaxRows),
		slog.Int("queue_max_rows", t.QueueMaxRows), slog.Int("queue_max_age_s", t.QueueMaxAgeS))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() { followSources(ctx) })
	for _, p := range pipes {
		wg.Go(func() { p.Run(ctx) })
	}
	retry := o.DatabaseRetry
	if retry <= 0 {
		retry = 2 * time.Second
	}
	err = db.Open(ctx, store.PoolOptions{
		URL: cfg.TSURL, MaxConns: t.TSMaxConns, StatementTimeout: time.Duration(t.TSStatementTimeoutS) * time.Second,
		ApplicationName: "uspace-authority-tsdb-writer",
	}, retry, rt.Logger, rt.Limiter)
	if err != nil {
		return err
	}
	wg.Go(func() { ret.Run(ctx) })
	<-ctx.Done()
	return nil
}
