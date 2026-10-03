package manned

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// CauseHandOver is the gap cause of rows manned-ingest could not hand
// to tsdb-writer.
const CauseHandOver = "manned_handover_failed"

// Counters of the bus sink (E-09).
const (
	CounterRowsHandedOver = "rows_handed_to_writer"
	CounterRowsRetried    = "rows_handover_retried"
	CounterRowsLost       = "rows_lost_handover_failed"
	CounterRowsShed       = "rows_shed_queue_full"
	CounterGapsRecorded   = "gap_records_written"
	CounterGapsLost       = "gap_records_lost"
)

// rowsPerMessage bounds the rows of one TSW message well under the
// stream's 1 MiB (a row is under 1 KiB).
const rowsPerMessage = 200

// BusSink publishes man.v1 over core NATS and hands rows to tsdb-writer
// (ts.Writer) through a bounded queue drained by one worker, so a slow
// JetStream never holds the stream: each TSW message carries a fixed
// message id and is retried at most Attempts times. Rows that cannot be
// handed over, or that the full queue sheds, are counted, logged at
// error level and recorded as a writer gap (B-13: a gap is never
// silent; the man.v1 messages reached the picture all the same).
type BusSink struct {
	NC        bus.Publisher
	Writer    ts.Writer
	QueueSize int
	Attempts  int
	Backoff   time.Duration
	Counters  *core.Counters
	Logger    *slog.Logger
	Limiter   *logging.Limiter

	once  sync.Once
	queue chan rowBatch
	mu    sync.Mutex
	seq   uint64
}

type rowBatch struct {
	rows []Row
	at   time.Time
}

func (s *BusSink) init() {
	s.once.Do(func() {
		if s.QueueSize <= 0 {
			s.QueueSize = 1024
		}
		s.queue = make(chan rowBatch, s.QueueSize)
		if s.Counters == nil {
			s.Counters = &core.Counters{}
		}
		if s.Logger == nil {
			s.Logger = logging.Discard()
		}
		if s.Limiter == nil {
			s.Limiter = logging.NewLimiter(s.Logger, time.Minute, 0, s.Counters)
		}
		if s.Attempts <= 0 {
			s.Attempts = 3
		}
		if s.Backoff <= 0 {
			s.Backoff = 200 * time.Millisecond
		}
	})
}

// Publish implements Sink.
func (s *BusSink) Publish(p Published) error {
	data, err := json.Marshal(p.Message)
	if err != nil {
		return err
	}
	return s.NC.Publish(p.Subject, data)
}

// Rows implements Sink: queued, never blocking the stream.
func (s *BusSink) Rows(rows []Row) {
	s.init()
	select {
	case s.queue <- rowBatch{rows: rows, at: time.Now()}:
	default:
		s.Counters.Add(CounterRowsShed, uint64(len(rows)))
		s.lost(context.Background(), "queue full", len(rows), time.Now())
	}
}

// Depth is the batches waiting.
func (s *BusSink) Depth() int {
	s.init()
	return len(s.queue)
}

// Run drains the queue until ctx ends.
func (s *BusSink) Run(ctx context.Context) {
	s.init()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-s.queue:
			s.write(ctx, b)
		}
	}
}

func (s *BusSink) nextID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return fmt.Sprintf("manned:%s:%d", bus.NewULID(time.Now()), s.seq)
}

func (s *BusSink) write(ctx context.Context, b rowBatch) {
	lost := 0
	rows := b.rows
	for len(rows) > 0 {
		n := min(len(rows), rowsPerMessage)
		if !s.enqueue(ctx, rows[:n]) {
			lost += n
		}
		rows = rows[n:]
	}
	s.Counters.Add(CounterRowsHandedOver, uint64(len(b.rows)-lost))
	if lost > 0 && ctx.Err() == nil {
		s.Counters.Add(CounterRowsLost, uint64(lost))
		s.lost(ctx, "JetStream unavailable", lost, b.at)
	}
}

func (s *BusSink) enqueue(ctx context.Context, rows []Row) bool {
	if s.Writer == nil {
		return false
	}
	id := s.nextID()
	for attempt := 1; attempt <= s.Attempts && ctx.Err() == nil; attempt++ {
		err := s.Writer.Enqueue(ctx, Table, rows, id)
		if err == nil {
			return true
		}
		if attempt == s.Attempts {
			s.Limiter.Limited("manned_rows_enqueue").Warn("manned rows not handed to tsdb-writer", slog.String("error", err.Error()))
			break
		}
		s.Counters.Inc(CounterRowsRetried)
		select {
		case <-ctx.Done():
		case <-time.After(s.Backoff * time.Duration(attempt)):
		}
	}
	return false
}

func (s *BusSink) lost(ctx context.Context, why string, n int, at time.Time) {
	s.Limiter.Limited("manned_rows_lost").Error("manned rows not handed to tsdb-writer; recorded as a writer gap",
		slog.String("cause", why), slog.Int("rows", n))
	if s.Writer == nil {
		s.Counters.Inc(CounterGapsLost)
		return
	}
	g := ts.GapMessage{Table: Table, Cause: CauseHandOver, Count: int64(n), At: at.UTC(), CountUnit: ts.UnitRows, Detail: why}
	if err := s.Writer.EnqueueGap(context.WithoutCancel(ctx), g, ""); err != nil {
		s.Counters.Inc(CounterGapsLost)
		return
	}
	s.Counters.Inc(CounterGapsRecorded)
}
