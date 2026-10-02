package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// RowStore hands rows and gap records to tsdb-writer (tsw.v1.*); nil means
// JetStream acknowledged them.
type RowStore interface {
	PutRows(ctx context.Context, b *ridpipe.Batch) error
	PutGap(ctx context.Context, g Gap) error
}

// RowsMessage is the tsw.v1.rid_observations message: one batch's rows.
type RowsMessage struct {
	Table string        `json:"table"`
	Rows  []ridpipe.Row `json:"rows"`
}

// Gap is one writer_gaps record (WP-9's table): queued observations shed
// before they were stored, with the cause, never silently (B-13).
type Gap struct {
	Table      string    `json:"table"`
	FromSeq    uint64    `json:"from_seq"`
	ToSeq      uint64    `json:"to_seq"`
	Cause      string    `json:"cause"`
	Count      int       `json:"count"`
	At         time.Time `json:"at"`
	ReceiverID string    `json:"receiver_id,omitempty"`
}

// Gap causes.
const (
	CauseQueueFull    = "ingest_queue_full"
	CauseQueueAge     = "ingest_queue_age"
	CauseQueueCorrupt = "ingest_queue_corrupt"
)

// JetRows publishes rows and gaps to the TSW stream.
type JetRows struct {
	JS      jetstream.JetStream
	Timeout time.Duration
}

func (s JetRows) publish(ctx context.Context, subject, msgID string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	msg := nats.NewMsg(subject)
	msg.Data = data
	if msgID != "" {
		msg.Header.Set(jetstream.MsgIDHeader, msgID)
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	_, err = s.JS.PublishMsg(ctx, msg)
	return err
}

// PutRows publishes b's rows under the batch id (a redelivered batch is
// stored once within the stream's duplicate window; WP-9 dedupes beyond).
func (s JetRows) PutRows(ctx context.Context, b *ridpipe.Batch) error {
	return s.publish(ctx, RowsSubject, "rows:"+b.ID, RowsMessage{Table: RowsTable, Rows: b.Rows})
}

// PutGap publishes one gap record.
func (s JetRows) PutGap(ctx context.Context, g Gap) error {
	return s.publish(ctx, GapsSubject, fmt.Sprintf("gap:%s:%d:%d", g.Cause, g.FromSeq, g.ToSeq), g)
}

// Counter names of the worker (E-09).
const (
	CounterRowsStored         = "rows_handed_to_writer"
	CounterBatchesStored      = "batches_handed_to_writer"
	CounterStorageUnavailable = "storage_unavailable"
	CounterShedFull           = "queue_shed_full_batches"
	CounterShedAge            = "queue_shed_age_batches"
	CounterShedObservations   = "queue_shed_observations"
	CounterQueueCorrupt       = "queue_corrupt_messages"
	CounterSinkFailed         = "sink_failed"
	CounterSinkPanicked       = "sink_panicked"
	CounterGapsRecorded       = "gap_records_written"
	CounterGapsDropped        = "gap_records_dropped"
	CounterAckFailed          = "queue_ack_failed"
)

// QueueMsg is what the worker needs of a delivered queue message (the
// jetstream.Msg subset, so tests can drive the worker without a server).
type QueueMsg interface {
	Data() []byte
	Metadata() (*jetstream.MsgMetadata, error)
	Ack() error
	NakWithDelay(delay time.Duration) error
	Term() error
}

// Worker drains the work queue: each batch is shed with a gap record when
// the queue is deeper than MaxBatches behind it or older than MaxAge
// (oldest first, never the newest, 05 §5), otherwise handed once to the
// Sink, then its rows to tsdb-writer, then acknowledged. A batch whose
// rows cannot be handed over waits in the queue and is retried (SC-18).
type Worker struct {
	Sink     ridpipe.Sink
	Store    RowStore
	Config   QueueConfig
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	Now      func() time.Time
	// Retry is the delay before a batch whose rows were not handed over
	// is delivered again.
	Retry time.Duration
	// OnShed and OnStored report per receiver (status lines).
	OnShed   func(receiverID string, observations int)
	OnStored func(receiverID string, observations int)

	mu      sync.Mutex
	sunk    map[string]*ridpipe.Batch // batch id -> decoded batch awaiting storage
	pending []Gap
	depth   uint64
}

// maxPendingGaps bounds the gap records held while storage is down; beyond
// it records of one cause are merged, so the count is never lost (E-10).
const maxPendingGaps = 1024

func (w *Worker) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Depth is the last queue depth seen (undelivered batches behind the
// newest delivery).
func (w *Worker) Depth() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.depth
}

// PendingGaps is the number of gap records not yet handed over.
func (w *Worker) PendingGaps() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pending)
}

func (w *Worker) addGap(g Gap) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) >= maxPendingGaps {
		last := &w.pending[len(w.pending)-1]
		last.Count += g.Count
		if g.ToSeq > last.ToSeq {
			last.ToSeq = g.ToSeq
		}
		if g.FromSeq < last.FromSeq {
			last.FromSeq = g.FromSeq
		}
		last.ReceiverID = ""
		w.Counters.Inc(CounterGapsDropped)
		return
	}
	w.pending = append(w.pending, g)
}

// flushGaps hands the held gap records over, oldest first.
func (w *Worker) flushGaps(ctx context.Context) {
	for {
		w.mu.Lock()
		if len(w.pending) == 0 {
			w.mu.Unlock()
			return
		}
		g := w.pending[0]
		w.mu.Unlock()
		if err := w.Store.PutGap(ctx, g); err != nil {
			return
		}
		w.mu.Lock()
		w.pending = w.pending[1:]
		w.mu.Unlock()
		w.Counters.Inc(CounterGapsRecorded)
	}
}

func (w *Worker) shed(msg QueueMsg, meta *jetstream.MsgMetadata, b *ridpipe.Batch, cause, counter string) {
	n := len(b.Rows)
	w.Counters.Inc(counter)
	w.Counters.Add(CounterShedObservations, uint64(n))
	w.addGap(Gap{Table: RowsTable, FromSeq: meta.Sequence.Stream, ToSeq: meta.Sequence.Stream, Cause: cause, Count: n,
		At: w.now().UTC(), ReceiverID: b.ReceiverID})
	w.Limiter.Limited("ingest_shed:"+cause).Warn("queued batch shed with a gap record",
		slog.String("cause", cause), slog.String("receiver_id", b.ReceiverID), slog.Int("observations", n),
		slog.Uint64("stream_seq", meta.Sequence.Stream))
	if w.OnShed != nil {
		w.OnShed(b.ReceiverID, n)
	}
	w.forget(b.ID)
	if err := msg.Term(); err != nil {
		w.Counters.Inc(CounterAckFailed)
	}
}

func (w *Worker) forget(id string) {
	w.mu.Lock()
	delete(w.sunk, id)
	w.mu.Unlock()
}

// observe hands b to the Sink once; a redelivery reuses the decoded batch.
func (w *Worker) observe(ctx context.Context, b *ridpipe.Batch) *ridpipe.Batch {
	w.mu.Lock()
	if w.sunk == nil {
		w.sunk = map[string]*ridpipe.Batch{}
	}
	if done, ok := w.sunk[b.ID]; ok {
		w.mu.Unlock()
		return done
	}
	w.mu.Unlock()
	func() {
		defer func() {
			if r := recover(); r != nil {
				w.Counters.Inc(CounterSinkPanicked)
				w.Limiter.Limited("ingest_sink_panic").Error("the decode pipeline panicked; the raw rows are stored",
					slog.String("receiver_id", b.ReceiverID), slog.String("panic", fmt.Sprint(r)))
			}
		}()
		if err := w.Sink.Observe(ctx, b); err != nil {
			w.Counters.Inc(CounterSinkFailed)
			w.Limiter.Limited("ingest_sink_failed").Warn("the decode pipeline refused a batch; the raw rows are stored",
				slog.String("receiver_id", b.ReceiverID), slog.String("error", err.Error()))
		}
	}()
	w.mu.Lock()
	// Bounded by MaxAckPending: an entry leaves when its batch is stored
	// or shed; a batch redelivered to another replica is decoded there.
	if len(w.sunk) < 4*w.Config.MaxAckPending {
		w.sunk[b.ID] = b
	}
	w.mu.Unlock()
	return b
}

// Handle settles one delivered queue message.
func (w *Worker) Handle(ctx context.Context, msg QueueMsg) {
	meta, err := msg.Metadata()
	if err != nil {
		w.Counters.Inc(CounterQueueCorrupt)
		_ = msg.Term()
		return
	}
	w.mu.Lock()
	w.depth = meta.NumPending
	w.mu.Unlock()
	var b ridpipe.Batch
	if err := json.Unmarshal(msg.Data(), &b); err != nil || b.ID == "" {
		w.Counters.Inc(CounterQueueCorrupt)
		w.addGap(Gap{Table: RowsTable, FromSeq: meta.Sequence.Stream, ToSeq: meta.Sequence.Stream, Cause: CauseQueueCorrupt,
			At: w.now().UTC()})
		_ = msg.Term()
		return
	}
	switch {
	case meta.NumPending >= uint64(w.Config.MaxBatches):
		w.shed(msg, meta, &b, CauseQueueFull, CounterShedFull)
		return
	case w.now().Sub(meta.Timestamp) > w.Config.MaxAge:
		w.shed(msg, meta, &b, CauseQueueAge, CounterShedAge)
		return
	}
	done := w.observe(ctx, &b)
	if err := w.Store.PutRows(ctx, done); err != nil {
		w.Counters.Inc(CounterStorageUnavailable)
		w.Limiter.Limited("ingest_storage").Warn("rows not handed to tsdb-writer; the batch waits in the queue",
			slog.String("receiver_id", b.ReceiverID), slog.String("error", err.Error()))
		if err := msg.NakWithDelay(w.Retry); err != nil {
			w.Counters.Inc(CounterAckFailed)
		}
		return
	}
	if err := msg.Ack(); err != nil {
		// The rows are handed over; a redelivery is stored once by the
		// message id and the writer's dedupe key.
		w.Counters.Inc(CounterAckFailed)
	}
	w.forget(b.ID)
	w.Counters.Inc(CounterBatchesStored)
	w.Counters.Add(CounterRowsStored, uint64(len(done.Rows)))
	if w.OnStored != nil {
		w.OnStored(b.ReceiverID, len(done.Rows))
	}
	w.flushGaps(ctx)
}

// Run pulls from the consumer until ctx ends. ensure provisions the stream
// and consumer; it is retried until it succeeds, so the worker starts
// degraded with the bus down (B-08).
func (w *Worker) Run(ctx context.Context, ensure func(context.Context) (jetstream.Consumer, error)) {
	var cons jetstream.Consumer
	for ctx.Err() == nil {
		if cons == nil {
			c, err := ensure(ctx)
			if err != nil {
				w.Limiter.Limited("ingest_queue_ensure").Warn("work queue unavailable; receivers are refused with 503 until it returns",
					slog.String("error", err.Error()))
				sleep(ctx, time.Second)
				continue
			}
			cons = c
		}
		batch, err := cons.Fetch(64, jetstream.FetchMaxWait(time.Second))
		if err != nil {
			if ctx.Err() == nil {
				w.Limiter.Limited("ingest_queue_fetch").Warn("work queue fetch failed", slog.String("error", err.Error()))
				cons = nil
				sleep(ctx, time.Second)
			}
			continue
		}
		for m := range batch.Messages() {
			w.Handle(ctx, m)
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && ctx.Err() == nil {
			w.Limiter.Limited("ingest_queue_fetch").Warn("work queue fetch ended", slog.String("error", err.Error()))
		}
		w.flushGaps(ctx)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
