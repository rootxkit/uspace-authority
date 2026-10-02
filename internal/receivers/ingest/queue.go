package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// Names on the bus (docs/PLAN.md §6). The stream and the storage
// subjects are provisioned by internal/bus and consumed by tsdb-writer
// (WP-9); EnsureQueue tolerates running before api's bus.Ensure.
const (
	QueueStream     = bus.StreamINGEST
	QueueSubjectAll = bus.SubjectIngestAll
	QueueConsumer   = "rid-ingest"
	// RowsSubject carries rid_observations rows to tsdb-writer.
	RowsSubject = "tsw.v1.rid_observations"
	// GapsSubject carries writer_gaps records to tsdb-writer.
	GapsSubject = "tsw.v1.writer_gaps"
	// RowsTable is the table of every row and gap record here.
	RowsTable = "rid_observations"
)

// QueueSubject is the work-queue subject of a batch from cell3.
func QueueSubject(cell3 string) string { return "ingest.v1." + cell3 }

// Errors of Enqueue.
var (
	// ErrQueueFull: the stream refused the batch at its hard bound (the
	// consumer is not shedding fast enough); 503, the receiver retries.
	ErrQueueFull = errors.New("ingest queue full")
	// ErrQueueUnavailable: the bus did not confirm the write; 503.
	ErrQueueUnavailable = errors.New("ingest queue unavailable")
)

// Enqueuer writes a batch durably; nil means JetStream acknowledged it.
type Enqueuer interface {
	Enqueue(ctx context.Context, b *ridpipe.Batch) error
}

// QueueConfig bounds the work queue.
type QueueConfig struct {
	// MaxBatches is the depth beyond which the consumer sheds the oldest
	// undelivered batch with a gap record (05 §5: never the newest).
	MaxBatches int
	// MaxAge is the age beyond which a queued batch is shed with a gap
	// record (the 10-minute bound of the work queue).
	MaxAge time.Duration
	// MaxAckPending bounds the batches delivered and not yet settled.
	MaxAckPending int
	// PublishTimeout bounds one queue write.
	PublishTimeout time.Duration
}

// HardMaxBatches is the stream bound this queue needs (discard new,
// BUS_INGEST_MAX_MSGS): the shedding bound plus the batches in flight,
// doubled. Reaching it means the consumer is not running, and the
// receiver is told 503 rather than any batch being dropped silently. A
// stream provisioned with less is reported at start (CheckBound).
func (c QueueConfig) HardMaxBatches() int64 { return int64(2 * (c.MaxBatches + c.MaxAckPending)) }

// JetQueue is the INGEST work queue on JetStream.
type JetQueue struct {
	JS     jetstream.JetStream
	Config QueueConfig
	// Stream is INGEST as internal/bus provisions it.
	Stream jetstream.StreamConfig
}

// EnsureQueue opens the INGEST stream (creating it from the bus topology
// when api has not yet) and the durable pull consumer. JetStream's own
// age limit is not used: a message it ages out would be lost without a
// record, so the consumer sheds by age instead.
func (q *JetQueue) EnsureQueue(ctx context.Context) (jetstream.Consumer, error) {
	s, err := bus.OpenStream(ctx, q.JS, q.Stream)
	if err != nil {
		return nil, err
	}
	return bus.PullConsumer(ctx, s, bus.PullSpec{
		Durable: QueueConsumer, FilterSubject: QueueSubjectAll, MaxAckPending: q.Config.MaxAckPending,
		AckWait: 30 * time.Second,
	})
}

// CheckBound reports whether the stream's hard bound leaves room for the
// shedding bound and the batches in flight; when it does not, receivers
// are told 503 queue_full before the consumer sheds anything.
func (q *JetQueue) CheckBound(ctx context.Context) (have, want int64, ok bool, err error) {
	s, err := bus.OpenStream(ctx, q.JS, q.Stream)
	if err != nil {
		return 0, 0, false, err
	}
	have, want = s.CachedInfo().Config.MaxMsgs, q.Config.HardMaxBatches()
	return have, want, have <= 0 || have >= want, nil
}

// Enqueue writes b to ingest.v1.<cell3> and returns after JetStream's
// acknowledgement (B-05). The message id is the batch id, so a retried
// write inside the stream's duplicate window is stored once.
func (q *JetQueue) Enqueue(ctx context.Context, b *ridpipe.Batch) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	msg := nats.NewMsg(QueueSubject(b.Cell3))
	msg.Data = data
	msg.Header.Set(jetstream.MsgIDHeader, b.ID)
	ctx, cancel := context.WithTimeout(ctx, q.Config.PublishTimeout)
	defer cancel()
	if _, err := q.JS.PublishMsg(ctx, msg); err != nil {
		var apiErr *jetstream.APIError
		if errors.As(err, &apiErr) && (apiErr.ErrorCode == 10077 || strings.Contains(apiErr.Description, "maximum")) {
			return fmt.Errorf("%w: %w", ErrQueueFull, err)
		}
		return fmt.Errorf("%w: %w", ErrQueueUnavailable, err)
	}
	return nil
}
