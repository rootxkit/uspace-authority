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

	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// Names on the bus (docs/PLAN.md §6). The stream, consumer and storage
// subjects are provisioned by internal/bus (WP-10) and consumed by
// tsdb-writer (WP-9); EnsureQueue tolerates running before them.
const (
	QueueStream     = "INGEST"
	QueueSubjectAll = "ingest.v1.>"
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

// HardMaxBatches is the stream's own limit (discard new): the shedding
// bound plus the batches in flight, doubled. Reaching it means the
// consumer is not running, and the receiver is told 503 rather than any
// batch being dropped silently.
func (c QueueConfig) HardMaxBatches() int64 { return int64(2 * (c.MaxBatches + c.MaxAckPending)) }

// JetQueue is the INGEST work queue on JetStream.
type JetQueue struct {
	JS     jetstream.JetStream
	Config QueueConfig
}

// EnsureQueue creates the INGEST stream and the durable consumer when they
// do not exist and leaves an existing stream's configuration alone (WP-10
// owns it). JetStream's own age limit is not used: a message it ages out
// would be lost without a record, so the consumer sheds by age instead.
func (q *JetQueue) EnsureQueue(ctx context.Context) (jetstream.Consumer, error) {
	s, err := q.JS.Stream(ctx, QueueStream)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		s, err = q.JS.CreateStream(ctx, jetstream.StreamConfig{
			Name: QueueStream, Subjects: []string{QueueSubjectAll}, Retention: jetstream.WorkQueuePolicy,
			Discard: jetstream.DiscardNew, MaxMsgs: q.Config.HardMaxBatches(), MaxMsgSize: 4 * (1 << 20),
			Storage: jetstream.FileStorage, Duplicates: 2 * time.Minute,
			Description: "rid-ingest work queue (WP-7): acknowledged receiver batches awaiting decode and storage",
		})
		if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			s, err = q.JS.Stream(ctx, QueueStream)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("stream %s: %w", QueueStream, err)
	}
	c, err := s.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable: QueueConsumer, FilterSubject: QueueSubjectAll, AckPolicy: jetstream.AckExplicitPolicy,
		AckWait: 30 * time.Second, MaxAckPending: q.Config.MaxAckPending, MaxDeliver: -1,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("consumer %s: %w", QueueConsumer, err)
	}
	return c, nil
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
