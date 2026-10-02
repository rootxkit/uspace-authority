package ts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// GapsTable is the token of tsw.v1.writer_gaps, the subject gap records
// travel on.
const GapsTable = "writer_gaps"

// RowsMessage is a tsw.v1.<table> message (schemas/tsw/rows/v1.json):
// the rows of one table, each a JSON object whose members are the
// table's column names. Producers fill Rows with any slice that
// marshals so (ridpipe.Row); the writer reads RawRows.
type RowsMessage struct {
	Table string `json:"table"`
	Rows  any    `json:"rows"`
}

// RowsMessageIn is a RowsMessage as the writer reads it.
type RowsMessageIn struct {
	Table string            `json:"table"`
	Rows  []json.RawMessage `json:"rows"`
}

// GapMessage is a tsw.v1.writer_gaps message (schemas/tsw/gap/v1.json):
// a hole a producer knows of, recorded by tsdb-writer in writer_gaps.
// rid-ingest's records (WP-7) carry no stream and count rows: they
// number the INGEST stream.
type GapMessage struct {
	Table      string    `json:"table"`
	FromSeq    uint64    `json:"from_seq"`
	ToSeq      uint64    `json:"to_seq"`
	Cause      string    `json:"cause"`
	Count      int64     `json:"count"`
	At         time.Time `json:"at"`
	ReceiverID string    `json:"receiver_id,omitempty"`
	Stream     string    `json:"stream,omitempty"`
	CountUnit  string    `json:"count_unit,omitempty"`
	Detail     string    `json:"detail,omitempty"`
}

// DefaultGapStream is the stream a GapMessage without one numbers.
const DefaultGapStream = bus.StreamINGEST

// Writer is how an adapter hands rows to tsdb-writer (docs/PLAN.md §2):
// it publishes to tsw.v1.<table> and returns once JetStream has the
// message; the adapter never opens the database. A nil error means the
// rows are durable in the TSW stream, from which tsdb-writer writes them
// once (by the message id within the stream's duplicate window, and by
// the table's dedupe key beyond it).
type Writer interface {
	// Enqueue publishes rows (a slice of values that marshal to JSON
	// objects keyed by column name) for table, under msgID when it is
	// not empty.
	Enqueue(ctx context.Context, table string, rows any, msgID string) error
	// EnqueueGap publishes a hole the adapter knows of (B-13).
	EnqueueGap(ctx context.Context, g GapMessage, msgID string) error
}

// Errors of BusWriter.
var (
	// ErrUnknownTable: table is not one tsdb-writer writes.
	ErrUnknownTable = errors.New("not a table tsdb-writer writes")
	// ErrTooLarge: the message exceeds bus.MaxPayloadBytes; the caller
	// splits its rows (E-10).
	ErrTooLarge = errors.New("rows message exceeds the TSW stream's maximum message size")
)

// BusWriter is the Writer on JetStream.
type BusWriter struct {
	JS jetstream.JetStream
	// Timeout bounds one publish.
	Timeout time.Duration
}

var _ Writer = BusWriter{}

// Enqueue implements Writer.
func (b BusWriter) Enqueue(ctx context.Context, table string, rows any, msgID string) error {
	if _, ok := Tables[table]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownTable, table)
	}
	data, err := json.Marshal(RowsMessage{Table: table, Rows: rows})
	if err != nil {
		return core.Fieldf("rows", "not JSON: %v", err)
	}
	var probe RowsMessageIn
	if err := json.Unmarshal(data, &probe); err != nil {
		return &core.FieldError{Field: "rows", Reason: "not an array of objects"}
	}
	return b.publish(ctx, table, data, msgID)
}

// EnqueueGap implements Writer.
func (b BusWriter) EnqueueGap(ctx context.Context, g GapMessage, msgID string) error {
	data, err := json.Marshal(g)
	if err != nil {
		return err
	}
	return b.publish(ctx, GapsTable, data, msgID)
}

func (b BusWriter) publish(ctx context.Context, table string, data []byte, msgID string) error {
	if len(data) > bus.MaxPayloadBytes {
		return fmt.Errorf("%w (%d > %d bytes)", ErrTooLarge, len(data), bus.MaxPayloadBytes)
	}
	subject, err := bus.Subjects.Tsw(table)
	if err != nil {
		return err
	}
	msg := nats.NewMsg(subject)
	msg.Data = data
	if msgID != "" {
		msg.Header.Set(jetstream.MsgIDHeader, msgID)
	}
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
		defer cancel()
	}
	if _, err := b.JS.PublishMsg(ctx, msg); err != nil {
		return fmt.Errorf("hand rows to tsdb-writer (%s): %w", subject, err)
	}
	return nil
}
