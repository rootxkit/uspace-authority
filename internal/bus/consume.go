package bus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
)

// PullSpec is a durable pull consumer with explicit ack and a bounded
// number of messages delivered and not yet acknowledged (05 §5: safety
// consumers read JetStream pull consumers with explicit ack and
// max_ack_pending).
type PullSpec struct {
	Durable       string
	FilterSubject string
	// MaxAckPending is required: an unbounded consumer is refused.
	MaxAckPending int
	AckWait       time.Duration
	// MaxDeliver is the number of deliveries before JetStream gives up;
	// -1 (the default here) never gives up: the consumer decides when a
	// message is shed and records it.
	MaxDeliver int
}

// PullConsumer creates or updates the durable pull consumer spec names on
// s.
func PullConsumer(ctx context.Context, s jetstream.Stream, spec PullSpec) (jetstream.Consumer, error) {
	if spec.MaxAckPending <= 0 {
		return nil, core.Fieldf("max_ack_pending", "consumer %s: must be bounded (> 0)", spec.Durable)
	}
	if spec.AckWait <= 0 {
		spec.AckWait = 30 * time.Second
	}
	if spec.MaxDeliver == 0 {
		spec.MaxDeliver = -1
	}
	c, err := s.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable: spec.Durable, FilterSubject: spec.FilterSubject, AckPolicy: jetstream.AckExplicitPolicy,
		AckWait: spec.AckWait, MaxAckPending: spec.MaxAckPending, MaxDeliver: spec.MaxDeliver,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("consumer %s: %w", spec.Durable, err)
	}
	return c, nil
}

// Follow keeps a reader of a KV bucket current by push then re-read
// (LESSONS G-08, B-09): every update the bucket's watch delivers and
// every message on the push subject is handed over at once, and the
// whole state is re-read every Reread, which repairs a missed push, a
// watch that broke or a bucket that was lost and restored. Each source
// is re-established after a failure.
type Follow struct {
	// Open returns the bucket (OpenBucket or JetStream.KeyValue).
	Open func(ctx context.Context) (jetstream.KeyValue, error)
	// Key is the key watched; empty watches every key.
	Key string
	// Conn and Subject are the push subject; a nil Conn has none.
	Conn    *nats.Conn
	Subject string
	// OnValue takes a value delivered by the watch or the push; when it
	// is nil, and after a delete, Reload is called instead.
	OnValue func(data []byte)
	// Reload re-reads the whole state; it is called every Reread and,
	// when OnValue is nil, after every watch update or push.
	Reload func(ctx context.Context)
	Reread time.Duration
	// Retry is the wait before a broken watch or subscription is
	// re-established (default 1 s).
	Retry  time.Duration
	Logger *slog.Logger
}

// Run follows until ctx ends.
func (f Follow) Run(ctx context.Context) {
	retry := f.Retry
	if retry <= 0 {
		retry = time.Second
	}
	poke := make(chan struct{}, 1)
	// A delete or a purge delivers nil: the reader re-reads rather than
	// take an absence as a state (B-09: never fail closed).
	deliver := func(data []byte) {
		if f.OnValue != nil && data != nil {
			f.OnValue(data)
			return
		}
		select {
		case poke <- struct{}{}:
		default:
		}
	}
	done := make(chan struct{}, 2)
	go func() { defer func() { done <- struct{}{} }(); f.watch(ctx, deliver, retry) }()
	go func() { defer func() { done <- struct{}{} }(); f.push(ctx, deliver, retry) }()
	defer func() { <-done; <-done }()
	reread := f.Reread
	if reread <= 0 {
		reread = time.Minute
	}
	t := time.NewTicker(reread)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poke:
		case <-t.C:
		}
		if f.Reload != nil {
			f.Reload(ctx)
		}
	}
}

func (f Follow) debug(msg string, err error) {
	if f.Logger != nil && err != nil {
		f.Logger.Debug(msg, slog.String("error", err.Error()))
	}
}

func wait(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// watch delivers every update of the bucket (updates only: the reader
// reads the current state itself at start and on Reread).
func (f Follow) watch(ctx context.Context, deliver func([]byte), retry time.Duration) {
	if f.Open == nil {
		return
	}
	for ctx.Err() == nil {
		kv, err := f.Open(ctx)
		if err == nil {
			var w jetstream.KeyWatcher
			if f.Key == "" {
				w, err = kv.WatchAll(ctx, jetstream.UpdatesOnly())
			} else {
				w, err = kv.Watch(ctx, f.Key, jetstream.UpdatesOnly())
			}
			if err == nil {
				for e := range w.Updates() {
					if e != nil && e.Operation() == jetstream.KeyValuePut {
						deliver(e.Value())
					} else if e != nil {
						deliver(nil)
					}
				}
				_ = w.Stop()
			}
		}
		if ctx.Err() == nil {
			f.debug("KV watch unavailable; relying on the push and the periodic re-read", err)
		}
		wait(ctx, retry)
	}
}

// push delivers every message on the push subject.
func (f Follow) push(ctx context.Context, deliver func([]byte), retry time.Duration) {
	if f.Conn == nil || f.Subject == "" {
		return
	}
	for ctx.Err() == nil {
		ch := make(chan *nats.Msg, 64)
		sub, err := f.Conn.ChanSubscribe(f.Subject, ch)
		if err == nil {
			for {
				select {
				case <-ctx.Done():
					_ = sub.Unsubscribe()
					return
				case m := <-ch:
					deliver(m.Data)
				}
			}
		}
		if !errors.Is(err, nats.ErrConnectionClosed) {
			f.debug("push subscription unavailable; relying on the watch and the periodic re-read", err)
		}
		wait(ctx, retry)
	}
}
