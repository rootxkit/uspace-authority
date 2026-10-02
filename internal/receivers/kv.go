package receivers

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
)

// Bucket is the KV bucket of the key set (docs/PLAN.md §6, WP-10's list),
// the default of RID_KEYSET_BUCKET.
const Bucket = "rid_receiver_keys"

// bucketHistory is the history WP-10 gives every bucket.
const bucketHistory = 8

// Connect opens a NATS connection that reconnects for ever and does not
// block or fail when the server is down at start (LESSONS B-08): the
// process starts degraded and says so through the handlers' logs.
// internal/bus (WP-10) replaces this with the per-process credentials.
func Connect(url, name string, logger *slog.Logger) (*nats.Conn, error) {
	return nats.Connect(url,
		nats.Name(name),
		nats.MaxReconnects(-1),
		nats.RetryOnFailedConnect(true),
		nats.ReconnectWait(time.Second),
		nats.ReconnectJitter(500*time.Millisecond, time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Warn("NATS disconnected; reconnecting", slog.String("error", err.Error()))
			}
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			logger.Info("NATS reconnected", slog.String("server", c.ConnectedUrlRedacted()))
		}),
	)
}

// KV is the key set in the NATS KV bucket rid_receiver_keys. Each call is
// bounded by Timeout, so an unreachable bus refuses a change quickly
// (503) instead of hanging the request.
type KV struct {
	JS      jetstream.JetStream
	Bucket  string
	Timeout time.Duration

	mu sync.Mutex
	kv jetstream.KeyValue
}

// NewKV returns the key set in bucket on conn.
func NewKV(conn *nats.Conn, bucket string, timeout time.Duration) (*KV, error) {
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	return &KV{JS: js, Bucket: bucket, Timeout: timeout}, nil
}

var _ KeyStore = (*KV)(nil)

// handle returns the bucket, creating it when it does not exist (WP-10's
// bus.Ensure provisions it; this tolerates running first).
func (k *KV) handle(ctx context.Context) (jetstream.KeyValue, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kv != nil {
		return k.kv, nil
	}
	kv, err := k.JS.KeyValue(ctx, k.Bucket)
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		kv, err = k.JS.CreateKeyValue(ctx, jetstream.KeyValueConfig{
			Bucket: k.Bucket, History: bucketHistory, MaxValueSize: MaxEntryBytes, Storage: jetstream.FileStorage,
			Description: "Remote ID receiver key set (WP-7): receiver id -> bearer hash, HMAC secret, status",
		})
		if errors.Is(err, jetstream.ErrBucketExists) {
			kv, err = k.JS.KeyValue(ctx, k.Bucket)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("key set bucket %s: %w", k.Bucket, err)
	}
	k.kv = kv
	return kv, nil
}

func (k *KV) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, k.Timeout)
}

// Put writes one entry.
func (k *KV) Put(ctx context.Context, e Entry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	ctx, cancel := k.bounded(ctx)
	defer cancel()
	kv, err := k.handle(ctx)
	if err != nil {
		return err
	}
	_, err = kv.Put(ctx, e.ReceiverID, raw)
	return err
}

// Delete removes one entry; an absent one is not an error.
func (k *KV) Delete(ctx context.Context, id string) error {
	ctx, cancel := k.bounded(ctx)
	defer cancel()
	kv, err := k.handle(ctx)
	if err != nil {
		return err
	}
	if err := kv.Delete(ctx, id); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return err
	}
	return nil
}

// Keys lists the receiver ids held.
func (k *KV) Keys(ctx context.Context) ([]string, error) {
	ctx, cancel := k.bounded(ctx)
	defer cancel()
	kv, err := k.handle(ctx)
	if err != nil {
		return nil, err
	}
	lister, err := kv.ListKeys(ctx)
	if err != nil {
		if errors.Is(err, jetstream.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for key := range lister.Keys() {
		out = append(out, key)
	}
	return out, nil
}

// Load reads every entry: id -> raw value, for ParseEntry.
func (k *KV) Load(ctx context.Context) (map[string][]byte, error) {
	ids, err := k.Keys(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := k.bounded(ctx)
	defer cancel()
	kv, err := k.handle(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(ids))
	for _, id := range ids {
		e, err := kv.Get(ctx, id)
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[id] = e.Value()
	}
	return out, nil
}

// Watch calls changed after every update of the bucket until ctx ends
// (the push half of push-then-reread; the caller re-reads on a timer
// too). It re-establishes the watch after a failure.
func (k *KV) Watch(ctx context.Context, changed func(), logger *slog.Logger) {
	for ctx.Err() == nil {
		kv, err := k.handle(ctx)
		if err == nil {
			var w jetstream.KeyWatcher
			w, err = kv.WatchAll(ctx, jetstream.UpdatesOnly())
			if err == nil {
				for e := range w.Updates() {
					if e != nil {
						changed()
					}
				}
				_ = w.Stop()
			}
		}
		if err != nil && ctx.Err() == nil {
			logger.Debug("key set watch unavailable; relying on the periodic re-read", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}
