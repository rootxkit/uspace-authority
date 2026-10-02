package receivers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// Bucket is the KV bucket of the key set (docs/PLAN.md §6), the default
// of RID_KEYSET_BUCKET.
const Bucket = bus.BucketRIDReceiverKeys

// KV is the key set in the NATS KV bucket rid_receiver_keys. Each call is
// bounded by Timeout, so an unreachable bus refuses a change quickly
// (503) instead of hanging the request.
type KV struct {
	JS jetstream.JetStream
	// Config is the bucket as internal/bus provisions it; a process
	// running before api's bus.Ensure creates it from this.
	Config  jetstream.KeyValueConfig
	Timeout time.Duration

	mu sync.Mutex
	kv jetstream.KeyValue
}

// NewKV returns the key set in the bucket named by limits (RID_KEYSET_BUCKET)
// on js.
func NewKV(js jetstream.JetStream, limits bus.Limits, timeout time.Duration) *KV {
	if limits.RIDReceiverKeysBucket == "" {
		limits.RIDReceiverKeysBucket = Bucket
	}
	cfg, _ := bus.NewTopology(limits).Bucket(limits.RIDReceiverKeysBucket)
	return &KV{JS: js, Config: cfg, Timeout: timeout}
}

var _ KeyStore = (*KV)(nil)

// handle returns the bucket, creating it when it does not exist
// (internal/bus provisions it; this tolerates running first).
func (k *KV) handle(ctx context.Context) (jetstream.KeyValue, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.kv != nil {
		return k.kv, nil
	}
	kv, err := bus.OpenBucket(ctx, k.JS, k.Config)
	if err != nil {
		return nil, fmt.Errorf("key set: %w", err)
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
// (the push half of push-then-reread; the caller re-reads on its own
// timer). It re-establishes the watch after a failure.
func (k *KV) Watch(ctx context.Context, changed func(), logger *slog.Logger) {
	bus.Follow{
		Open: k.handle, Reload: func(context.Context) { changed() },
		// The caller's timer re-reads; this one only backs it up.
		Reread: time.Hour, Logger: logger,
	}.Run(ctx)
}
