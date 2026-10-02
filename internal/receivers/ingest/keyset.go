package ingest

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/receivers"
)

// KeySource is where the key set is read: the KV bucket rid_receiver_keys
// (receivers.KV).
type KeySource interface {
	Load(ctx context.Context) (map[string][]byte, error)
	Watch(ctx context.Context, changed func(), logger *slog.Logger)
}

// ErrKeySetInvalid is a key set with an entry that does not parse, an
// empty id or an id twice: a startup error of the ingest (LESSONS B-14).
var ErrKeySetInvalid = errors.New("receiver key set invalid")

// ParseKeySet parses every entry of a loaded key set, sorted by id. Any
// invalid entry refuses the whole set.
func ParseKeySet(raw map[string][]byte) ([]receivers.Entry, error) {
	ids := make([]string, 0, len(raw))
	for id := range raw {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]receivers.Entry, 0, len(ids))
	for _, id := range ids {
		e, err := receivers.ParseEntry(id, raw[id])
		if err != nil {
			return nil, errors.Join(ErrKeySetInvalid, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// LoadKeyring reads the whole key set into kr. It returns the number of
// receivers, an ErrKeySetInvalid error for a set that must stop the
// process, or another error when the set could not be read at all.
func LoadKeyring(ctx context.Context, src KeySource, kr *receivers.Keyring) (int, error) {
	raw, err := src.Load(ctx)
	if err != nil {
		return 0, err
	}
	entries, err := ParseKeySet(raw)
	if err != nil {
		return 0, err
	}
	if err := kr.Replace(entries); err != nil {
		return 0, errors.Join(ErrKeySetInvalid, err)
	}
	return len(entries), nil
}

// FollowKeySet keeps kr current: a reload after every change the watch
// pushes and every interval (push, then periodic re-read, G-08). A reload
// that fails keeps the last key set, counted and logged at a bounded rate.
func FollowKeySet(ctx context.Context, src KeySource, kr *receivers.Keyring, interval time.Duration, logger *slog.Logger, lim *logging.Limiter) {
	poke := make(chan struct{}, 1)
	go src.Watch(ctx, func() {
		select {
		case poke <- struct{}{}:
		default:
		}
	}, logger)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-poke:
		case <-t.C:
		}
		n, err := LoadKeyring(ctx, src, kr)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			lim.Limited("rid_ingest_keyset").Warn("receiver key set not reloaded; keeping the last one",
				slog.String("error", err.Error()), slog.Int("receivers_held", kr.Len()))
			continue
		}
		logger.Debug("receiver key set reloaded", slog.Int("receivers", n))
	}
}
