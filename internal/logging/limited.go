package logging

import (
	"container/list"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Counter names of the limiter (E-09: suppression is counted, never
// silent).
const (
	CounterLogSuppressed  = "log_lines_suppressed"
	CounterLogKeysEvicted = "log_limiter_keys_evicted"
)

// DefaultLimiterKeys bounds the number of keys a Limiter remembers.
const DefaultLimiterKeys = 1024

// Limiter rate-limits repeated log events by key: the first event of a
// key is logged, then at most one per interval, carrying the number of
// events suppressed since the last one logged (LESSONS E-09). The key
// set is bounded (E-10): beyond maxKeys the least recently seen key is
// forgotten, so its next event is logged as a first event again, and
// the eviction is counted.
type Limiter struct {
	base     *slog.Logger
	interval time.Duration
	maxKeys  int
	counters *core.Counters
	now      func() time.Time

	mu    sync.Mutex
	keys  map[string]*list.Element
	order *list.List // front = most recently seen
}

type keyState struct {
	key        string
	lastLogged time.Time
	suppressed uint64
}

// NewLimiter returns a Limiter over base. counters may be nil.
func NewLimiter(base *slog.Logger, interval time.Duration, maxKeys int, counters *core.Counters) *Limiter {
	if maxKeys <= 0 {
		maxKeys = DefaultLimiterKeys
	}
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Limiter{
		base: base, interval: interval, maxKeys: maxKeys, counters: counters,
		now: time.Now, keys: make(map[string]*list.Element), order: list.New(),
	}
}

// Limited returns a logger whose events are rate-limited under key.
// Every logger returned for the same key shares one budget.
func (l *Limiter) Limited(key string) *slog.Logger {
	return slog.New(&limitedHandler{inner: l.base.Handler(), lim: l, key: key})
}

// Len is the number of keys remembered.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}

// admit decides whether an event under key is logged now, and if so how
// many events were suppressed before it.
func (l *Limiter) admit(key string) (bool, uint64) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.keys[key]; ok {
		l.order.MoveToFront(el)
		st := el.Value.(*keyState)
		if now.Sub(st.lastLogged) < l.interval {
			st.suppressed++
			l.counters.Inc(CounterLogSuppressed)
			return false, 0
		}
		n := st.suppressed
		st.suppressed = 0
		st.lastLogged = now
		return true, n
	}
	if len(l.keys) >= l.maxKeys {
		oldest := l.order.Back()
		l.order.Remove(oldest)
		delete(l.keys, oldest.Value.(*keyState).key)
		l.counters.Inc(CounterLogKeysEvicted)
	}
	l.keys[key] = l.order.PushFront(&keyState{key: key, lastLogged: now})
	return true, 0
}

type limitedHandler struct {
	inner slog.Handler
	lim   *Limiter
	key   string
}

// Enabled follows the base handler.
func (h *limitedHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle logs the record if the key is admitted, with the suppressed count.
func (h *limitedHandler) Handle(ctx context.Context, r slog.Record) error {
	ok, suppressed := h.lim.admit(h.key)
	if !ok {
		return nil
	}
	r = r.Clone()
	r.AddAttrs(slog.String("limit_key", h.key), slog.Uint64("suppressed", suppressed))
	return h.inner.Handle(ctx, r)
}

// WithAttrs keeps the key and its budget.
func (h *limitedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &limitedHandler{inner: h.inner.WithAttrs(attrs), lim: h.lim, key: h.key}
}

// WithGroup keeps the key and its budget.
func (h *limitedHandler) WithGroup(name string) slog.Handler {
	return &limitedHandler{inner: h.inner.WithGroup(name), lim: h.lim, key: h.key}
}
