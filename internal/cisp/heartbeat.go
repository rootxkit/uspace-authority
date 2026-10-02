package cisp

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// DefaultHeartbeatInterval is the publisher heartbeat's period (M3:
// every 15 s; the CISP marks a publisher stale after 60 s of silence).
const DefaultHeartbeatInterval = 15 * time.Second

// HeartbeatSender is the part of the CISP client the heartbeat calls.
type HeartbeatSender interface {
	Heartbeat(ctx context.Context, sentAt time.Time) (int, *StatusError, error)
}

// HeartbeatState is the heartbeat's last outcome for the status line and
// the console.
type HeartbeatState struct {
	Enabled             bool
	IntervalS           float64
	LastSuccessAt       *time.Time
	LastStatus          *int
	LastError           string
	ConsecutiveFailures int
}

// Heartbeat posts POST /v1/publishers/heartbeat {sent_at} every
// Interval under the job lock (one api replica sends per period). A
// failure is a counter and a state, never a crash.
type Heartbeat struct {
	CISP     HeartbeatSender
	Lock     Locker
	Interval time.Duration
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	Now      func() time.Time

	mu    sync.Mutex
	state HeartbeatState
}

func (h *Heartbeat) now() time.Time {
	if h.Now == nil {
		return time.Now()
	}
	return h.Now()
}

func (h *Heartbeat) interval() time.Duration {
	if h.Interval <= 0 {
		return DefaultHeartbeatInterval
	}
	return h.Interval
}

func (h *Heartbeat) count(name string) {
	if h.Counters != nil {
		h.Counters.Inc(name)
	}
}

// Beat sends one heartbeat under the lock; it reports whether this
// replica sent it.
func (h *Heartbeat) Beat(ctx context.Context) bool {
	lock := h.Lock
	if lock == nil {
		lock = NoLock
	}
	release, ok, err := lock(ctx)
	if err != nil || !ok {
		h.count(CounterHeartbeatSkipped)
		if err != nil {
			h.fail(ctx, nil, "the heartbeat lock could not be taken: "+short(err.Error()))
		}
		return false
	}
	defer release()
	status, problem, err := h.CISP.Heartbeat(ctx, h.now())
	switch {
	case err != nil:
		h.fail(ctx, nil, "no answer from the CISP: "+short(err.Error()))
	case status != http.StatusNoContent:
		h.fail(ctx, &status, problem.Error())
	default:
		at := h.now().UTC()
		h.count(CounterHeartbeats)
		h.mu.Lock()
		recovered := h.state.ConsecutiveFailures > 0
		h.state.LastSuccessAt, h.state.LastStatus, h.state.LastError, h.state.ConsecutiveFailures = &at, &status, "", 0
		h.mu.Unlock()
		if recovered && h.Logger != nil {
			h.Logger.Info("publisher heartbeat answered again")
		}
	}
	return true
}

func (h *Heartbeat) fail(ctx context.Context, status *int, reason string) {
	h.count(CounterHeartbeatsFailed)
	h.mu.Lock()
	h.state.LastStatus, h.state.LastError = status, reason
	h.state.ConsecutiveFailures++
	n := h.state.ConsecutiveFailures
	h.mu.Unlock()
	l := h.Logger
	if h.Limiter != nil {
		l = h.Limiter.Limited("cisp-heartbeat")
	}
	if l != nil {
		l.WarnContext(ctx, "publisher heartbeat failed; the CISP marks the authority stale after 60 s of silence",
			slog.String("reason", reason), slog.Int("consecutive_failures", n))
	}
}

// Run beats at once and every Interval until ctx ends.
func (h *Heartbeat) Run(ctx context.Context) {
	h.mu.Lock()
	h.state.Enabled, h.state.IntervalS = true, h.interval().Seconds()
	h.mu.Unlock()
	h.Beat(ctx)
	t := time.NewTicker(h.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.Beat(ctx)
		}
	}
}

// State is the heartbeat's last outcome.
func (h *Heartbeat) State() HeartbeatState {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.state
	if s.IntervalS == 0 {
		s.IntervalS = h.interval().Seconds()
	}
	return s
}
