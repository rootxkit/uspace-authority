package policy

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Follower holds the policy a process judges with. It applies only a
// higher version than the one it holds, and never one that does not
// validate (E-15), so a late or replayed announcement cannot roll a
// process back and a bad value cannot disarm a check. Every violation
// carries Version() as policy_version (spec 04 §3.3).
type Follower struct {
	counters *core.Counters

	mu        sync.RWMutex
	current   Policy
	have      bool
	appliedAt time.Time
}

// NewFollower returns a follower that holds no policy yet; counters may
// be nil.
func NewFollower(counters *core.Counters) *Follower {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Follower{counters: counters}
}

// Counters are the follower's counters.
func (f *Follower) Counters() *core.Counters { return f.counters }

// Apply offers p. It returns true when p replaced the held policy: p
// validates and its version is higher. An equal version (a re-read of
// the same policy) is ignored silently; a lower one is counted.
func (f *Follower) Apply(p Policy) bool {
	if p.Version <= 0 || p.Validate() != nil {
		f.counters.Inc(CounterInvalidRefused)
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.have && p.Version <= f.current.Version {
		if p.Version < f.current.Version {
			f.counters.Inc(CounterOlderIgnored)
		}
		return false
	}
	f.current, f.have, f.appliedAt = p, true, time.Now()
	f.counters.Inc(CounterApplied)
	return true
}

// PublishPolicy applies p: a Follower is the in-process Publisher of the
// api that owns it.
func (f *Follower) PublishPolicy(_ context.Context, p Policy) error {
	f.Apply(p)
	return nil
}

// Current is the held policy and whether there is one.
func (f *Follower) Current() (Policy, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.current, f.have
}

// Version is the held policy_version, 0 before the first policy.
func (f *Follower) Version() int64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.have {
		return 0
	}
	return f.current.Version
}

// StatusAttrs are the follower's attributes on the status line: the
// version held and since when, or "none" so a process without a policy
// never looks like one judging with defaults (E-02).
func (f *Follower) StatusAttrs() []slog.Attr {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.have {
		return []slog.Attr{slog.Int64("policy_version", 0), slog.String("policy", "none")}
	}
	return []slog.Attr{
		slog.Int64("policy_version", f.current.Version),
		slog.Int64("policy_age_s", int64(time.Since(f.appliedAt).Seconds())),
	}
}

// Run re-reads the policy with load at once and then every interval
// until ctx ends (G-08: the push is repaired by a periodic read). A
// failed read keeps the last policy, is counted and logged at most once
// per interval by the caller's limiter.
func (f *Follower) Run(ctx context.Context, load func(context.Context) (Policy, error), every time.Duration, logger *slog.Logger) {
	if logger == nil {
		logger = logging.Discard()
	}
	refresh := func() {
		p, err := load(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			f.counters.Inc(CounterRefreshFailed)
			logging.Error(ctx, logger, "policy re-read failed; keeping the last policy", err,
				slog.Int64("policy_version", f.Version()))
			return
		}
		if f.Apply(p) {
			logger.Info("policy applied", slog.Int64("policy_version", p.Version))
		}
	}
	refresh()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}
