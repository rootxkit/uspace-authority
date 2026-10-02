package sources

import (
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"
)

// Counter names of the wiring, beside core's applied,
// ignored_older_version and new_epoch (E-09).
const (
	CounterMalformed    = "ignored_malformed"
	CounterReadFailed   = "read_failed"
	CounterNotPublished = "read_not_published"
)

type key struct {
	sourceType string
	instanceID string
	whole      bool
}

func keyOf(sourceType string, instanceID *string) key {
	if instanceID == nil {
		return key{sourceType: sourceType, whole: true}
	}
	return key{sourceType: sourceType, instanceID: *instanceID}
}

// Follower is the switch state a process follows: core's Follower plus
// who switched each source. It is safe for concurrent use. With no state
// everything is enabled (B-09).
type Follower struct {
	core     *coresources.Follower
	counters core.Counters
	now      func() time.Time

	mu        sync.RWMutex
	rows      map[key]Control
	appliedAt time.Time

	// changed is signalled after every state taken (WP-12: detect hands
	// the new state to its monitors at once, B-11); capacity one, a
	// signal not yet read stands for every later one.
	changedOnce sync.Once
	changed     chan struct{}
}

// NewFollower returns a follower with no state: every source enabled.
func NewFollower() *Follower {
	return &Follower{core: coresources.NewFollower(), now: time.Now}
}

// Apply offers d; it reports whether d moved the state forward (core's
// rule: higher version within the epoch, any version under a new one).
func (f *Follower) Apply(d Document) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.core.Apply(d.State()) {
		return false
	}
	f.rows = make(map[key]Control, len(d.Controls))
	for _, c := range d.Controls {
		f.rows[keyOf(c.SourceType, c.InstanceID)] = c
	}
	f.appliedAt = f.now()
	f.signal()
	return true
}

func (f *Follower) changes() chan struct{} {
	f.changedOnce.Do(func() { f.changed = make(chan struct{}, 1) })
	return f.changed
}

func (f *Follower) signal() {
	select {
	case f.changes() <- struct{}{}:
	default:
	}
}

// Changes is signalled after every state Apply takes. One reader: a
// signal is not a copy of the state, State is read after it.
func (f *Follower) Changes() <-chan struct{} { return f.changes() }

// State is the state held as core judges it, and whether one has been
// taken (none: every source is enabled).
func (f *Follower) State() (coresources.State, bool) { return f.core.State() }

// Offer decodes raw and applies it. A malformed value is counted and
// ignored: the state held stays (never fail closed).
func (f *Follower) Offer(raw []byte) bool {
	d, err := Decode(raw)
	if err != nil {
		f.counters.Inc(CounterMalformed)
		return false
	}
	return f.Apply(d)
}

// Query is core's decision on the state held.
func (f *Follower) Query(sourceType string, instanceID *string) coresources.Decision {
	return f.core.Query(sourceType, instanceID)
}

// DisabledBy says who switched the source off and why, when Query says
// it is disabled by a type or an instance row; nil otherwise (enabled,
// or disabled by default deny, which is configuration, not a person).
func (f *Follower) DisabledBy(sourceType string, instanceID *string) *Control {
	d := f.core.Query(sourceType, instanceID)
	if d.Enabled || d.WhyDisabled == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	var k key
	switch *d.WhyDisabled {
	case coresources.WhyType:
		k = keyOf(sourceType, nil)
	case coresources.WhyInstance:
		k = keyOf(sourceType, instanceID)
	case coresources.WhyDefaultDeny:
		return nil
	}
	c, ok := f.rows[k]
	if !ok {
		return nil
	}
	return &c
}

// DisabledByWho is the actor of DisabledBy, or nil.
func (f *Follower) DisabledByWho(sourceType string, instanceID *string) *string {
	if c := f.DisabledBy(sourceType, instanceID); c != nil {
		who := c.Actor
		return &who
	}
	return nil
}

// Known reports whether any state has been applied.
func (f *Follower) Known() bool {
	_, ok := f.core.State()
	return ok
}

// CoreCounters are core's counters: applied, ignored_older_version,
// new_epoch.
func (f *Follower) CoreCounters() *core.Counters { return f.core.Counters() }

// Counters are the wiring's counters: ignored_malformed, read_failed,
// read_not_published.
func (f *Follower) Counters() *core.Counters { return &f.counters }

// StatusAttrs puts the state on every status line (E-09): whether it is
// known, its epoch and version, and how long ago it was applied.
func (f *Follower) StatusAttrs() []slog.Attr {
	st, ok := f.core.State()
	if !ok {
		return []slog.Attr{slog.Bool("source_control_known", false)}
	}
	f.mu.RLock()
	at := f.appliedAt
	f.mu.RUnlock()
	return []slog.Attr{
		slog.Bool("source_control_known", true), slog.String("source_control_epoch", st.Epoch),
		slog.Uint64("source_control_version", st.Version),
		slog.Float64("source_control_applied_age_s", f.now().Sub(at).Seconds()),
	}
}
