package picture

import (
	"maps"
	"math"
	"slices"
	"sync"
	"time"

	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/sources"
)

// Source states of source/status/v1.
const (
	StateLive     = "live"
	StateStale    = "stale"
	StateDisabled = "disabled"
	StateDown     = "down"
	StateUnknown  = "unknown"
)

// Switches is the source-control state the picture follows
// (*sources.Follower).
type Switches interface {
	Query(sourceType string, instanceID *string) coresources.Decision
	DisabledByWho(sourceType string, instanceID *string) *string
	InstancesOff() []sources.Control
	Known() bool
}

// Statuses is the adapters' last src.v1 statuses (*sources.StatusStore).
type Statuses interface {
	Instances() [][2]string
	Get(sourceType string, instanceID *string) (sources.Status, bool)
}

// SourceView is what the console is told of each source (02 F9, B-11):
// the adapter's last src.v1 status, shown stale once the adapter is
// silent for staleAfter, overlaid with the source-control state the
// picture follows itself, so a source switched off reads "disabled by
// <who>" within one status interval even when its adapter is silent or
// has not caught up. Beside the instances, one row per source type
// (source_instance null) says whether the type is switched off and
// whether any instance of it is heard. It never hides a source: an
// instance once heard stays listed (bounded by the status store, E-10).
type SourceView struct {
	Statuses   Statuses
	Switches   Switches
	StaleAfter time.Duration
	// Types are the source types always listed (sources.Types).
	Types []string

	mu      sync.Mutex
	since   map[string]sinceOf
	last    map[string]SourceState
	state   map[string]string
	lastAll []SourceState
}

// Snapshot is the rows of the last Compute, without computing (a new
// connection's first status between two ticks).
func (v *SourceView) Snapshot() []SourceState {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slices.Clone(v.lastAll)
}

type sinceOf struct {
	state string
	at    time.Time
}

func sourceKey(sourceType string, instance *string) string {
	if instance == nil {
		return sourceType + "\x00*"
	}
	return sourceType + "\x00" + *instance
}

// knownState keeps a state of the closed enumeration; anything else is
// unknown.
func knownState(s string) string {
	switch s {
	case StateLive, StateStale, StateDisabled, StateDown, StateUnknown:
		return s
	}
	return StateUnknown
}

// Compute builds every source's state at now and returns them sorted
// (types first, then instances) and those whose state, disabled_by, who
// or lagging changed since the previous call.
func (v *SourceView) Compute(now time.Time) (all, changed []SourceState) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.since == nil {
		v.since, v.last, v.state = map[string]sinceOf{}, map[string]SourceState{}, map[string]string{}
	}
	var instances []SourceState
	byType := map[string][]SourceState{}
	if v.Statuses != nil {
		for _, ti := range v.Statuses.Instances() {
			inst := ti[1]
			st, ok := v.Statuses.Get(ti[0], &inst)
			if !ok {
				continue
			}
			s := v.instance(ti[0], inst, st, now)
			instances = append(instances, s)
			byType[ti[0]] = append(byType[ti[0]], s)
		}
	}
	if v.Switches != nil {
		// An instance switched off is listed, by whom, even when its
		// adapter has never been heard (B-11).
		for _, c := range v.Switches.InstancesOff() {
			if c.InstanceID == nil {
				continue
			}
			inst := *c.InstanceID
			if v.Statuses != nil {
				if _, heard := v.Statuses.Get(c.SourceType, &inst); heard {
					continue
				}
			}
			s := SourceState{Source: c.SourceType, SourceInstance: ptr(inst), State: StateDisabled, Since: stamp(c.ChangedAt),
				Counters: map[string]uint64{"accepted": 0, "refused": 0}}
			v.overlay(&s, c.SourceType, &inst)
			instances = append(instances, s)
			byType[c.SourceType] = append(byType[c.SourceType], s)
		}
	}
	types := slices.Clone(v.Types)
	for t := range byType {
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	slices.Sort(types)
	for _, t := range types {
		all = append(all, v.typeRow(t, byType[t], now))
	}
	slices.SortFunc(instances, func(a, b SourceState) int {
		if a.Source != b.Source {
			return compareStrings(a.Source, b.Source)
		}
		return compareStrings(*a.SourceInstance, *b.SourceInstance)
	})
	all = append(all, instances...)
	state := make(map[string]string, len(all))
	for i := range all {
		s := &all[i]
		k := sourceKey(s.Source, s.SourceInstance)
		prev, seen := v.since[k]
		if !seen || prev.state != s.State {
			at := now
			if !seen && s.Since != "" {
				if t, err := time.Parse(time.RFC3339Nano, s.Since); err == nil && !t.After(now) {
					at = t
				}
			}
			prev = sinceOf{state: s.State, at: at}
			v.since[k] = prev
		}
		s.Since = stamp(prev.at)
		state[k] = s.State
		if old, ok := v.last[k]; !ok || old.State != s.State || !eqStr(old.DisabledBy, s.DisabledBy) ||
			!eqStr(old.DisabledByWho, s.DisabledByWho) || old.Lagging != s.Lagging {
			changed = append(changed, *s)
		}
		v.last[k] = *s
	}
	// What is no longer listed (evicted by the status store) is
	// forgotten here too, so the maps stay bounded.
	for k := range v.last {
		if _, ok := state[k]; !ok {
			delete(v.last, k)
			delete(v.since, k)
		}
	}
	v.state = state
	v.lastAll = slices.Clone(all)
	return all, changed
}

func eqStr(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

// instance is one instance's row.
func (v *SourceView) instance(sourceType, inst string, st sources.Status, now time.Time) SourceState {
	b := st.Body
	s := SourceState{
		Source: sourceType, SourceInstance: ptr(inst), State: knownState(b.State), Since: b.Since,
		Counters: map[string]uint64{"accepted": 0, "refused": 0}, DisabledBy: b.DisabledBy, DisabledByWho: b.DisabledByWho,
	}
	maps.Copy(s.Counters, b.Counters)
	silent := now.Sub(st.ReceivedAt)
	if b.AgeS != nil {
		s.AgeS = ptr(math.Round((*b.AgeS+math.Max(0, silent.Seconds()))*10) / 10)
	}
	if s.State != StateDisabled && v.StaleAfter > 0 && silent > v.StaleAfter {
		// The adapter itself is silent: whatever it said last is old.
		s.State = StateStale
	}
	v.overlay(&s, sourceType, &inst)
	if s.State == StateLive && b.Lagging {
		s.Lagging, s.LagS = true, b.LagS
	}
	return s
}

// overlay applies the followed switch: off wins, and says by whom.
func (v *SourceView) overlay(s *SourceState, sourceType string, inst *string) {
	if v.Switches != nil {
		if d := v.Switches.Query(sourceType, inst); !d.Enabled {
			by := string(coresources.WhyInstance)
			if d.WhyDisabled != nil {
				by = string(*d.WhyDisabled)
			}
			s.State, s.DisabledBy = StateDisabled, &by
			s.DisabledByWho = v.Switches.DisabledByWho(sourceType, inst)
			s.Lagging, s.LagS = false, nil
			return
		}
	}
	if s.State == StateDisabled {
		if s.DisabledBy == nil {
			s.DisabledBy = ptr(string(coresources.WhyInstance))
		}
		return
	}
	s.DisabledBy, s.DisabledByWho = nil, nil
}

// typeRow is the row of a source type: switched off, or the best state
// of its instances (live when any is, stale when one is stale or down,
// unknown otherwise: none heard, or every one switched off, each of
// which says so on its own row).
func (v *SourceView) typeRow(sourceType string, inst []SourceState, now time.Time) SourceState {
	s := SourceState{Source: sourceType, State: StateUnknown, Since: stamp(now), Counters: map[string]uint64{"accepted": 0, "refused": 0}}
	for _, i := range inst {
		s.Counters["accepted"] += i.Counters["accepted"]
		s.Counters["refused"] += i.Counters["refused"]
		if i.AgeS != nil && (s.AgeS == nil || *i.AgeS < *s.AgeS) {
			s.AgeS = ptr(*i.AgeS)
		}
		switch {
		case i.State == StateLive:
			s.State = StateLive
		case s.State != StateLive && (i.State == StateStale || i.State == StateDown):
			s.State = StateStale
		}
	}
	v.overlay(&s, sourceType, nil)
	return s
}

// StateOf is the state of a source instance as last computed: what the
// picture puts in a track's source_state. An instance not yet listed is
// disabled when the switches say so and unknown otherwise.
func (v *SourceView) StateOf(sourceType, instance string) string {
	v.mu.Lock()
	st, ok := v.state[sourceKey(sourceType, &instance)]
	v.mu.Unlock()
	if ok {
		return st
	}
	if v.Switches != nil && !v.Switches.Query(sourceType, &instance).Enabled {
		return StateDisabled
	}
	return StateUnknown
}

// TypeState is the last computed state of a source type's row.
func (v *SourceView) TypeState(sourceType string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if st, ok := v.state[sourceKey(sourceType, nil)]; ok {
		return st
	}
	return StateUnknown
}
