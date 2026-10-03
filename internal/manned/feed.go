package manned

import (
	"encoding/json"
	"math"
	"slices"
	"sync"
	"time"
)

// The states of the feed (B-03, B-04, C-12: unavailable is not lost).
const (
	FeedHealthy     = "healthy"
	FeedStale       = "stale"
	FeedUnavailable = "unavailable"
	FeedLagging     = "lagging"
	FeedDisabled    = "disabled"
)

// FeedSettings are the feed's thresholds (configuration with documented
// defaults, INV-03).
type FeedSettings struct {
	// StaleAfter: no frame for this long, console/status/v1 included, and
	// the feed is stale (02 F4: 5 s).
	StaleAfter time.Duration
	// LagAfter: the freshest live aircraft of the last two windows older
	// than this when it arrived, and the feed is lagging with lag_s
	// (B-03: the liveness timeout, 15 s).
	LagAfter time.Duration
}

// DefaultFeedSettings are the configuration's defaults.
func DefaultFeedSettings() FeedSettings {
	return FeedSettings{StaleAfter: 5 * time.Second, LagAfter: 15 * time.Second}
}

// Feed is the state of the ANSP feed as this system sees it: connected
// or unavailable since T (the socket is down; what the ANSP holds is
// not lost, B-04), stale (connected and silent), lagging (frames arrive
// but even the freshest aircraft is old), disabled by source control, or
// healthy. It keeps the ANSP's own word too: its degraded[], sources[]
// and adapters[] of the last status or snapshot. Safe for concurrent use.
type Feed struct {
	s FeedSettings

	mu         sync.Mutex
	connected  bool
	downSince  time.Time
	downReason string
	lastFrame  time.Time
	disabled   bool
	// The minimum age of live aircraft in the current and the previous
	// window of StaleAfter.
	winStart       time.Time
	curMin, prvMin float64
	curHas, prvHas bool
	// The ANSP's word.
	degraded []string
	sources  []json.RawMessage
	adapters []AdapterState
	statusAt time.Time
	dropped  *int64
}

// Reasons the feed is unavailable.
const (
	ReasonNotConnected = "not_connected"
	ReasonUnconfigured = "ansp_unconfigured"
	ReasonNoToken      = "no_token"
	ReasonClosed       = "connection_closed"
	ReasonRefused      = "connection_refused"
	ReasonSilent       = "connection_silent"
)

// NewFeed is a feed never connected, unavailable since start.
func NewFeed(s FeedSettings, start time.Time) *Feed {
	d := DefaultFeedSettings()
	if s.StaleAfter <= 0 {
		s.StaleAfter = d.StaleAfter
	}
	if s.LagAfter <= 0 {
		s.LagAfter = d.LagAfter
	}
	return &Feed{s: s, downSince: start, downReason: ReasonNotConnected}
}

// Settings are the feed's thresholds.
func (f *Feed) Settings() FeedSettings { return f.s }

// Connected records the socket open at now.
func (f *Feed) Connected(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connected, f.downReason = true, ""
	f.lastFrame = now
	f.curHas, f.prvHas = false, false
}

// Down records the socket closed (or never opened) at now for reason;
// the first down after a connection sets the since.
func (f *Feed) Down(now time.Time, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connected || f.downSince.IsZero() {
		f.downSince = now
	}
	f.connected, f.downReason = false, reason
}

// SetDisabled records the feed switched off or on by source control.
func (f *Feed) SetDisabled(off bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disabled = off
}

// Frame records a frame of any schema received at now.
func (f *Feed) Frame(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if now.After(f.lastFrame) {
		f.lastFrame = now
	}
}

// LiveSample records the age of a live aircraft when it arrived.
func (f *Feed) LiveSample(ageS float64, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollLocked(now)
	if !f.curHas || ageS < f.curMin {
		f.curMin, f.curHas = ageS, true
	}
}

func (f *Feed) rollLocked(now time.Time) {
	if f.winStart.IsZero() {
		f.winStart = now
		return
	}
	for now.Sub(f.winStart) >= f.s.StaleAfter {
		f.prvMin, f.prvHas = f.curMin, f.curHas
		f.curMin, f.curHas = 0, false
		f.winStart = f.winStart.Add(f.s.StaleAfter)
		if now.Sub(f.winStart) >= 2*f.s.StaleAfter {
			f.prvHas = false
			f.winStart = now
		}
	}
}

// ANSPStatus keeps the ANSP's degraded[], sources[], adapters[] and
// dropped_frames of a status frame or snapshot received at now.
func (f *Feed) ANSPStatus(st statusIn, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st.Degraded != nil {
		f.degraded = slices.Clone(st.Degraded)
	}
	if st.Sources != nil {
		f.sources = slices.Clone(st.Sources)
	}
	if st.Adapters != nil {
		f.adapters = slices.Clone(st.Adapters)
	}
	if st.DroppedFrames != nil {
		d := *st.DroppedFrames
		f.dropped = &d
	}
	f.statusAt = now
}

// FeedView is the feed at one instant.
type FeedView struct {
	State string
	// Since is when the feed went unavailable (zero otherwise).
	UnavailableSince time.Time
	Reason           string
	// LagS is set while lagging.
	LagS *float64
	// AgeS is the seconds since the last frame (nil before the first).
	AgeS       *float64
	Degraded   []string
	Sources    []json.RawMessage
	Adapters   []AdapterState
	StatusAgeS *float64
	Dropped    *int64
}

// View is the feed's state at now.
func (f *Feed) View(now time.Time) FeedView {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollLocked(now)
	v := FeedView{Degraded: slices.Clone(f.degraded), Sources: slices.Clone(f.sources), Adapters: slices.Clone(f.adapters), Dropped: f.dropped}
	if !f.lastFrame.IsZero() {
		a := secondsSince(now, f.lastFrame)
		v.AgeS = &a
	}
	if !f.statusAt.IsZero() {
		a := secondsSince(now, f.statusAt)
		v.StatusAgeS = &a
	}
	switch {
	case f.disabled:
		v.State = FeedDisabled
	case !f.connected:
		v.State, v.UnavailableSince, v.Reason = FeedUnavailable, f.downSince, f.downReason
	case now.Sub(f.lastFrame) > f.s.StaleAfter:
		v.State = FeedStale
	default:
		v.State = FeedHealthy
		lag := math.Inf(1)
		if f.curHas {
			lag = f.curMin
		}
		if f.prvHas && f.prvMin < lag {
			lag = f.prvMin
		}
		if !math.IsInf(lag, 1) && lag > f.s.LagAfter.Seconds() {
			l := math.Round(lag*1000) / 1000
			v.State, v.LagS = FeedLagging, &l
		}
	}
	return v
}
