package manned

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"time"

	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// The states of source/status/v1 (uspace-lab
// schemas/common/source/status/v1).
const (
	srcLive     = "live"
	srcStale    = "stale"
	srcDown     = "down"
	srcDisabled = "disabled"
)

// StatusBody is source/status/v1's body for the feed with this
// process's extras, which the schema admits (unknown members are
// ignored within the major version): feed_state (healthy, stale,
// unavailable, lagging, disabled), unavailable_since and its reason,
// what the ANSP itself says is degraded, the age of its last status,
// the aircraft held and the mTLS mode towards the ANSP.
type StatusBody struct {
	Source           string            `json:"source"`
	SourceInstance   *string           `json:"source_instance"`
	State            string            `json:"state"`
	Since            string            `json:"since"`
	AgeS             *float64          `json:"age_s"`
	DisabledBy       *string           `json:"disabled_by"`
	DisabledByWho    *string           `json:"disabled_by_who"`
	Counters         map[string]uint64 `json:"counters"`
	Lagging          bool              `json:"lagging"`
	LagS             *float64          `json:"lag_s"`
	FeedState        string            `json:"feed_state"`
	UnavailableSince *string           `json:"unavailable_since"`
	Reason           *string           `json:"reason"`
	ANSPDegraded     []string          `json:"ansp_degraded"`
	ANSPStatusAgeS   *float64          `json:"ansp_status_age_s"`
	ANSPDropped      *int64            `json:"ansp_dropped_frames"`
	Adapters         int               `json:"adapters"`
	AircraftHeld     int               `json:"aircraft_held"`
	MTLSMode         string            `json:"mtls_mode"`
}

// Who says who switched a source off (sources.Follower.DisabledByWho).
type Who func(sourceType string, instanceID *string) *string

// Status publishes src.v1.ansp_feed.<feed instance> every interval
// (04 §3.6: 2 s) with the feed's state, and the ANSP's own status of
// each of its adapters (console/status/v1 sources[]) on
// src.v1.ansp_feed.<adapter>, with this system's switch and the feed's
// reachability laid over it. While the feed is stale or unavailable the
// aircraft held are aged stale (never removed).
type Status struct {
	Ingest   *Ingest
	Pub      bus.Publisher
	Gate     Gate
	Who      Who
	MTLSMode string
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	Now      func() time.Time

	since map[string]sinceOf
}

type sinceOf struct {
	state string
	at    time.Time
}

func (s *Status) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Status) sinceFor(key, state string, at time.Time) string {
	if s.since == nil {
		s.since = map[string]sinceOf{}
	}
	prev, ok := s.since[key]
	if !ok || prev.state != state {
		prev = sinceOf{state: state, at: at}
		s.since[key] = prev
	}
	return bus.Stamp(prev.at)
}

func (s *Status) decision(instance string) coresources.Decision {
	if s.Gate == nil {
		return coresources.Decision{Enabled: true}
	}
	feed := s.Ingest.S.FeedInstance
	if d := s.Gate.Query(SourceType, &feed); !d.Enabled {
		return d
	}
	return s.Gate.Query(SourceType, &instance)
}

func whyOf(d coresources.Decision) *string {
	by := string(coresources.WhyInstance)
	if d.WhyDisabled != nil {
		by = string(*d.WhyDisabled)
	}
	return &by
}

// Snapshot is the feed's status at now.
func (s *Status) Snapshot(now time.Time) StatusBody {
	in := s.Ingest
	in.init()
	inst := in.S.FeedInstance
	v := in.Feed.View(now)
	counters := in.Counters.Snapshot()
	counters["accepted"] = counters[CounterAircraft]
	counters["refused"] = counters[CounterRefusedSchema] + counters[CounterRefusedDisabled] + counters[CounterFramesMalformed]
	b := StatusBody{
		Source: SourceType, SourceInstance: &inst, AgeS: v.AgeS, Counters: counters, FeedState: v.State,
		ANSPDegraded: v.Degraded, ANSPStatusAgeS: v.StatusAgeS, ANSPDropped: v.Dropped, Adapters: len(v.Adapters),
		AircraftHeld: in.Len(), MTLSMode: s.MTLSMode,
	}
	if b.ANSPDegraded == nil {
		b.ANSPDegraded = []string{}
	}
	at := now
	switch v.State {
	case FeedDisabled:
		d := s.decision(inst)
		b.State, b.DisabledBy = srcDisabled, whyOf(d)
		if s.Who != nil {
			b.DisabledByWho = s.Who(SourceType, &inst)
		}
	case FeedUnavailable:
		b.State = srcDown
		u := bus.Stamp(v.UnavailableSince)
		b.UnavailableSince, at = &u, v.UnavailableSince
		if v.Reason != "" {
			r := v.Reason
			b.Reason = &r
		}
	case FeedStale:
		b.State = srcStale
	case FeedLagging:
		b.State, b.Lagging, b.LagS = srcLive, true, v.LagS
	default:
		b.State = srcLive
	}
	b.Since = s.sinceFor("\x00feed", v.State, at)
	return b
}

// adapterBody is the ANSP's source/status/v1 body of one adapter with
// this system's view laid over it: switched off here (disabled, by whom),
// or not seen through a stale or unavailable feed (stale or down, and
// feed_state says why). The ANSP's other members are kept as received.
func (s *Status) adapterBody(raw json.RawMessage, feed FeedView, now time.Time) (string, map[string]any, bool) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&m) != nil || m == nil {
		return "", nil, false
	}
	id, _ := m["source_instance"].(string)
	if src, _ := m["source"].(string); src != SourceType || !ValidInstance(id) || id == s.Ingest.S.FeedInstance {
		return "", nil, false
	}
	state, _ := m["state"].(string)
	m["feed_state"] = feed.State
	m["via"] = SourceType + ":" + s.Ingest.S.FeedInstance
	if d := s.decision(id); !d.Enabled {
		state = srcDisabled
		m["disabled_by"] = *whyOf(d)
		if s.Who != nil {
			inst := id
			if w := s.Who(SourceType, &inst); w != nil {
				m["disabled_by_who"] = *w
			}
		}
	} else if state != srcDisabled {
		switch feed.State {
		case FeedUnavailable:
			state = srcDown
		case FeedStale:
			state = srcStale
		}
	}
	m["state"] = state
	if state != srcDisabled {
		m["disabled_by"] = nil
	}
	m["since"] = s.sinceFor(id, state, now)
	return id, m, true
}

// Publish sends the feed's status and every adapter's once and returns
// how many were published.
func (s *Status) Publish(now time.Time) int {
	in := s.Ingest
	in.init()
	body := s.Snapshot(now)
	switch body.FeedState {
	case FeedStale, FeedUnavailable:
		in.Age("", StateStale, now)
	case FeedDisabled:
		in.Age("", StateSourceDisabled, now)
	}
	n := 0
	if s.publish(in.S.FeedInstance, bus.SystemEnvelope(SchemaSource, Producer, now, body)) {
		n++
	}
	view := in.Feed.View(now)
	seen := 0
	for _, raw := range view.Sources {
		if seen >= in.S.MaxAdapters {
			in.Counters.Inc(CounterAdaptersRefused)
			break
		}
		id, m, ok := s.adapterBody(raw, view, now)
		if !ok {
			in.Counters.Inc(CounterAdaptersRefused)
			continue
		}
		seen++
		if s.publish(id, bus.SystemEnvelope(SchemaSource, Producer, now, m)) {
			n++
		}
	}
	return n
}

func (s *Status) publish(instance string, env any) bool {
	subject, err := bus.Subjects.Src(SourceType, instance)
	if err != nil {
		return false
	}
	data, err := json.Marshal(env)
	if err == nil {
		err = s.Pub.Publish(subject, data)
	}
	if err != nil {
		if s.Limiter != nil {
			s.Limiter.Limited("manned_status_publish").Warn("feed status not published", slog.String("error", err.Error()))
		}
		return false
	}
	return true
}

// Run publishes every interval until ctx ends.
func (s *Status) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Publish(s.now())
		}
	}
}
