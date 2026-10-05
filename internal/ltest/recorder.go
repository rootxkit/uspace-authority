package ltest

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// DefaultRecorderMax bounds each list a Recorder keeps (E-10): past it
// the oldest is forgotten and counted.
const DefaultRecorderMax = 200_000

// TrackObs is one trk.v1 message as the recorder received it.
type TrackObs struct {
	Subject string
	At      time.Time
	Msg     track.Message
	// Invalid is the schema's refusal of the message, if any.
	Invalid string
}

// AlertObs is one alrt.v1 message as the recorder received it.
type AlertObs struct {
	Subject string
	At      time.Time
	Msg     violation.Message
	Invalid string
}

// SourceObs is one src.v1 (or man.v1) message.
type SourceObs struct {
	Subject string
	At      time.Time
	Body    map[string]any
}

// Recorder keeps what the system said on the bus during a scenario:
// every track, every violation transition and republication, every
// source status and manned track, each with the time it arrived.
type Recorder struct {
	mu      sync.Mutex
	max     int
	tracks  []TrackObs
	alerts  []AlertObs
	srcs    []SourceObs
	manned  []SourceObs
	dropped map[string]int
	changed chan struct{}
}

// NewRecorder subscribes to trk.v1.>, alrt.v1.>, src.v1.> and man.v1.>
// on nc until the test ends.
func NewRecorder(t testing.TB, nc *nats.Conn, limit int) *Recorder {
	t.Helper()
	if limit <= 0 {
		limit = DefaultRecorderMax
	}
	r := &Recorder{max: limit, dropped: map[string]int{}, changed: make(chan struct{})}
	for _, subj := range []string{bus.SubjectTrkAll, bus.SubjectAlrtAll, bus.SubjectSrcAll, bus.SubjectManAll} {
		sub, err := nc.Subscribe(subj, r.take)
		if err != nil {
			t.Fatalf("ltest: subscribe %s: %v", subj, err)
		}
		if err := sub.SetPendingLimits(1<<20, 1<<30); err != nil {
			t.Fatalf("ltest: pending limits: %v", err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("ltest: flush: %v", err)
	}
	return r
}

func bounded[T any](xs []T, x T, limit int, dropped *int) []T {
	xs = append(xs, x)
	if len(xs) > limit {
		xs = xs[1:]
		*dropped++
	}
	return xs
}

func (r *Recorder) take(m *nats.Msg) {
	at := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case strings.HasPrefix(m.Subject, "trk.v1."):
		o := TrackObs{Subject: m.Subject, At: at}
		if err := json.Unmarshal(m.Data, &o.Msg); err != nil {
			o.Invalid = err.Error()
		} else if err := o.Msg.Validate(); err != nil {
			o.Invalid = err.Error()
		}
		n := r.dropped["tracks"]
		r.tracks = bounded(r.tracks, o, r.max, &n)
		r.dropped["tracks"] = n
	case strings.HasPrefix(m.Subject, "alrt.v1."):
		o := AlertObs{Subject: m.Subject, At: at}
		if v, err := violation.Decode(m.Data); err != nil {
			o.Invalid = err.Error()
			_ = json.Unmarshal(m.Data, &o.Msg)
		} else {
			o.Msg = *v
		}
		n := r.dropped["alerts"]
		r.alerts = bounded(r.alerts, o, r.max, &n)
		r.dropped["alerts"] = n
	default:
		o := SourceObs{Subject: m.Subject, At: at}
		_ = json.Unmarshal(m.Data, &o.Body)
		key := "sources"
		list := &r.srcs
		if strings.HasPrefix(m.Subject, "man.v1.") {
			key, list = "manned", &r.manned
		}
		n := r.dropped[key]
		*list = bounded(*list, o, r.max, &n)
		r.dropped[key] = n
	}
	close(r.changed)
	r.changed = make(chan struct{})
}

// Changed is closed at the next message.
func (r *Recorder) Changed() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.changed
}

// Tracks are the tracks whose id is trackID ("" is every one).
func (r *Recorder) Tracks(trackID string) []TrackObs {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []TrackObs
	for i := range r.tracks {
		if trackID == "" || r.tracks[i].Msg.Body.TrackID == trackID {
			out = append(out, r.tracks[i])
		}
	}
	return out
}

// Alerts are every alrt.v1 message, republications included.
func (r *Recorder) Alerts() []AlertObs {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]AlertObs(nil), r.alerts...)
}

// Sources are the src.v1 messages on subjects starting with prefix.
func (r *Recorder) Sources(prefix string) []SourceObs {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []SourceObs
	for _, o := range r.srcs {
		if strings.HasPrefix(o.Subject, prefix) {
			out = append(out, o)
		}
	}
	return out
}

// Manned are the man.v1 messages.
func (r *Recorder) Manned() []SourceObs {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]SourceObs(nil), r.manned...)
}

// Dropped is how many of each list were forgotten past the bound.
func (r *Recorder) Dropped() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.dropped))
	for k, v := range r.dropped {
		out[k] = v
	}
	return out
}

// Violation is one violation's life as seen on alrt.v1.
type Violation struct {
	ID       string
	Kind     violation.Kind
	Track    string
	ZoneID   string
	Severity string
	// RaisedAt is when the raise arrived and RaiseCapturedAt the placed
	// time of the sample that raised it.
	RaisedAt        time.Time
	RaiseCapturedAt time.Time
	// ClearedAt is when the clear arrived (zero while open).
	ClearedAt   time.Time
	ClearReason string
	Messages    int
	Invalid     []string
	// Raised is false when the first message seen was not a raise.
	Raised bool
}

// Violations folds the alerts by violation_id, in order of first
// arrival.
func (r *Recorder) Violations() []*Violation {
	alerts := r.Alerts()
	byID := map[string]*Violation{}
	var order []*Violation
	for i := range alerts {
		a := &alerts[i]
		b := &a.Msg.Body
		v := byID[b.ViolationID]
		if v == nil {
			v = &Violation{ID: b.ViolationID, Kind: b.Kind, Track: b.TrackRef}
			if b.ZoneID != nil {
				v.ZoneID = *b.ZoneID
			}
			byID[b.ViolationID] = v
			order = append(order, v)
		}
		v.Messages++
		v.Severity = string(b.Severity)
		if a.Invalid != "" {
			v.Invalid = append(v.Invalid, a.Invalid)
		}
		switch b.State {
		case violation.StateRaised:
			if !v.Raised {
				v.Raised, v.RaisedAt = true, a.At
				v.RaiseCapturedAt, _ = time.Parse(time.RFC3339Nano, b.CapturedAt)
			}
		case violation.StateCleared:
			if v.ClearedAt.IsZero() {
				v.ClearedAt = a.At
				if b.ClearReason != nil {
					v.ClearReason = *b.ClearReason
				}
			}
		case violation.StateUpdated:
		}
	}
	return order
}

// SourceState is the state member of a source status (the body of the
// 04 §2 envelope), or "".
func SourceState(o SourceObs) string {
	body, _ := o.Body["body"].(map[string]any)
	st, _ := body["state"].(string)
	return st
}

// SourceStates are the states the statuses on subject went through, a
// repeat of the same state written once.
func (r *Recorder) SourceStates(subject string) []string {
	var out []string
	for _, o := range r.Sources(subject) {
		if o.Subject != subject {
			continue
		}
		if st := SourceState(o); len(out) == 0 || out[len(out)-1] != st {
			out = append(out, st)
		}
	}
	return out
}
