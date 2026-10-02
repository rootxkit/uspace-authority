package ingest

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"maps"
	"math"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/receivers"
)

// SourceType is this adapter's type in source control and status
// (04 §2 `source`, WP-10's source_controls.source_type).
const SourceType = "direct_rid"

// Producer names this process in every envelope (04 §2).
const Producer = "authority/rid-ingest"

// StatusSubject is a receiver's status subject (docs/PLAN.md §6).
func StatusSubject(receiverID string) string { return "src.v1." + SourceType + "." + receiverID }

// Gate is the source-control switch (uspace-core sources.Follower).
type Gate interface {
	Query(sourceType string, instanceID *string) sources.Decision
}

// Publisher sends one core NATS message (nats.Conn.Publish).
type Publisher interface {
	Publish(subject string, data []byte) error
}

type receiverStats struct {
	accepted   uint64
	duplicates uint64
	stored     uint64
	shed       uint64
	refused    uint64
	byReason   map[string]uint64
	firstSeen  time.Time
	lastSeen   time.Time
	backlog    bool
	lagS       *float64
	stateSince time.Time
	lastState  string
}

// Status keeps every receiver's counters and publishes its
// source/status/v1 every Interval (B-03, B-11, E-09): enabled or disabled
// and by whom, last seen, accepted, refused by reason, the queue depth,
// lagging with lag_s, silent since T.
type Status struct {
	Keyring    *receivers.Keyring
	Gate       Gate
	Pub        Publisher
	Depth      func() uint64
	StaleAfter time.Duration
	// LagAfter is the liveness timeout beyond which a receiver replaying
	// backlog is lagging (B-03: 15 s).
	LagAfter time.Duration
	Now      func() time.Time
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	// MaxReceivers bounds the receivers counted (E-10); refusals of a
	// receiver beyond it are counted only in the process counters.
	MaxReceivers int

	mu    sync.Mutex
	stats map[string]*receiverStats
	start time.Time
}

func (s *Status) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Status) get(id string) *receiverStats {
	if s.stats == nil {
		s.stats = map[string]*receiverStats{}
	}
	st, ok := s.stats[id]
	if !ok {
		if len(s.stats) >= s.MaxReceivers {
			return nil
		}
		st = &receiverStats{byReason: map[string]uint64{}}
		s.stats[id] = st
	}
	return st
}

// Accepted records an accepted batch: its fresh and duplicate
// observations, and, when it is backlog, the lag inside the receiver's own
// clock (sent_at_ms minus its newest rx_ts), so the receiver's skew
// cancels.
func (s *Status) Accepted(id string, b *Batch, fresh, dups int) {
	now := s.now()
	var lag *float64
	if b.Backlog {
		var newest time.Time
		for i := range b.Observations {
			if t := b.Observations[i].RxTS; t != nil && t.After(newest) {
				newest = *t
			}
		}
		if !newest.IsZero() {
			v := math.Max(0, float64(b.SentAtMS-newest.UnixMilli())/1000)
			lag = &v
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.get(id)
	if st == nil {
		return
	}
	st.accepted += uint64(fresh)
	st.duplicates += uint64(dups)
	if st.firstSeen.IsZero() {
		st.firstSeen = now
	}
	st.lastSeen = now
	st.backlog = b.Backlog
	st.lagS = lag
}

// Refused records a refused request of a known receiver.
func (s *Status) Refused(id, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.get(id)
	if st == nil {
		return
	}
	st.refused++
	st.byReason[reason]++
}

// Stored and Shed record what the worker did with a receiver's rows.
func (s *Status) Stored(id string, n int) {
	s.add(id, func(st *receiverStats) { st.stored += uint64(n) })
}

// Shed records observations shed from the queue.
func (s *Status) Shed(id string, n int) { s.add(id, func(st *receiverStats) { st.shed += uint64(n) }) }

func (s *Status) add(id string, fn func(*receiverStats)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.get(id); st != nil {
		fn(st)
	}
}

// Body is source/status/v1's body (uspace-lab schemas/common/source/status/v1)
// with this adapter's extras, which the schema admits (unknown members
// are ignored within the major version).
type Body struct {
	Source         string            `json:"source"`
	SourceInstance *string           `json:"source_instance"`
	State          string            `json:"state"`
	Since          string            `json:"since"`
	AgeS           *float64          `json:"age_s"`
	DisabledBy     *string           `json:"disabled_by"`
	DisabledByWho  *string           `json:"disabled_by_who"`
	Counters       map[string]uint64 `json:"counters"`
	QueueDepth     uint64            `json:"queue_depth"`
	Lagging        bool              `json:"lagging"`
	LagS           *float64          `json:"lag_s"`
	SilentSince    *string           `json:"silent_since"`
	DisabledReason *string           `json:"disabled_reason,omitempty"`
}

// Envelope is the 04 §2 envelope.
type Envelope struct {
	Schema     string `json:"schema"`
	MsgID      string `json:"msg_id"`
	Producer   string `json:"producer"`
	TS         string `json:"ts"`
	RxTS       string `json:"rx_ts"`
	CapturedAt string `json:"captured_at"`
	TimeSource string `json:"time_source"`
	Backlog    bool   `json:"backlog"`
	Body       Body   `json:"body"`
}

// stamp is the envelope's timestamp form: RFC 3339 UTC, milliseconds.
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// Snapshot builds the status of one receiver at now.
func (s *Status) Snapshot(id string, now time.Time) Body {
	e, known := s.Keyring.Lookup(id)
	s.mu.Lock()
	var st receiverStats
	if p := s.get(id); p != nil {
		st = *p
		st.byReason = maps.Clone(p.byReason)
	}
	s.mu.Unlock()
	inst := id
	b := Body{Source: SourceType, SourceInstance: &inst, QueueDepth: s.depth()}
	b.Counters = map[string]uint64{
		"accepted": st.accepted, "refused": st.refused, "duplicates": st.duplicates,
		"stored": st.stored, "dropped_shed": st.shed,
	}
	for r, n := range st.byReason {
		b.Counters[r] = n
	}
	if !st.lastSeen.IsZero() {
		age := math.Max(0, now.Sub(st.lastSeen).Seconds())
		b.AgeS = &age
	}
	decision := s.Gate.Query(SourceType, &inst)
	switch {
	case known && !e.Enabled():
		by := "instance"
		b.State, b.DisabledBy, b.DisabledByWho, b.DisabledReason = "disabled", &by, e.DisabledBy, e.DisabledReason
	case !decision.Enabled:
		by := string(sources.WhyInstance)
		if decision.WhyDisabled != nil {
			by = string(*decision.WhyDisabled)
		}
		b.State, b.DisabledBy = "disabled", &by
	case st.lastSeen.IsZero():
		b.State = "unknown"
	case now.Sub(st.lastSeen) <= s.StaleAfter:
		b.State = "live"
	default:
		b.State = "stale"
		silent := stamp(st.lastSeen)
		b.SilentSince = &silent
	}
	if st.backlog && st.lagS != nil && *st.lagS > s.LagAfter.Seconds() && b.State == "live" {
		b.Lagging, b.LagS = true, st.lagS
	}
	s.mu.Lock()
	if p := s.get(id); p != nil {
		if p.lastState != b.State || p.stateSince.IsZero() {
			p.lastState, p.stateSince = b.State, now
			if !st.lastSeen.IsZero() && b.State == "stale" {
				p.stateSince = st.lastSeen
			}
		}
		b.Since = stamp(p.stateSince)
	} else {
		b.Since = stamp(s.start)
	}
	s.mu.Unlock()
	return b
}

func (s *Status) depth() uint64 {
	if s.Depth == nil {
		return 0
	}
	return s.Depth()
}

// Publish sends every known receiver's status once.
func (s *Status) Publish(now time.Time) int {
	n := 0
	for _, id := range s.Keyring.IDs() {
		env := Envelope{
			Schema: "source/status/v1", MsgID: NewULID(now), Producer: Producer,
			TS: stamp(now), RxTS: stamp(now), CapturedAt: stamp(now), TimeSource: "system",
			Body: s.Snapshot(id, now),
		}
		data, err := json.Marshal(env)
		if err != nil {
			continue
		}
		if err := s.Pub.Publish(StatusSubject(id), data); err != nil {
			s.Limiter.Limited("ingest_status_publish").Warn("receiver status not published", slog.String("error", err.Error()))
			continue
		}
		n++
	}
	return n
}

// Run publishes every interval until ctx ends.
func (s *Status) Run(ctx context.Context, interval time.Duration) {
	s.mu.Lock()
	s.start = s.now()
	s.mu.Unlock()
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

// crockford is the ULID alphabet.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID for at: 48 bits of milliseconds and 80 random
// bits, Crockford base32 (the envelope's msg_id).
func NewULID(at time.Time) string {
	var b [16]byte
	ms := uint64(at.UnixMilli()) & (1<<48 - 1)
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:])
	// 128 bits as 26 base32 digits, least significant first: the top
	// digit holds the top 3 bits, so it is 0-7 as the schema requires.
	var out [26]byte
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 | uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | (hi&31)<<59
		hi >>= 5
	}
	return string(out[:])
}
