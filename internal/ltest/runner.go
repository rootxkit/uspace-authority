package ltest

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/violation"
)

// Expect is one alert path a scenario must see: a violation kind on a
// track (and, when Zone is set, that zone), raised once per entry of
// Clears and cleared with that reason ("" expects it still open when
// Verify runs).
type Expect struct {
	Kind     violation.Kind `json:"kind"`
	Track    string         `json:"track"`
	Zone     string         `json:"zone,omitempty"`
	Severity core.Severity  `json:"severity,omitempty"`
	Clears   []string       `json:"clears"`
	// Gated is a raise that waits, by design, for an outcome other than
	// the sample (a DSS read past a grace, WP-26): its latency is
	// recorded but not held to RaiseLatencyBudget.
	Gated bool `json:"gated,omitempty"`
}

// RaiseLatencyBudget is the plan's budget for a violation (docs/PLAN.md
// §8): raised p99 < 2 s after the captured_at of the sample that raised
// it. Verify fails a run whose raises are slower.
const RaiseLatencyBudget = 2 * time.Second

// Raise expects kind on track raised len(clears) times, each cleared
// with its reason.
func Raise(kind violation.Kind, track string, clears ...string) Expect {
	return Expect{Kind: kind, Track: track, Clears: clears}
}

// InZone is e restricted to one zone.
func (e Expect) InZone(zoneID string) Expect { e.Zone = zoneID; return e }

// WithSeverity is e with the severity each raise must carry.
func (e Expect) WithSeverity(s core.Severity) Expect { e.Severity = s; return e }

// GatedByAnOutcome is e with its latency kept out of the budget (Gated).
func (e Expect) GatedByAnOutcome() Expect { e.Gated = true; return e }

// Observed is one violation in the report.
type Observed struct {
	ViolationID string    `json:"violation_id"`
	Kind        string    `json:"kind"`
	Track       string    `json:"track"`
	Zone        string    `json:"zone,omitempty"`
	Severity    string    `json:"severity"`
	RaisedAt    time.Time `json:"raised_at"`
	CapturedAt  time.Time `json:"captured_at"`
	ClearedAt   time.Time `json:"cleared_at,omitzero"`
	ClearReason string    `json:"clear_reason,omitempty"`
	// LatencyMS is captured_at of the raising sample to the raise's
	// arrival on alrt.v1; StoredLatencyMS to api's row.
	LatencyMS       float64  `json:"latency_ms"`
	StoredLatencyMS *float64 `json:"stored_latency_ms,omitempty"`
	Expected        bool     `json:"expected"`
	Events          []string `json:"events,omitempty"`
}

// Distribution summarises latencies in milliseconds.
type Distribution struct {
	N   int     `json:"n"`
	Min float64 `json:"min_ms"`
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	P99 float64 `json:"p99_ms"`
	Max float64 `json:"max_ms"`
}

// Distribute summarises xs (milliseconds).
func Distribute(xs []float64) Distribution {
	if len(xs) == 0 {
		return Distribution{}
	}
	s := slices.Clone(xs)
	sort.Float64s(s)
	at := func(p float64) float64 {
		i := int(float64(len(s))*p+0.999999) - 1
		return s[min(max(i, 0), len(s)-1)]
	}
	return Distribution{N: len(s), Min: s[0], P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: s[len(s)-1]}
}

// Report is the outcome of a scenario's alerts.
type Report struct {
	Expected []Expect   `json:"expected"`
	Observed []Observed `json:"observed"`
	// MissedAlerts are expected raises that never came; FalseAlerts are
	// raises nothing expected. Both must be zero.
	MissedAlerts int `json:"missed_alerts"`
	FalseAlerts  int `json:"false_alerts"`
	// Failures name every way the run differed from the expectations.
	Failures []string `json:"failures"`
	// Latency is captured_at to the raise on alrt.v1, StoredLatency to
	// api's violations row.
	Latency       Distribution `json:"latency"`
	StoredLatency Distribution `json:"stored_latency"`
}

func key(kind violation.Kind, track string) string { return string(kind) + " " + track }

// Judge compares the violations seen on alrt.v1 with the expectations
// and returns the report; it reads nothing else, so a recorded run (or
// a made-up one) can be judged without the stack.
func Judge(seen []*Violation, expects []Expect) Report {
	rep := Report{Expected: append([]Expect{}, expects...), Observed: []Observed{}, Failures: []string{}}
	byKey := map[string][]*Violation{}
	for _, v := range seen {
		byKey[key(v.Kind, v.Track)] = append(byKey[key(v.Kind, v.Track)], v)
	}
	used := map[string]bool{}
	gated := map[string]bool{}
	expectedKeys := map[string]bool{}
	for _, e := range expects {
		k := key(e.Kind, e.Track)
		expectedKeys[k] = true
		var got []*Violation
		for _, v := range byKey[k] {
			if (e.Zone == "" || v.ZoneID == e.Zone) && !used[v.ID] {
				got = append(got, v)
			}
		}
		for i, clear := range e.Clears {
			if i >= len(got) {
				rep.MissedAlerts++
				rep.Failures = append(rep.Failures, fmt.Sprintf("missed: %s on %s%s raise %d of %d never came", e.Kind, e.Track, zoneSuffix(e.Zone), i+1, len(e.Clears)))
				continue
			}
			v := got[i]
			used[v.ID] = true
			gated[v.ID] = e.Gated
			switch {
			case !v.Raised:
				rep.Failures = append(rep.Failures, fmt.Sprintf("%s %s on %s: first message was not a raise", v.ID, e.Kind, e.Track))
			case clear == "" && !v.ClearedAt.IsZero():
				rep.Failures = append(rep.Failures, fmt.Sprintf("%s %s on %s: cleared %s, expected still open", v.ID, e.Kind, e.Track, v.ClearReason))
			case clear != "" && v.ClearedAt.IsZero():
				rep.Failures = append(rep.Failures, fmt.Sprintf("%s %s on %s: never cleared, expected %s", v.ID, e.Kind, e.Track, clear))
			case clear != "" && v.ClearReason != clear:
				rep.Failures = append(rep.Failures, fmt.Sprintf("%s %s on %s: cleared %s, expected %s", v.ID, e.Kind, e.Track, v.ClearReason, clear))
			}
			if e.Severity != "" && v.Severity != string(e.Severity) {
				rep.Failures = append(rep.Failures, fmt.Sprintf("%s %s on %s: severity %s, expected %s", v.ID, e.Kind, e.Track, v.Severity, e.Severity))
			}
		}
	}
	var lat, budgeted []float64
	for _, v := range seen {
		o := Observed{ViolationID: v.ID, Kind: string(v.Kind), Track: v.Track, Zone: v.ZoneID, Severity: v.Severity,
			RaisedAt: v.RaisedAt.UTC(), CapturedAt: v.RaiseCapturedAt.UTC(), ClearedAt: v.ClearedAt.UTC(), ClearReason: v.ClearReason, Expected: used[v.ID]}
		if v.Raised && !v.RaiseCapturedAt.IsZero() {
			o.LatencyMS = float64(v.RaisedAt.Sub(v.RaiseCapturedAt)) / float64(time.Millisecond)
			lat = append(lat, o.LatencyMS)
			if !gated[v.ID] {
				budgeted = append(budgeted, o.LatencyMS)
			}
		}
		for _, inv := range v.Invalid {
			rep.Failures = append(rep.Failures, fmt.Sprintf("%s: a message the schema refuses: %s", v.ID, inv))
		}
		if !used[v.ID] {
			rep.FalseAlerts++
			why := "no expectation names it"
			if expectedKeys[key(v.Kind, v.Track)] {
				why = "more raises than expected"
			}
			rep.Failures = append(rep.Failures, fmt.Sprintf("false alert: %s %s on %s%s (%s)", v.ID, v.Kind, v.Track, zoneSuffix(v.ZoneID), why))
		}
		rep.Observed = append(rep.Observed, o)
	}
	rep.Latency = Distribute(lat)
	if budget, d := float64(RaiseLatencyBudget)/float64(time.Millisecond), Distribute(budgeted); d.N > 0 && d.P99 >= budget {
		rep.Failures = append(rep.Failures, fmt.Sprintf("raise latency p99 %.0f ms, over the %.0f ms budget (plan §8)", d.P99, budget))
	}
	return rep
}

func zoneSuffix(z string) string {
	if z == "" {
		return ""
	}
	return " in " + z
}

// Verify judges every violation seen on alrt.v1 against expects (the
// missed-alert and false-alert counts must both be zero), checks that
// api stored each one with an events row per transition when the
// violation store runs, records the latency distribution, and fails
// the test on any difference. The report is written to the results
// file.
func (s *Stack) Verify(expects ...Expect) Report {
	s.T.Helper()
	rep := Judge(s.Rec.Violations(), expects)
	s.mu.Lock()
	vs := s.store
	s.mu.Unlock()
	if vs != nil {
		s.checkStored(vs, &rep)
	}
	s.mu.Lock()
	s.expected = expects
	s.verified = &rep
	s.mu.Unlock()
	for _, f := range rep.Failures {
		s.T.Error(f)
	}
	s.T.Logf("%s: %d expected raises, %d observed, missed %d, false %d; latency captured_at to raise p50 %.0f ms p99 %.0f ms max %.0f ms (n=%d)",
		s.Name, countRaises(expects), len(rep.Observed), rep.MissedAlerts, rep.FalseAlerts, rep.Latency.P50, rep.Latency.P99, rep.Latency.Max, rep.Latency.N)
	return rep
}

func countRaises(es []Expect) int {
	n := 0
	for _, e := range es {
		n += len(e.Clears)
	}
	return n
}

// checkStored waits until api's rows agree with what alrt.v1 carried:
// the same state and clear reason, an events row for the raise and one
// for the clear.
func (s *Stack) checkStored(vs *ViolationStore, rep *Report) {
	agree := func() (bool, []string) {
		rows := map[string]StoredViolation{}
		stored := vs.Rows()
		for i := range stored {
			rows[stored[i].ID] = stored[i]
		}
		var why []string
		for i := range rep.Observed {
			o := &rep.Observed[i]
			r, ok := rows[o.ViolationID]
			if !ok {
				why = append(why, o.ViolationID+": not stored")
				continue
			}
			o.Events = r.Events
			d := float64(r.Created.Sub(o.CapturedAt)) / float64(time.Millisecond)
			o.StoredLatencyMS = &d
			cleared := !o.ClearedAt.IsZero()
			reason := ""
			if r.ClearReason != nil {
				reason = *r.ClearReason
			}
			switch {
			case cleared != (r.Closed != nil) || reason != o.ClearReason:
				why = append(why, fmt.Sprintf("%s: stored closed=%v reason %q, alrt.v1 cleared=%v reason %q", o.ViolationID, r.Closed != nil, reason, cleared, o.ClearReason))
			case len(r.Events) == 0 || r.Events[0] != "violation_raised":
				why = append(why, fmt.Sprintf("%s: events %v do not start with violation_raised", o.ViolationID, r.Events))
			case cleared && r.Events[len(r.Events)-1] != "violation_cleared":
				why = append(why, fmt.Sprintf("%s: events %v do not end with violation_cleared", o.ViolationID, r.Events))
			}
		}
		return len(why) == 0, why
	}
	var why []string
	ok := s.awaitQuiet(15*time.Second, func() bool {
		var done bool
		done, why = agree()
		return done
	})
	if !ok {
		for _, w := range why {
			rep.Failures = append(rep.Failures, "stored: "+w)
		}
	}
	var lat []float64
	for i := range rep.Observed {
		if d := rep.Observed[i].StoredLatencyMS; d != nil {
			lat = append(lat, *d)
		}
	}
	rep.StoredLatency = Distribute(lat)
}

// Await waits up to d for cond, re-checking at every bus message and at
// least every 100 ms, and fails the test naming what without it.
func (s *Stack) Await(what string, d time.Duration, cond func() bool) {
	s.T.Helper()
	if !s.awaitQuiet(d, cond) {
		s.T.Fatalf("ltest: %s: timed out waiting for %s", s.Name, what)
	}
}

func (s *Stack) awaitQuiet(d time.Duration, cond func() bool) bool {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		changed := s.Rec.Changed()
		if cond() {
			return true
		}
		select {
		case <-changed:
		case <-tick.C:
		case <-deadline.C:
			return cond()
		}
	}
}

// Open is the violation of kind on track seen raised and not cleared,
// or nil.
func (s *Stack) Open(kind violation.Kind, track string) *Violation {
	for _, v := range s.Rec.Violations() {
		if v.Kind == kind && v.Track == track && v.Raised && v.ClearedAt.IsZero() {
			return v
		}
	}
	return nil
}

// Cleared is the latest violation of kind on track seen cleared, or nil.
func (s *Stack) Cleared(kind violation.Kind, track string) *Violation {
	var last *Violation
	for _, v := range s.Rec.Violations() {
		if v.Kind == kind && v.Track == track && !v.ClearedAt.IsZero() {
			last = v
		}
	}
	return last
}

// AwaitRaised waits for kind on track to be open and returns it.
func (s *Stack) AwaitRaised(kind violation.Kind, track string, d time.Duration) *Violation {
	s.T.Helper()
	var v *Violation
	s.Await(fmt.Sprintf("%s raised on %s", kind, track), d, func() bool { v = s.Open(kind, track); return v != nil })
	return v
}

// AwaitCleared waits for the violation id to be cleared and returns its
// reason.
func (s *Stack) AwaitCleared(id string, d time.Duration) string {
	s.T.Helper()
	var reason string
	s.Await("the clear of "+id, d, func() bool {
		for _, v := range s.Rec.Violations() {
			if v.ID == id && !v.ClearedAt.IsZero() {
				reason = v.ClearReason
				return true
			}
		}
		return false
	})
	return reason
}

// Kinds are the distinct kinds of the expectations, for the log.
func Kinds(es []Expect) string {
	var ks []string
	for _, e := range es {
		if !slices.Contains(ks, string(e.Kind)) {
			ks = append(ks, string(e.Kind))
		}
	}
	return strings.Join(ks, ", ")
}

// AwaitSourceState waits for a status on subject in state that
// arrived after after, and returns when it arrived.
func (s *Stack) AwaitSourceState(subject, state string, after time.Time, d time.Duration) time.Time {
	s.T.Helper()
	var at time.Time
	s.Await(subject+" "+state, d, func() bool {
		for _, o := range s.Rec.Sources(subject) {
			if o.Subject == subject && SourceState(o) == state && o.At.After(after) {
				at = o.At
				return true
			}
		}
		return false
	})
	return at
}
