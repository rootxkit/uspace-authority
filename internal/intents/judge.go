package intents

import (
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/f3548"
)

// Reason says why a candidate intent matched an aircraft or why it did
// not (WP-26: "the candidates considered and why each failed").
type Reason string

// The reasons, in the order a candidate is judged.
const (
	// ReasonMatched: the DSS places the intent at the aircraft, it is
	// flying (Activated, or Nonconforming or Contingent, whose
	// conformance is the USSP's), and the sample is inside its window.
	ReasonMatched Reason = "matched"
	// ReasonWithdrawn: the intent is no longer in the DSS (its USSP ended
	// or deleted it) though an earlier read listed it in this airspace.
	ReasonWithdrawn Reason = "withdrawn"
	// ReasonNotActivated: Accepted, planned and not flying.
	ReasonNotActivated Reason = "not_activated"
	// ReasonBeforeStart and ReasonAfterEnd: the sample is outside the
	// intent's time window.
	ReasonBeforeStart Reason = "before_start"
	ReasonAfterEnd    Reason = "after_end"
	// ReasonNotAtPosition: listed in the airspace, but the DSS does not
	// place it at the aircraft's position (and height, when known).
	ReasonNotAtPosition Reason = "not_at_position"
)

// IdentityNotExposed is what a match says of the aircraft's identity:
// F3548's reference names neither the operator nor the UAS, and the
// details that might (GET /uss/v1/operational_intents/{entityid}) need
// utm.strategic_coordination, which the authority does not hold (Q-A5).
// A match is therefore an intent at the aircraft's place and time, not
// the aircraft's own (a spec gap, WP-26 pull request).
const IdentityNotExposed = "not_exposed"

// Candidate is one operational intent considered for an aircraft.
type Candidate struct {
	ID         string `json:"id"`
	Manager    string `json:"manager"`
	USSBaseURL string `json:"uss_base_url"`
	State      string `json:"state"`
	TimeStart  string `json:"time_start"`
	TimeEnd    string `json:"time_end"`
	Reason     Reason `json:"reason"`
}

// Outcome is the judgement of one aircraft's sample against the intents.
type Outcome struct {
	TrackID string
	// Matched says an intent covers the aircraft; Match is it.
	Matched bool
	Match   *Candidate
	// OffNominal is a match on a Nonconforming or Contingent intent.
	OffNominal bool
	// VerticalChecked is false when the position was asked without a
	// height (no WGS84 altitude on the track): the match is horizontal
	// only, and the 120 m rule is never lifted on it.
	VerticalChecked bool
	// Candidates are every intent considered, the match first, at most
	// the board's MaxCandidates; Truncated says more were.
	Candidates []Candidate
	Truncated  bool
	// At is the sample's captured_at, CheckedAt when the DSS answered.
	At, CheckedAt time.Time
}

// flying are the states an aircraft may be in the air under (spec 09
// §1.5): an Accepted intent is planned, not flown.
func flying(s f3548.OperationalIntentState) bool {
	return s == f3548.Activated || s == f3548.Nonconforming || s == f3548.Contingent
}

// rank orders matches: Activated before the off-nominal states.
func rank(s f3548.OperationalIntentState) int {
	if s == f3548.Activated {
		return 0
	}
	return 1
}

// timeReason is why a flying intent's window excludes at, or "".
func timeReason(r *f3548.OperationalIntentReference, at time.Time) Reason {
	switch {
	case at.Before(r.TimeStart.Value):
		return ReasonBeforeStart
	case at.After(r.TimeEnd.Value):
		return ReasonAfterEnd
	}
	return ""
}

// couldMatch reports whether r would match a sample at at if the DSS
// placed it at the aircraft: the cache answers "no intent here" without
// asking the DSS when none could.
func couldMatch(e *Entry, at time.Time) bool {
	return e.Withdrawn == nil && flying(e.Ref.State) && timeReason(&e.Ref, at) == ""
}

func candidateOf(r *f3548.OperationalIntentReference, reason Reason) Candidate {
	return Candidate{
		ID: r.Id, Manager: r.Manager, USSBaseURL: r.UssBaseUrl, State: string(r.State),
		TimeStart: r.TimeStart.Value.UTC().Format(time.RFC3339Nano), TimeEnd: r.TimeEnd.Value.UTC().Format(time.RFC3339Nano),
		Reason: reason,
	}
}

// Judge matches a sample at at against the intents: inZone are the
// cached intents of the U-space airspace the aircraft is in, atPosition
// what the DSS answered for the aircraft's position (nil when it was not
// asked: no cached intent could match). An intent at the position
// matches when it is flying and at is inside its window; every other
// intent is a candidate with the reason it failed. With several matches
// an Activated intent is preferred, then the lowest id.
func Judge(inZone []Entry, atPosition []f3548.OperationalIntentReference, at time.Time, verticalChecked bool, maxCandidates int) Outcome {
	o := Outcome{At: at, VerticalChecked: verticalChecked}
	here := make(map[string]bool, len(atPosition))
	cands := make([]Candidate, 0, len(inZone)+len(atPosition))
	var best *f3548.OperationalIntentReference
	for i := range atPosition {
		r := &atPosition[i]
		if here[r.Id] {
			continue
		}
		here[r.Id] = true
		var reason Reason
		switch {
		case !flying(r.State):
			reason = ReasonNotActivated
		case timeReason(r, at) != "":
			reason = timeReason(r, at)
		default:
			reason = ReasonMatched
			if best == nil || rank(r.State) < rank(best.State) || (rank(r.State) == rank(best.State) && r.Id < best.Id) {
				best = r
			}
		}
		cands = append(cands, candidateOf(r, reason))
	}
	for i := range inZone {
		e := &inZone[i]
		if here[e.Ref.Id] {
			continue
		}
		here[e.Ref.Id] = true
		var reason Reason
		switch {
		case e.Withdrawn != nil:
			reason = ReasonWithdrawn
		case !flying(e.Ref.State):
			reason = ReasonNotActivated
		case timeReason(&e.Ref, at) != "":
			reason = timeReason(&e.Ref, at)
		default:
			reason = ReasonNotAtPosition
		}
		cands = append(cands, candidateOf(&e.Ref, reason))
	}
	if best != nil {
		o.Matched = true
		m := candidateOf(best, ReasonMatched)
		o.Match = &m
		o.OffNominal = best.State != f3548.Activated
	}
	slices.SortFunc(cands, func(a, b Candidate) int {
		am, bm := best != nil && a.ID == best.Id, best != nil && b.ID == best.Id
		if am != bm {
			if am {
				return -1
			}
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	if maxCandidates > 0 && len(cands) > maxCandidates {
		cands, o.Truncated = cands[:maxCandidates], true
	}
	o.Candidates = cands
	return o
}
