package intents

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3548"
)

func reasons(o Outcome) map[string]Reason {
	out := map[string]Reason{}
	for _, c := range o.Candidates {
		out[c.ID] = c.Reason
	}
	return out
}

// E-01: an Activated intent the DSS places at the aircraft, inside its
// window, matches; beside it every reason a candidate fails for.
func TestJudgeMatchesAndSaysWhyEveryOtherCandidateFailed(t *testing.T) {
	at := t0
	win := func(id string, st f3548.OperationalIntentState) f3548.OperationalIntentReference {
		return refOf(id, st, at.Add(-time.Minute), at.Add(time.Minute))
	}
	withdrawnAt := at.Add(-time.Second)
	inZone := []Entry{
		{Ref: win("a-match", f3548.Activated)},
		{Ref: win("b-elsewhere", f3548.Activated)},
		{Ref: win("c-gone", f3548.Activated), Withdrawn: &withdrawnAt},
		{Ref: win("d-planned", f3548.Accepted)},
		{Ref: refOf("e-later", f3548.Activated, at.Add(time.Minute), at.Add(2*time.Minute))},
		{Ref: refOf("f-ended", f3548.Activated, at.Add(-2*time.Minute), at.Add(-time.Minute))},
	}
	here := []f3548.OperationalIntentReference{win("a-match", f3548.Activated), win("g-planned-here", f3548.Accepted),
		refOf("h-ended-here", f3548.Activated, at.Add(-2*time.Minute), at.Add(-time.Second))}
	o := Judge(inZone, here, at, true, 0)
	if !o.Matched || o.Match == nil || o.Match.ID != "a-match" || o.OffNominal || !o.VerticalChecked || o.Candidates[0].ID != "a-match" {
		t.Fatalf("match %+v", o)
	}
	want := map[string]Reason{
		"a-match": ReasonMatched, "b-elsewhere": ReasonNotAtPosition, "c-gone": ReasonWithdrawn, "d-planned": ReasonNotActivated,
		"e-later": ReasonBeforeStart, "f-ended": ReasonAfterEnd, "g-planned-here": ReasonNotActivated, "h-ended-here": ReasonAfterEnd,
	}
	got := reasons(o)
	if len(got) != len(want) {
		t.Fatalf("candidates %v", got)
	}
	for id, r := range want {
		if got[id] != r {
			t.Errorf("%s: %s, want %s", id, got[id], r)
		}
	}

	// Absence: the same airspace without the intent at the position.
	o = Judge(inZone, here[1:], at, false, 0)
	if o.Matched || o.Match != nil || reasons(o)["a-match"] != ReasonNotAtPosition || o.VerticalChecked {
		t.Fatalf("no match %+v", o)
	}
	// No position read at all (nothing could match): nothing matches.
	if o := Judge(inZone[2:], nil, at, true, 0); o.Matched || len(o.Candidates) != 4 {
		t.Fatalf("cache only %+v", o)
	}
}

// Nonconforming and Contingent intents are flying under an
// authorisation (their conformance is the USSP's): they match, marked
// off-nominal; an Activated one is preferred when both are here.
func TestJudgeOffNominalMatchesAndActivatedIsPreferred(t *testing.T) {
	at := t0
	for _, st := range []f3548.OperationalIntentState{f3548.Nonconforming, f3548.Contingent} {
		r := refOf("x", st, at.Add(-time.Minute), at.Add(time.Minute))
		o := Judge(nil, []f3548.OperationalIntentReference{r}, at, true, 0)
		if !o.Matched || !o.OffNominal || o.Match.State != string(st) {
			t.Fatalf("%s: %+v", st, o)
		}
	}
	both := []f3548.OperationalIntentReference{
		refOf("a", f3548.Contingent, at.Add(-time.Minute), at.Add(time.Minute)),
		refOf("z", f3548.Activated, at.Add(-time.Minute), at.Add(time.Minute)),
	}
	if o := Judge(nil, both, at, true, 0); o.Match.ID != "z" || o.OffNominal || o.Candidates[0].ID != "z" {
		t.Fatalf("preference %+v", o)
	}
}

// E-10: the candidates are bounded and the cut says so; beside it the
// same outcome under the bound.
func TestJudgeBoundsTheCandidates(t *testing.T) {
	var inZone []Entry
	for _, id := range []string{"a", "b", "c", "d"} {
		inZone = append(inZone, Entry{Ref: refOf(id, f3548.Activated, t0.Add(-time.Minute), t0.Add(time.Minute))})
	}
	if o := Judge(inZone, nil, t0, true, 3); len(o.Candidates) != 3 || !o.Truncated {
		t.Fatalf("over the bound %+v", o)
	}
	if o := Judge(inZone, nil, t0, true, 4); len(o.Candidates) != 4 || o.Truncated {
		t.Fatalf("at the bound %+v", o)
	}
}
