package incidents

import (
	"strings"
	"testing"
	"time"
)

// Only the public part of a registration is stored: a secret part sent
// is dropped (spec 06 §5); a value without one is kept.
func TestAircraftKeepsThePublicPartOnly(t *testing.T) {
	public := PublicPartOf(nil)
	a, err := normaliseAircraft("aircraft[0]", Aircraft{OperatorReg: sp("FIN87astrdge12k8-xyz")}, public)
	if err != nil || *a.OperatorReg != "FIN87astrdge12k8" {
		t.Fatalf("%v %v", a.OperatorReg, err)
	}
	a, err = normaliseAircraft("aircraft[0]", Aircraft{OperatorReg: sp(testReg)}, public)
	if err != nil || *a.OperatorReg != testReg {
		t.Fatalf("%v %v", a.OperatorReg, err)
	}
	// A pattern from the policy is used when there is one.
	withPolicy := PublicPartOf(func() (string, bool) { return "^GEO[A-Z0-9]{13}$", true })
	if got := withPolicy("GEOTESTOPER00001-abc"); got != "GEOTESTOPER00001" {
		t.Fatalf("got %q", got)
	}
}

func TestAircraftBounds(t *testing.T) {
	if _, err := normaliseAircraft("a", Aircraft{}, nil); err == nil {
		t.Fatal("an aircraft with nothing to identify it accepted")
	}
	tracks := make([]string, 0, MaxTrackIDs+1)
	for range MaxTrackIDs {
		tracks = append(tracks, "t")
	}
	if _, err := normaliseAircraft("a", Aircraft{TrackIDs: tracks}, nil); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	if _, err := normaliseAircraft("a", Aircraft{TrackIDs: append(tracks, "t")}, nil); err == nil {
		t.Fatal("past the track bound accepted")
	}
	if _, err := normaliseAircraft("a", Aircraft{Serial: sp(strings.Repeat("X", 65))}, nil); err == nil {
		t.Fatal("a long serial accepted")
	}
	if _, err := normaliseAircraft("a", Aircraft{Serial: sp("TEST1"), Identification: Identification{Status: strings.Repeat("x", 65)}}, nil); err == nil {
		t.Fatal("a long identification accepted")
	}
}

func newIncident() NewIncident {
	return NewIncident{Kind: KindAirprox, OccurredAt: at(0), OpenedFrom: FromOwnObservation, Severity: "warning",
		Aircraft: []Aircraft{{Serial: sp(testSerial)}}}
}

func TestCheckNew(t *testing.T) {
	in := newIncident()
	if err := checkNew(&in, nil, false); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*NewIncident){
		"kind":        func(n *NewIncident) { n.Kind = "crash" },
		"from":        func(n *NewIncident) { n.OpenedFrom = "occurrence_report" },
		"violation":   func(n *NewIncident) { n.OpenedFrom = FromViolation },
		"notice_ref":  func(n *NewIncident) { n.OpenedFrom = FromANSPNotice },
		"occurred_at": func(n *NewIncident) { n.OccurredAt = time.Time{} },
		"severity":    func(n *NewIncident) { n.Severity = "major" },
		"narrative":   func(n *NewIncident) { n.Narrative = strings.Repeat("x", MaxNarrative+1) },
		"intent_refs": func(n *NewIncident) { n.IntentRefs = make([]string, MaxIntentRefs+1) },
		"aircraft":    func(n *NewIncident) { n.Aircraft = make([]Aircraft, MaxAircraft+1) },
	}
	for name, mutate := range cases {
		in := newIncident()
		mutate(&in)
		if err := checkNew(&in, nil, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	notice := newIncident()
	notice.OpenedFrom, notice.NoticeRef = FromUSSPNotice, sp("USSP-REF-1")
	if err := checkNew(&notice, nil, false); err != nil {
		t.Fatalf("a notice with its reference: %v", err)
	}
	// WP-19, E-01: police_request is refused by hand and accepted from a
	// police export; a police export never opens another origin.
	police := newIncident()
	police.OpenedFrom = FromPoliceRequest
	if err := checkNew(&police, nil, false); err == nil {
		t.Fatal("police_request opened by hand")
	}
	police = newIncident()
	police.OpenedFrom = FromPoliceRequest
	if err := checkNew(&police, nil, true); err != nil {
		t.Fatalf("police_request from an export: %v", err)
	}
	other := newIncident()
	if err := checkNew(&other, nil, true); err == nil {
		t.Fatal("a police export opened own_observation")
	}
}

func TestCheckStatus(t *testing.T) {
	if err := checkStatus(StatusAssigned, nil); err == nil {
		t.Fatal("assigned without an assignee")
	}
	for _, to := range []string{StatusOpen, StatusClosed} {
		if err := checkStatus(to, nil); err != nil {
			t.Fatalf("%s: %v", to, err)
		}
	}
	if err := checkStatus(StatusAssigned, sp("officer-2")); err != nil {
		t.Fatal(err)
	}
	if err := checkStatus("archived", nil); err == nil {
		t.Fatal("an unknown status accepted")
	}
}

func TestCheckPatch(t *testing.T) {
	s := &Service{}
	if err := s.checkPatch(&Patch{Note: sp("")}); err == nil {
		t.Fatal("an empty note accepted")
	}
	if err := s.checkPatch(&Patch{Note: sp(strings.Repeat("x", MaxNote+1))}); err == nil {
		t.Fatal("a long note accepted")
	}
	if err := s.checkPatch(&Patch{Severity: sp("major")}); err == nil {
		t.Fatal("an unknown severity accepted")
	}
	if err := s.checkPatch(&Patch{AddAircraft: []Aircraft{{}}}); err == nil {
		t.Fatal("an empty aircraft accepted")
	}
	p := Patch{Note: sp("ok"), Severity: sp("critical"), Status: sp(StatusClosed), Narrative: sp("n"), IntentRefs: &[]string{"i1"},
		AddAircraft: []Aircraft{{OperatorReg: sp("FIN87astrdge12k8-xyz")}}}
	s.PublicPart = PublicPartOf(nil)
	if err := s.checkPatch(&p); err != nil || *p.AddAircraft[0].OperatorReg != "FIN87astrdge12k8" {
		t.Fatalf("%v %v", err, p.AddAircraft[0].OperatorReg)
	}
}
