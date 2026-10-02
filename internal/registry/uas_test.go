package registry

import (
	"context"
	"net/http"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// E-01 pairs for an aircraft (G-05, G-06): each refusal beside the
// registration it was derived from, which is accepted.
func TestUASRegistrationRefusalsAndTheirAcceptance(t *testing.T) {
	mtom := 800
	cases := []struct {
		name  string
		edit  func(*NewUAS)
		field string
	}{
		{"C1 needs a CTA-2063-A serial", func(u *NewUAS) { u.Serial = serialLegacy }, "serial"},
		{"C2 needs one too", func(u *NewUAS) { u.ClassLabel, u.Serial = "C2", "1A2B3AB" }, "serial"},
		{"lower-case CTA serial", func(u *NewUAS) { u.Serial = "testa0123456789" }, "serial"},
		{"unknown class", func(u *NewUAS) { u.ClassLabel = "C9" }, "class_label"},
		{"empty serial", func(u *NewUAS) { u.Serial, u.ClassLabel = "  ", "" }, "serial"},
		{"serial over the bound", func(u *NewUAS) { u.ClassLabel, u.Serial = "", "TEST"+longText(maxSerialLen) }, "serial"},
		{"no Remote ID capability", func(u *NewUAS) { u.RIDCapability = "" }, "rid_capability"},
		{"MTOM zero", func(u *NewUAS) { z := 0; u.MTOMG = &z }, "mtom_g"},
		{"operator id not a registry id", func(u *NewUAS) { u.OperatorID = "nobody" }, "operator_id"},
		{"registration mark over the bound", func(u *NewUAS) { u.RegistrationMark = longText(maxMarkLen + 1) }, "registration_mark"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			op := f.operator(t, naturalOperator(numberA))
			in := NewUAS{OperatorID: op.ID, Serial: serialC1, ClassLabel: "C1", MTOMG: &mtom, RIDCapability: "direct"}
			edited := in
			c.edit(&edited)
			_, err := f.svc.CreateUAS(context.Background(), edited, registrar)
			wantProblem(t, err, http.StatusBadRequest, c.field)
			if len(f.store.uas) != 0 {
				t.Fatal("a refused aircraft was stored")
			}
			if _, err := f.svc.CreateUAS(context.Background(), in, registrar); err != nil {
				t.Fatalf("twin refused: %v", err)
			}
		})
	}
}

func longText(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'A'
	}
	return string(b)
}

// G-05: the serial is kept as given; an exact duplicate and a second
// spelling that differs only by case are refused (the second would make
// every folded lookup ambiguous), and a different serial is accepted.
func TestUASDuplicateAndAmbiguousFoldAreRefused(t *testing.T) {
	f := newFixture(t)
	op := f.operator(t, naturalOperator(numberA))
	u := f.uas(t, op.ID, " "+serialLegacy+" ", "")
	if u.Serial != serialLegacy || u.SerialFold != "TEST-LEGACY-1" || u.ManufacturerCode != serialLegacy {
		t.Fatalf("stored %+v", u)
	}
	ctx := context.Background()
	_, err := f.svc.CreateUAS(ctx, NewUAS{OperatorID: op.ID, Serial: serialLegacy, RIDCapability: "none"}, registrar)
	wantProblem(t, err, http.StatusConflict, "serial")
	if p := problemOf(err); p.Errors[0].Reason != `"TEST-legacy-1" is registered already` {
		t.Errorf("duplicate reason %q", p.Errors[0].Reason)
	}
	_, err = f.svc.CreateUAS(ctx, NewUAS{OperatorID: op.ID, Serial: "test-LEGACY-1", RIDCapability: "none"}, registrar)
	wantProblem(t, err, http.StatusConflict, "serial")
	if p := problemOf(err); p.Detail != "this serial differs only by case from a registered one" {
		t.Errorf("ambiguous detail %q", p.Detail)
	}
	c1 := f.uas(t, op.ID, serialC1, "C1")
	if c1.ManufacturerCode != "TEST" {
		t.Fatalf("manufacturer code %q", c1.ManufacturerCode)
	}
	// The database's unique constraint behind the check still answers 409.
	f.store.uas["x"] = UAS{ID: "x", OperatorID: op.ID, Serial: "TEST-RACE", SerialFold: "TEST-RACE-2", ManufacturerCode: "TEST-RACE"}
	_, err = f.svc.CreateUAS(ctx, NewUAS{OperatorID: op.ID, Serial: "TEST-RACE", RIDCapability: "none"}, registrar)
	wantProblem(t, err, http.StatusConflict, "serial")
}

func TestUASNeedsARegisteredUnrevokedOperator(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, err := f.svc.CreateUAS(ctx, NewUAS{OperatorID: "0123456789abcdef0123456789abcdef", Serial: serialLegacy, RIDCapability: "none"}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "operator_id")
	op := f.operator(t, naturalOperator(numberA))
	if _, err := f.svc.SetOperatorStatus(ctx, op.ID, StatusRevoked, "fraud", registrar); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.CreateUAS(ctx, NewUAS{OperatorID: op.ID, Serial: serialLegacy, RIDCapability: "none"}, registrar)
	wantProblem(t, err, http.StatusConflict, "operator_id")
	ok := f.operator(t, naturalOperator(numberB))
	f.uas(t, ok.ID, serialLegacy, "")
}

func TestUASUpdateAndStatus(t *testing.T) {
	f := newFixture(t)
	op := f.operator(t, naturalOperator(numberA))
	u := f.uas(t, op.ID, serialLegacy, "C0")
	ctx := context.Background()
	_, err := f.svc.UpdateUAS(ctx, u.ID, UASPatch{}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "body")
	c1 := "C1"
	_, err = f.svc.UpdateUAS(ctx, u.ID, UASPatch{ClassLabel: &c1}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "serial") // G-06 re-judged on a class change
	c4, mark, mtom, rid := "C4", "4L-TEST", 20000, "both"
	got, err := f.svc.UpdateUAS(ctx, u.ID, UASPatch{ClassLabel: &c4, RegistrationMark: &mark, MTOMG: &mtom, RIDCapability: &rid}, registrar)
	if err != nil || got.ClassLabel != "C4" || got.RegistrationMark != mark || *got.MTOMG != mtom {
		t.Fatalf("update %+v %v", got, err)
	}
	if f.proj.uas[u.ID].Label != mark {
		t.Errorf("projected label %q, want the registration mark", f.proj.uas[u.ID].Label)
	}
	_, err = f.svc.UpdateUAS(ctx, "0123456789abcdef0123456789abcdef", UASPatch{ClassLabel: &c4}, registrar)
	wantProblem(t, err, http.StatusNotFound, "id")
	s, err := f.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar)
	if err != nil || s.Status != StatusSuspended || f.proj.uas[u.ID].Status != string(StatusSuspended) {
		t.Fatalf("suspend %+v %v", s, err)
	}
	_, err = f.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "again", registrar)
	wantProblem(t, err, http.StatusConflict, "status")
	_, err = f.svc.SetUASStatus(ctx, "0123456789abcdef0123456789abcdef", StatusActive, "", registrar)
	wantProblem(t, err, http.StatusNotFound, "id")
	if _, err := f.svc.SetUASStatus(ctx, u.ID, StatusRevoked, "destroyed", registrar); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.UpdateUAS(ctx, u.ID, UASPatch{ClassLabel: &c4}, registrar)
	wantProblem(t, err, http.StatusConflict, "status")

	got2, err := f.svc.GetUAS(ctx, u.ID)
	if err != nil || got2.Status != StatusRevoked {
		t.Fatalf("get %+v %v", got2, err)
	}
	_, err = f.svc.GetUAS(ctx, "0123456789abcdef0123456789abcdef")
	wantProblem(t, err, http.StatusNotFound, "id")
	rows, err := f.svc.ListUAS(ctx, "test-LEGACY-1", "", "", Page{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("lookup by folded serial: %v %v", rows, err)
	}
	rows, _ = f.svc.ListUAS(ctx, "", op.ID, StatusActive, Page{})
	if len(rows) != 0 {
		t.Fatal("status filter")
	}
}

func TestPilotRegistrationAndCompetencies(t *testing.T) {
	f := newFixture(t)
	op := f.operator(t, naturalOperator(numberA))
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		in    NewPilot
		field string
	}{
		{"no national id", NewPilot{Name: "Test Pilot"}, "person_ref"},
		{"national id too short", NewPilot{PersonRef: "123", Name: "Test Pilot"}, "person_ref"},
		{"no name", NewPilot{PersonRef: "01001012345"}, "name"},
		{"operator id malformed", NewPilot{PersonRef: "01001012345", Name: "Test Pilot", OperatorID: "x"}, "operator_id"},
		{"operator unknown", NewPilot{PersonRef: "01001012345", Name: "Test Pilot", OperatorID: "0123456789abcdef0123456789abcdef"}, "operator_id"},
	} {
		_, err := f.svc.CreatePilot(ctx, c.in, registrar)
		wantProblem(t, err, http.StatusBadRequest, c.field)
	}
	p, err := f.svc.CreatePilot(ctx, NewPilot{PersonRef: " 01001012345 ", Name: "Test Pilot", OperatorID: op.ID}, registrar)
	if err != nil || p.Status != StatusActive || p.OperatorID != op.ID {
		t.Fatalf("register %+v %v", p, err)
	}
	r := f.store.pilots[p.ID]
	if r.PersonRefLast4 != "2345" || r.PersonRefHash != f.svc.Hasher.PersonRef("01001012345") || len(r.NameSealed) == 0 {
		t.Fatalf("stored %+v", r)
	}
	_, err = f.svc.CreatePilot(ctx, NewPilot{PersonRef: "01001012345", Name: "Other"}, registrar)
	wantProblem(t, err, http.StatusConflict, "person_ref")

	_, err = f.svc.RecordCompetency(ctx, p.ID, Competency{Competency: "A9", CertificateRef: "TEST-C", ValidUntil: t0}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "competency")
	_, err = f.svc.RecordCompetency(ctx, p.ID, Competency{Competency: "A2"}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "certificate_ref")
	for _, c := range []string{"A1_A3", "A2", "STS_01", "national_ge_bvlos"} {
		if _, err := f.svc.RecordCompetency(ctx, p.ID, Competency{Competency: c, CertificateRef: "TEST-" + c, ValidUntil: t0.AddDate(5, 0, 0)}, registrar); err != nil {
			t.Fatalf("%s: %v", c, err)
		}
	}
	// Recording again renews the one row.
	got, err := f.svc.RecordCompetency(ctx, p.ID, Competency{Competency: "A2", CertificateRef: "TEST-A2-RENEWED", ValidUntil: t0.AddDate(6, 0, 0)}, registrar)
	if err != nil || len(got.Competencies) != 4 {
		t.Fatalf("renewal %+v %v", got.Competencies, err)
	}
	pii, err := f.svc.PilotPersonalData(ctx, p.ID, "licence check", registrar)
	if err != nil || pii.Name != "Test Pilot" || pii.PersonRefLast4 != "2345" {
		t.Fatalf("personal data %+v %v", pii, err)
	}
	_, err = f.svc.PilotPersonalData(ctx, p.ID, "", registrar)
	wantProblem(t, err, http.StatusBadRequest, "purpose")
	if e := f.store.events[len(f.store.events)-1]; e.EventType != audit.EventRegistryPIIViewed || e.Purpose != "licence check" {
		t.Fatalf("view not recorded: %+v", e)
	}

	name, detach := "Renamed Pilot", ""
	u, err := f.svc.UpdatePilot(ctx, p.ID, PilotPatch{Name: &name, OperatorID: &detach}, registrar)
	if err != nil || u.OperatorID != "" {
		t.Fatalf("update %+v %v", u, err)
	}
	_, err = f.svc.UpdatePilot(ctx, p.ID, PilotPatch{}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "body")
	bad := "x"
	_, err = f.svc.UpdatePilot(ctx, p.ID, PilotPatch{OperatorID: &bad}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "operator_id")
	_, err = f.svc.UpdatePilot(ctx, "0123456789abcdef0123456789abcdef", PilotPatch{Name: &name}, registrar)
	wantProblem(t, err, http.StatusNotFound, "id")
	if s, err := f.svc.SetPilotStatus(ctx, p.ID, StatusSuspended, "medical", registrar); err != nil || s.Status != StatusSuspended {
		t.Fatalf("suspend %+v %v", s, err)
	}
	_, err = f.svc.SetPilotStatus(ctx, p.ID, StatusSuspended, "again", registrar)
	wantProblem(t, err, http.StatusConflict, "status")
	if _, err := f.svc.SetPilotStatus(ctx, p.ID, StatusRevoked, "fraud", registrar); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.RecordCompetency(ctx, p.ID, Competency{Competency: "A2", CertificateRef: "TEST", ValidUntil: t0}, registrar)
	wantProblem(t, err, http.StatusConflict, "status")
	_, err = f.svc.UpdatePilot(ctx, p.ID, PilotPatch{Name: &name}, registrar)
	wantProblem(t, err, http.StatusConflict, "status")

	gp, err := f.svc.GetPilot(ctx, p.ID)
	if err != nil || gp.Status != StatusRevoked {
		t.Fatalf("get %+v %v", gp, err)
	}
	_, err = f.svc.GetPilot(ctx, "0123456789abcdef0123456789abcdef")
	wantProblem(t, err, http.StatusNotFound, "id")
	list, err := f.svc.ListPilots(ctx, "", StatusRevoked, Page{})
	if err != nil || len(list) != 1 {
		t.Fatalf("list %v %v", list, err)
	}
	// Pilots are not identification facts: nothing of theirs is projected.
	if len(f.proj.uas) != 0 || len(f.proj.operators) != 1 {
		t.Fatalf("projection %d operators %d uas", len(f.proj.operators), len(f.proj.uas))
	}
}
