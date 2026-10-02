package registry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// F8: each status an entity can have, answered status only; an unknown
// key is unknown, never an error.
func TestValidateAnswersEachStatus(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	op := f.operator(t, naturalOperator(numberA))
	susp := f.operator(t, legalOperator(numberB))
	rev := f.operator(t, naturalOperator("GEOTEST00000003"))
	short := naturalOperator("GEOTEST00000004")
	short.ValidUntil = t0.Add(time.Hour)
	f.operator(t, short)
	if _, err := f.svc.SetOperatorStatus(ctx, susp.ID, StatusSuspended, "insurance", registrar); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetOperatorStatus(ctx, rev.ID, StatusRevoked, "fraud", registrar); err != nil {
		t.Fatal(err)
	}
	f.uas(t, op.ID, serialC1, "C1")
	heavy := 30000
	legacy, err := f.svc.CreateUAS(ctx, NewUAS{OperatorID: op.ID, Serial: serialLegacy, MTOMG: &heavy, RIDCapability: "network"}, registrar)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetUASStatus(ctx, legacy.ID, StatusSuspended, "unsafe", registrar); err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.CreatePilot(ctx, NewPilot{PersonRef: "01001012345", Name: "Test Pilot"}, registrar)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RecordCompetency(ctx, p.ID, Competency{Competency: "A2", CertificateRef: "TEST-A2", ValidUntil: t0.AddDate(5, 0, 0)}, registrar); err != nil {
		t.Fatal(err)
	}
	f.now = t0.Add(2 * time.Hour) // exp is past valid_until, not yet marked by the job

	cases := []struct {
		q    Query
		want [3]string
	}{
		{Query{Operator: numberA}, [3]string{ValidityValid}},
		{Query{Operator: "geotest00000001-x9z"}, [3]string{ValidityValid}}, // public part, case ignored (G-04)
		{Query{Operator: numberB}, [3]string{ValiditySuspended}},
		{Query{Operator: "GEOTEST00000003"}, [3]string{ValidityRevoked}},
		{Query{Operator: "GEOTEST00000004"}, [3]string{ValidityRevoked}}, // expired: not valid
		{Query{Operator: "GEONOBODY000001"}, [3]string{ValidityUnknown}},
		{Query{Serial: serialC1}, [3]string{"", ValidityValid}},
		{Query{Serial: "test-legacy-1"}, [3]string{"", ValiditySuspended}}, // folded, unique (G-05)
		{Query{Serial: "TEST-NOBODY"}, [3]string{"", ValidityUnknown}},
		{Query{Pilot: p.ID}, [3]string{"", "", ValidityValid}},
		{Query{Pilot: "not-an-id"}, [3]string{"", "", ValidityUnknown}},
		{Query{Pilot: "0123456789abcdef0123456789abcdef"}, [3]string{"", "", ValidityUnknown}},
		{Query{Operator: numberA, Serial: serialC1, Pilot: p.ID}, [3]string{ValidityValid, ValidityValid, ValidityValid}},
	}
	for _, c := range cases {
		got, err := f.svc.Validate(ctx, []Query{c.q}, PurposeIdentification, ussp)
		if err != nil {
			t.Fatalf("%+v: %v", c.q, err)
		}
		g := got[0]
		have := [3]string{statusOf(g.Operator), statusOfUAS(g.UAS), statusOfPilot(g.Pilot)}
		if have != c.want {
			t.Errorf("%+v: %v, want %v", c.q, have, c.want)
		}
	}
	got, _ := f.svc.Validate(ctx, []Query{{Operator: numberA, Serial: serialC1, Pilot: p.ID}}, PurposeAuthorisation, ussp)
	if g := got[0]; g.Operator.ValidUntil == nil || !g.Operator.ValidUntil.Equal(op.ValidUntil) || g.UAS.ClassLabel != "C1" ||
		g.UAS.MTOMBand != "under_900g" || len(g.Pilot.Competencies) != 1 || g.Pilot.Competencies[0].Competency != "A2" {
		t.Fatalf("details %+v %+v %+v", g.Operator, g.UAS, g.Pilot)
	}
	got, _ = f.svc.Validate(ctx, []Query{{Serial: serialLegacy}}, PurposeAuthorisation, ussp)
	if got[0].UAS.MTOMBand != "from_25000g" || got[0].UAS.ClassLabel != "" {
		t.Fatalf("heavy %+v", got[0].UAS)
	}
}

// Every call is one events row with the client and the purpose; with
// the audit log down no answer leaves (absence beside presence).
func TestValidateIsAuditedOrNotAnswered(t *testing.T) {
	f := newFixture(t)
	f.operator(t, naturalOperator(numberA))
	ctx := context.Background()
	before := len(f.store.events)
	if _, err := f.svc.Validate(ctx, []Query{{Operator: numberA}, {Serial: "TEST-X"}}, PurposeAuthorisation, ussp); err != nil {
		t.Fatal(err)
	}
	if len(f.store.events) != before+1 {
		t.Fatalf("%d events for one call", len(f.store.events)-before)
	}
	e := f.store.events[len(f.store.events)-1]
	if e.EventType != audit.EventRegistryValidated || e.Actor != ussp || e.Purpose != PurposeAuthorisation {
		t.Fatalf("event %+v", e)
	}
	if f.svc.Counters.Get(CounterValidated) != 2 || f.svc.Counters.Get(CounterValidatedUnknown) != 1 {
		t.Errorf("counters %v", f.svc.Counters.Snapshot())
	}
	f.store.failRecord = true
	if got, err := f.svc.Validate(ctx, []Query{{Operator: numberA}}, PurposeAuthorisation, ussp); err == nil || got != nil {
		t.Fatalf("answered without an audit row: %v %v", got, err)
	}
	f.store.failRecord = false
	f.store.failReads = true
	if _, err := f.svc.Validate(ctx, []Query{{Operator: numberA}}, PurposeAuthorisation, ussp); err == nil {
		t.Fatal("read failure hidden")
	}
}

// E-10: a batch is bounded at MaxBatch; the bound itself is accepted.
// The purpose is required and one of the two F8 names.
func TestValidateBounds(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	batch := func(n int) []Query {
		qs := make([]Query, n)
		for i := range qs {
			qs[i] = Query{Serial: fmt.Sprintf("TEST-%03d", i)}
		}
		return qs
	}
	if got, err := f.svc.Validate(ctx, batch(MaxBatch), PurposeIdentification, ussp); err != nil || len(got) != MaxBatch {
		t.Fatalf("the bound refused: %d %v", len(got), err)
	}
	_, err := f.svc.Validate(ctx, batch(MaxBatch+1), PurposeIdentification, ussp)
	wantProblem(t, err, http.StatusBadRequest, "items")
	_, err = f.svc.Validate(ctx, nil, PurposeIdentification, ussp)
	wantProblem(t, err, http.StatusBadRequest, "items")
	_, err = f.svc.Validate(ctx, []Query{{}}, PurposeIdentification, ussp)
	wantProblem(t, err, http.StatusBadRequest, "items[0]")
	for _, purpose := range []string{"", "marketing"} {
		_, err = f.svc.Validate(ctx, batch(1), purpose, ussp)
		wantProblem(t, err, http.StatusBadRequest, "purpose")
	}
	f.svc.Pattern = func() (string, bool) { return "", false }
	_, err = f.svc.Validate(ctx, batch(1), PurposeIdentification, ussp)
	wantProblem(t, err, http.StatusServiceUnavailable, "")
}

func TestMTOMBand(t *testing.T) {
	bounds := []int{250, 900, 4000, 25000}
	for _, c := range []struct {
		g    int
		want string
	}{{249, "under_250g"}, {250, "under_900g"}, {3999, "under_4000g"}, {24999, "under_25000g"}, {25000, "from_25000g"}} {
		g := c.g
		if got := MTOMBand(&g, bounds); got != c.want {
			t.Errorf("%d g: %q, want %q", c.g, got, c.want)
		}
	}
	if MTOMBand(nil, bounds) != "" {
		t.Error("no mass has a band")
	}
	one := 1
	if MTOMBand(&one, nil) != "" {
		t.Error("no bounds has a band")
	}
}

// The change feed pages by sequence, ids and statuses only.
func TestChangeFeedPages(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	op := f.operator(t, naturalOperator(numberA))
	u := f.uas(t, op.ID, serialC1, "C1")
	if _, err := f.svc.SetUASStatus(ctx, u.ID, StatusSuspended, "unsafe", registrar); err != nil {
		t.Fatal(err)
	}
	page1, next, err := f.svc.Changes(ctx, 0, 2)
	if err != nil || len(page1) != 2 || next != 2 || page1[0].EntityType != EntityOperator || page1[1].PublicKey != serialC1 {
		t.Fatalf("page 1: %+v %d %v", page1, next, err)
	}
	page2, next2, _ := f.svc.Changes(ctx, next, 2)
	if len(page2) != 1 || page2[0].Status != StatusSuspended || next2 != 3 {
		t.Fatalf("page 2: %+v %d", page2, next2)
	}
	empty, same, _ := f.svc.Changes(ctx, next2, 0)
	if len(empty) != 0 || same != next2 {
		t.Fatalf("past the end: %+v %d", empty, same)
	}
	_, _, err = f.svc.Changes(ctx, -1, 10)
	wantProblem(t, err, http.StatusBadRequest, "since")
	f.store.failReads = true
	if _, _, err := f.svc.Changes(ctx, 0, 10); err == nil {
		t.Fatal("read failure hidden")
	}
}

// Spec 06 s5: an operator number sent with its EU secret part is
// answered and audited by its public part only; the secret part is
// neither echoed nor recorded. The twin without a secret part is echoed
// as sent.
func TestValidateNeverEchoesOrRecordsTheSecretPart(t *testing.T) {
	f := newFixture(t)
	f.operator(t, naturalOperator(numberA))
	ctx := context.Background()
	got, err := f.svc.Validate(ctx, []Query{{Operator: "GEOTEST00000001-x9z"}, {Operator: "GEONOBODY000001-q7w"}, {Operator: numberB}}, PurposeIdentification, ussp)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Operator.Number != numberA || got[0].Operator.Status != ValidityValid {
		t.Fatalf("answered %+v", got[0].Operator)
	}
	if got[1].Operator.Number != "GEONOBODY000001" || got[1].Operator.Status != ValidityUnknown {
		t.Fatalf("unknown answered %+v", got[1].Operator)
	}
	if got[2].Operator.Number != numberB {
		t.Fatalf("plain number answered %+v", got[2].Operator)
	}
	e := f.store.events[len(f.store.events)-1]
	recorded := fmt.Sprint(e.Payload)
	for _, secret := range []string{"x9z", "q7w"} {
		if strings.Contains(recorded, secret) {
			t.Fatalf("the secret part %q was recorded: %s", secret, recorded)
		}
	}
	if !strings.Contains(recorded, numberA) || !strings.Contains(recorded, "GEONOBODY000001") {
		t.Fatalf("the public parts were not recorded: %s", recorded)
	}
}
