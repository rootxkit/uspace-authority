package registry

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// E-01: each refusal beside its acceptance. The accepted twin of every
// case is the natural or legal fixture it was derived from.
func TestOperatorRegistrationRefusalsAndTheirAcceptance(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*NewOperator)
		field string
	}{
		{"pattern: lower-case country code", func(o *NewOperator) { o.RegistrationNumber = "geoTEST00000003" }, "registration_number"},
		{"pattern: too short", func(o *NewOperator) { o.RegistrationNumber = "GEO123" }, "registration_number"},
		{"hyphen: the secret part is never registered", func(o *NewOperator) { o.RegistrationNumber = "GEOTEST00000003-x9z" }, "registration_number"},
		{"number required", func(o *NewOperator) { o.RegistrationNumber = " " }, "registration_number"},
		{"natural without a name", func(o *NewOperator) { o.PII.FullName = "" }, "full_name"},
		{"natural without a date of birth", func(o *NewOperator) { o.PII.DateOfBirth = "" }, "date_of_birth"},
		{"date of birth not a date", func(o *NewOperator) { o.PII.DateOfBirth = "02/01/1980" }, "date_of_birth"},
		{"date of birth in the future", func(o *NewOperator) { o.PII.DateOfBirth = "2030-01-01" }, "date_of_birth"},
		{"natural with a legal name", func(o *NewOperator) { o.PII.LegalName = "X LLC" }, "legal_name"},
		{"no postal address", func(o *NewOperator) { o.PII.PostalAddress = "" }, "postal_address"},
		{"not an e-mail", func(o *NewOperator) { o.PII.ContactEmail = "operator at example" }, "contact_email"},
		{"e-mail with a display name", func(o *NewOperator) { o.PII.ContactEmail = "X <x@example.test>" }, "contact_email"},
		{"not a phone", func(o *NewOperator) { o.PII.ContactPhone = "call me" }, "contact_phone"},
		{"secret part of two characters", func(o *NewOperator) { o.SecretPart = "x9" }, "secret_part"},
		{"secret part not alphanumeric", func(o *NewOperator) { o.SecretPart = "x!z" }, "secret_part"},
		{"authorisations not an array", func(o *NewOperator) { o.Authorisations = []byte(`{"kind":"x"}`) }, "authorisations"},
		{"authorisations over the bound", func(o *NewOperator) {
			o.Authorisations = []byte(`[{"x":"` + strings.Repeat("a", MaxAuthorisationsBytes) + `"}]`)
		}, "authorisations"},
		{"unknown source", func(o *NewOperator) { o.Source = "scraped" }, "source"},
		{"unknown type", func(o *NewOperator) { o.OperatorType = "robot" }, "operator_type"},
		{"no valid_until", func(o *NewOperator) { o.ValidUntil = time.Time{} }, "valid_until"},
		{"valid_until before valid_from", func(o *NewOperator) { o.ValidUntil = t0.Add(-time.Hour) }, "valid_until"},
		{"valid_from in the future", func(o *NewOperator) { o.ValidFrom = t0.Add(time.Hour) }, "valid_from"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			in := naturalOperator("GEOTEST00000003")
			c.edit(&in)
			_, err := f.svc.CreateOperator(context.Background(), in, registrar)
			wantProblem(t, err, http.StatusBadRequest, c.field)
			if len(f.store.operators) != 0 || len(f.store.events) != 0 || f.proj.writes != 0 {
				t.Fatal("a refused registration left a row, an event or a projection write")
			}
			if f.svc.Counters.Get(CounterRefused) != 1 {
				t.Errorf("refusal not counted: %v", f.svc.Counters.Snapshot())
			}
			// The twin: the unedited registration is accepted.
			f.operator(t, naturalOperator("GEOTEST00000003"))
		})
	}
	t.Run("legal person with a full name", func(t *testing.T) {
		f := newFixture(t)
		in := legalOperator(numberB)
		in.PII.FullName = "Someone"
		_, err := f.svc.CreateOperator(context.Background(), in, registrar)
		wantProblem(t, err, http.StatusBadRequest, "full_name")
		in = legalOperator(numberB)
		in.PII.LegalIdentificationNumber = ""
		_, err = f.svc.CreateOperator(context.Background(), in, registrar)
		wantProblem(t, err, http.StatusBadRequest, "legal_identification_number")
		f.operator(t, legalOperator(numberB))
	})
}

// A registration is stored with its public part and keyed by regnum's
// compare key; a second spelling of the same number is a duplicate
// (G-04, G-12).
func TestOperatorNumberIsKeyedByItsCompareKey(t *testing.T) {
	f := newFixture(t)
	o := f.operator(t, naturalOperator(" GEOabcd1234efgh "))
	if o.RegistrationNumber != "GEOabcd1234efgh" || o.Status != StatusActive {
		t.Fatalf("stored %+v", o)
	}
	_, err := f.svc.CreateOperator(context.Background(), naturalOperator("GEOABCD1234EFGH"), registrar)
	wantProblem(t, err, http.StatusConflict, "registration_number")
	// A different number is accepted.
	f.operator(t, naturalOperator(numberA))
	// The list finds it by the public part of a broadcast spelling.
	rows, err := f.svc.ListOperators(context.Background(), "geoabcd1234EFGH-x9z", "", Page{})
	if err != nil || len(rows) != 1 || rows[0].ID != o.ID {
		t.Fatalf("lookup by number: %v %v", rows, err)
	}
	none, err := f.svc.ListOperators(context.Background(), "GEOOTHER0000001", "", Page{})
	if err != nil || len(none) != 0 {
		t.Fatalf("unknown number found: %v %v", none, err)
	}
}

// The format is the active policy's (G-07, INV-03): a number under
// another pattern is accepted only when the policy says so.
func TestOperatorNumberFollowsThePolicyPattern(t *testing.T) {
	f := newFixture(t)
	f.svc.Pattern = func() (string, bool) { return `^GEO[0-9]{6}$`, true }
	f.operator(t, naturalOperator("GEO123456"))
	_, err := f.svc.CreateOperator(context.Background(), naturalOperator(numberA), registrar)
	wantProblem(t, err, http.StatusBadRequest, "registration_number")

	f.svc.Pattern = func() (string, bool) { return "", false }
	_, err = f.svc.CreateOperator(context.Background(), naturalOperator(numberA), registrar)
	wantProblem(t, err, http.StatusServiceUnavailable, "")
	if f.svc.Counters.Get(CounterPolicyUnavailable) != 1 {
		t.Errorf("policy_unavailable not counted")
	}
}

// Spec 06 §5, D9: the secret part and the personal data never reach
// the store in clear; the secret part verifies; the personal data comes
// back only through the purpose-logged read.
func TestOperatorSecretAndPersonalDataAreNeverStoredInClear(t *testing.T) {
	f := newFixture(t)
	in := naturalOperator(numberA)
	in.SecretPart = "x9z"
	o := f.operator(t, in)
	if !o.HasSecretPart {
		t.Fatal("has_secret_part false")
	}
	r := f.store.operators[o.ID]
	if r.SecretHash == "" || len(r.SecretSalt) != saltBytes || !f.svc.Hasher.SecretPartMatches(r.SecretSalt, r.SecretHash, "x9z") {
		t.Fatalf("secret part not hashed and verifiable: %+v", r)
	}
	if f.svc.Hasher.SecretPartMatches(r.SecretSalt, r.SecretHash, "x9y") {
		t.Fatal("a wrong secret part verifies")
	}
	for _, sealed := range [][]byte{r.Sealed.FullName, r.Sealed.DateOfBirth, r.Sealed.PostalAddress, r.Sealed.ContactEmail, r.Sealed.ContactPhone} {
		for _, clear := range []string{"Test Person", "1980-01-02", "Test Street", "operator@example.test", "555 000 001", "x9z"} {
			if bytes.Contains(sealed, []byte(clear)) {
				t.Fatalf("%q stored in clear", clear)
			}
		}
	}
	if r.Sealed.LegalName != nil || r.Sealed.KeyID != "pii-test" {
		t.Fatalf("sealed columns: %+v", r.Sealed)
	}
	// A sealed value moved to another column does not open.
	r.Sealed.ContactEmail = r.Sealed.ContactPhone
	if _, err := f.svc.openOperator(&r); err == nil {
		t.Fatal("a value copied into another column opened")
	}

	// Refused without a purpose, and nothing is recorded.
	before := len(f.store.events)
	_, err := f.svc.OperatorPersonalData(context.Background(), o.ID, " ", registrar)
	wantProblem(t, err, http.StatusBadRequest, "purpose")
	if len(f.store.events) != before {
		t.Fatal("a refused read was recorded as a view")
	}
	// With a purpose: the data, and a registry_pii_viewed event with it.
	p, err := f.svc.OperatorPersonalData(context.Background(), o.ID, "case TEST-1 contact", registrar)
	if err != nil || p.FullName != "Test Person" || p.ContactEmail != "operator@example.test" || p.InsurancePolicyNumber != "TEST-INS-1" {
		t.Fatalf("personal data %+v %v", p, err)
	}
	last := f.store.events[len(f.store.events)-1]
	if last.EventType != audit.EventRegistryPIIViewed || last.Purpose != "case TEST-1 contact" || last.EntityID != o.ID {
		t.Fatalf("view event %+v", last)
	}
	// An audit outage refuses the read: no record, no data.
	f.store.failRecord = true
	if p, err := f.svc.OperatorPersonalData(context.Background(), o.ID, "x", registrar); err == nil || p.FullName != "" {
		t.Fatalf("read without its event: %+v %v", p, err)
	}
	_, err = f.svc.OperatorPersonalData(context.Background(), "0123456789abcdef0123456789abcdef", "x", registrar)
	if err == nil {
		t.Fatal("unknown operator read")
	}
}

// Every change is an events row naming no personal value; a status
// change is also a change-feed entry.
func TestOperatorChangesAreAuditedWithoutPersonalValues(t *testing.T) {
	f := newFixture(t)
	o := f.operator(t, naturalOperator(numberA))
	name := "Renamed Person"
	if _, err := f.svc.UpdateOperator(context.Background(), o.ID, OperatorPatch{FullName: &name}, registrar); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetOperatorStatus(context.Background(), o.ID, StatusSuspended, "insurance lapsed", registrar); err != nil {
		t.Fatal(err)
	}
	want := []string{audit.EventOperatorRegistered, audit.EventOperatorUpdated, audit.EventRegistryStatusChanged}
	if got := f.store.eventTypes(); !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for _, e := range f.store.events {
		for _, clear := range []string{"Test Person", "Renamed Person", "operator@example.test", "1980-01-02"} {
			if strings.Contains(strings.ToLower(e.EntityID+e.EventType+payloadString(e.Payload)), strings.ToLower(clear)) {
				t.Fatalf("%s carries %q", e.EventType, clear)
			}
		}
	}
	if len(f.store.changes) != 2 || f.store.changes[1].Status != StatusSuspended || f.store.changes[1].PublicKey != numberA {
		t.Fatalf("change feed %+v", f.store.changes)
	}
	got, err := f.svc.OperatorPersonalData(context.Background(), o.ID, "check", registrar)
	if err != nil || got.FullName != name {
		t.Fatalf("patched name %+v %v", got, err)
	}
}

func payloadString(p any) string {
	m, _ := p.(map[string]any)
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		if s, ok := v.(string); ok {
			b.WriteString(s)
		}
	}
	return b.String()
}

func TestOperatorPatchRefusals(t *testing.T) {
	f := newFixture(t)
	o := f.operator(t, naturalOperator(numberA))
	ctx := context.Background()
	_, err := f.svc.UpdateOperator(ctx, o.ID, OperatorPatch{}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "body")
	bad := "not-an-email"
	_, err = f.svc.UpdateOperator(ctx, o.ID, OperatorPatch{ContactEmail: &bad}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "contact_email")
	legal := "X LLC"
	_, err = f.svc.UpdateOperator(ctx, o.ID, OperatorPatch{LegalName: &legal}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "legal_name")
	early := t0.Add(-time.Hour)
	_, err = f.svc.UpdateOperator(ctx, o.ID, OperatorPatch{ValidUntil: &early}, registrar)
	wantProblem(t, err, http.StatusBadRequest, "valid_until")
	_, err = f.svc.UpdateOperator(ctx, "0123456789abcdef0123456789abcdef", OperatorPatch{ContactEmail: &bad}, registrar)
	wantProblem(t, err, http.StatusNotFound, "id")
	// The accepted twins.
	good, later, yes := "new@example.test", t0.AddDate(3, 0, 0), true
	u, err := f.svc.UpdateOperator(ctx, o.ID, OperatorPatch{
		ContactEmail: &good, ValidUntil: &later, CompetencyConfirmation: &yes, Authorisations: []byte(`[]`),
	}, registrar)
	if err != nil || !u.ValidUntil.Equal(later) || !u.CompetencyConfirmation || u.RegistryVersion <= o.RegistryVersion {
		t.Fatalf("patch %+v %v", u, err)
	}
	if _, err := f.svc.SetOperatorStatus(ctx, o.ID, StatusRevoked, "fraud", registrar); err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.UpdateOperator(ctx, o.ID, OperatorPatch{ContactEmail: &good}, registrar)
	wantProblem(t, err, http.StatusConflict, "status")
}

// The status graph, one function for every entity (brief: active ->
// suspended -> active; revoked final; expired by the job).
func TestStatusGraph(t *testing.T) {
	cases := []struct {
		from, to Status
		reason   string
		system   bool
		code     int // 0 accepted
	}{
		{StatusActive, StatusSuspended, "r", false, 0},
		{StatusSuspended, StatusActive, "", false, 0},
		{StatusActive, StatusRevoked, "r", false, 0},
		{StatusSuspended, StatusRevoked, "r", false, 0},
		{StatusExpired, StatusActive, "", false, 0},
		{StatusExpired, StatusRevoked, "r", false, 0},
		{StatusActive, StatusExpired, "", true, 0},
		{StatusSuspended, StatusExpired, "", true, 0},
		{StatusActive, StatusExpired, "", false, http.StatusBadRequest},
		{StatusRevoked, StatusActive, "", false, http.StatusConflict},
		{StatusRevoked, StatusSuspended, "r", false, http.StatusConflict},
		{StatusActive, StatusActive, "", false, http.StatusConflict},
		{StatusExpired, StatusSuspended, "r", false, http.StatusConflict},
		{StatusActive, StatusSuspended, "", false, http.StatusBadRequest},
		{StatusActive, StatusRevoked, "", false, http.StatusBadRequest},
		{StatusActive, StatusSuspended, strings.Repeat("x", maxReasonLen+1), false, http.StatusBadRequest},
		{StatusActive, "pending", "", false, http.StatusBadRequest},
	}
	for _, c := range cases {
		err := CheckTransition(c.from, c.to, c.reason, c.system)
		switch {
		case c.code == 0 && err != nil:
			t.Errorf("%s -> %s refused: %v", c.from, c.to, err)
		case c.code != 0 && (err == nil || problemOf(err).Status != c.code):
			t.Errorf("%s -> %s: %v, want %d", c.from, c.to, err, c.code)
		}
	}
}

// An expired registration is renewed only after its valid_until moved
// into the future.
func TestOperatorRenewalNeedsAFutureValidUntil(t *testing.T) {
	f := newFixture(t)
	o := f.operator(t, naturalOperator(numberA))
	f.now = o.ValidUntil.Add(time.Minute)
	if n, err := f.svc.ExpireDue(context.Background()); err != nil || n != 1 {
		t.Fatalf("expired %d %v", n, err)
	}
	_, err := f.svc.SetOperatorStatus(context.Background(), o.ID, StatusActive, "", registrar)
	wantProblem(t, err, http.StatusConflict, "valid_until")
	later := f.now.AddDate(1, 0, 0)
	if _, err := f.svc.UpdateOperator(context.Background(), o.ID, OperatorPatch{ValidUntil: &later}, registrar); err != nil {
		t.Fatal(err)
	}
	r, err := f.svc.SetOperatorStatus(context.Background(), o.ID, StatusActive, "", registrar)
	if err != nil || r.Status != StatusActive {
		t.Fatalf("renewal %+v %v", r, err)
	}
}

// The expiry job marks only what is due, as the system, with a feed
// entry and the projection's status (presence and absence, E-01); a
// held job lock skips the run.
func TestExpiryMarksOnlyWhatIsDue(t *testing.T) {
	f := newFixture(t)
	short := naturalOperator(numberA)
	short.ValidUntil = t0.Add(24 * time.Hour)
	due := f.operator(t, short)
	keep := f.operator(t, naturalOperator(numberB))
	ctx := context.Background()

	if n, err := f.svc.ExpireDue(ctx); err != nil || n != 0 {
		t.Fatalf("expired %d before anything was due: %v", n, err)
	}
	f.now = t0.Add(25 * time.Hour)
	f.store.lockHeld = true
	if n, err := f.svc.ExpireDue(ctx); err != nil || n != 0 {
		t.Fatalf("ran without the job lock: %d %v", n, err)
	}
	f.store.lockHeld = false
	if n, err := f.svc.ExpireDue(ctx); err != nil || n != 1 {
		t.Fatalf("expired %d: %v", n, err)
	}
	if f.store.operators[due.ID].Status != StatusExpired || f.store.operators[keep.ID].Status != StatusActive {
		t.Fatal("wrong registration expired")
	}
	ev := f.store.events[len(f.store.events)-1]
	if ev.Actor.Type != audit.ActorSystem || ev.EventType != audit.EventRegistryStatusChanged {
		t.Fatalf("expiry event %+v", ev)
	}
	if f.proj.operators[due.ID].Status != string(StatusRevoked) {
		t.Fatalf("projection %+v", f.proj.operators[due.ID])
	}
	if f.svc.Counters.Get(CounterExpired) != 1 {
		t.Error("expiry not counted")
	}
	f.store.failRecord = true
	f.store.operators[keep.ID] = func() OperatorRecord { r := f.store.operators[keep.ID]; r.ValidUntil = t0; return r }()
	if _, err := f.svc.ExpireDue(ctx); err == nil || f.svc.Counters.Get(CounterExpiryFailed) != 1 {
		t.Fatalf("failed run not counted: %v", err)
	}
}

func TestOperatorReadsAndPages(t *testing.T) {
	f := newFixture(t)
	a := f.operator(t, naturalOperator(numberA))
	f.operator(t, legalOperator(numberB))
	ctx := context.Background()
	got, err := f.svc.GetOperator(ctx, a.ID)
	if err != nil || got.ID != a.ID {
		t.Fatalf("get %v", err)
	}
	_, err = f.svc.GetOperator(ctx, "0123456789abcdef0123456789abcdef")
	wantProblem(t, err, http.StatusNotFound, "id")
	first, err := f.svc.ListOperators(ctx, "", "", Page{Limit: 1})
	if err != nil || len(first) != 1 {
		t.Fatalf("page 1: %v %v", first, err)
	}
	second, _ := f.svc.ListOperators(ctx, "", "", Page{After: first[0].ID, Limit: 1})
	if len(second) != 1 || second[0].ID == first[0].ID {
		t.Fatalf("page 2: %v", second)
	}
	suspended, _ := f.svc.ListOperators(ctx, "", StatusSuspended, Page{})
	if len(suspended) != 0 {
		t.Fatal("status filter")
	}
	f.store.failReads = true
	if _, err := f.svc.ListOperators(ctx, "", "", Page{}); err == nil {
		t.Fatal("read failure hidden")
	}
	f.svc.Pattern = func() (string, bool) { return "", false }
	if _, err := f.svc.ListOperators(ctx, numberA, "", Page{}); err == nil {
		t.Fatal("number lookup without a policy")
	}
}
