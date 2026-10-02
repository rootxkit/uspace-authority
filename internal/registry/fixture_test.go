package registry

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/pii"
)

// Fixtures use test numbers and TEST serials only (CLAUDE.md rule 11).
// A registered number never contains a hyphen (regnum refuses one, G-04),
// so the GEO-TEST-* shape is written without hyphens: GEOTEST... under
// the default EU pattern.
const (
	numberA = "GEOTEST00000001"
	numberB = "GEOTEST00000002"
	// serialC1 is a CTA-2063-A serial (manufacturer code TEST, length
	// character A = 10).
	serialC1 = "TESTA0123456789"
	// serialLegacy is a maker's legacy serial, acceptable for C0, C4 and
	// unlabelled aircraft only (G-06).
	serialLegacy = "TEST-legacy-1"
)

var (
	t0        = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	registrar = audit.Actor{Type: audit.ActorUser, ID: "registrar-1", Realm: audit.RealmConsole}
)

type fixture struct {
	svc   *Service
	store *memStore
	now   time.Time
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	sealer, err := pii.NewSealer("pii-test", randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := NewHasher(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: newMemStore(), now: t0}
	f.svc = &Service{
		Store: f.store, Sealer: sealer, Hasher: hasher,
		Pattern:  func() (string, bool) { return regnum.DefaultPattern, true },
		Counters: &core.Counters{},
		Now:      func() time.Time { return f.now },
	}
	return f
}

func naturalOperator(number string) NewOperator {
	return NewOperator{
		OperatorType: OperatorNatural, RegistrationNumber: number,
		PII: OperatorPII{
			FullName: "Test Person", DateOfBirth: "1980-01-02", PostalAddress: "1 Test Street, Tbilisi",
			ContactEmail: "operator@example.test", ContactPhone: "+995 555 000 001", InsurancePolicyNumber: "TEST-INS-1",
		},
		Authorisations: []byte(`[{"kind":"declaration","ref":"TEST-DEC-1"}]`),
		ValidUntil:     t0.AddDate(1, 0, 0),
	}
}

func legalOperator(number string) NewOperator {
	return NewOperator{
		OperatorType: OperatorLegal, RegistrationNumber: number, CompetencyConfirmation: true,
		PII: OperatorPII{
			LegalName: "Test Aerial LLC", LegalIdentificationNumber: "TEST-404000001", PostalAddress: "2 Test Avenue, Batumi",
			ContactEmail: "ops@example.test", ContactPhone: "+995 555 000 002",
		},
		ValidUntil: t0.AddDate(2, 0, 0),
	}
}

func (f *fixture) operator(t *testing.T, in NewOperator) Operator {
	t.Helper()
	o, err := f.svc.CreateOperator(context.Background(), in, registrar)
	if err != nil {
		t.Fatalf("register operator %s: %v", in.RegistrationNumber, err)
	}
	return o
}

func (f *fixture) uas(t *testing.T, operatorID, sn, class string) UAS {
	t.Helper()
	mtom := 800
	u, err := f.svc.CreateUAS(context.Background(), NewUAS{
		OperatorID: operatorID, Serial: sn, ClassLabel: class, MTOMG: &mtom, RIDCapability: "direct", Model: "TEST-QUAD",
	}, registrar)
	if err != nil {
		t.Fatalf("register UAS %s: %v", sn, err)
	}
	return u
}

// problemOf is the problem an error maps onto.
func problemOf(err error) *httpx.Problem { return httpx.ProblemFromError(err) }

// wantProblem fails unless err maps onto status and, when field is not
// empty, names field.
func wantProblem(t *testing.T, err error, status int, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted, want %d on %q", status, field)
	}
	p := problemOf(err)
	if p.Status != status {
		t.Fatalf("status %d (%v), want %d", p.Status, err, status)
	}
	if field == "" {
		return
	}
	for _, e := range p.Errors {
		if e.Field == field {
			return
		}
	}
	t.Fatalf("no error on %q: %+v", field, p.Errors)
}
