package registry

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

var importer = audit.Actor{Type: audit.ActorUser, ID: "registrar-import", Realm: audit.RealmConsole}

func imported(record int, ref, number string) ImportedOperator {
	in := naturalOperator(number)
	in.Authorisations = []byte("[]")
	return ImportedOperator{Record: record, SourceRef: ref, Operator: in, Status: StatusActive}
}

func importedUAS(record int, ref, owner, sn, class string) ImportedUAS {
	mtom := 800
	return ImportedUAS{Record: record, SourceRef: ref, OperatorNumber: owner, Status: StatusActive,
		UAS: NewUAS{Serial: sn, ClassLabel: class, MTOMG: &mtom, RIDCapability: "direct", Model: "TEST-QUAD"}}
}

func opts(dry bool) ImportOptions {
	return ImportOptions{DryRun: dry, Origin: "upload", SHA256: strings.Repeat("a", 64), RulesVersion: "test-1"}
}

func (f *fixture) countEvents(eventType string) int {
	n := 0
	for _, e := range f.store.eventTypes() {
		if e == eventType {
			n++
		}
	}
	return n
}

func problemFields(ps []*core.FieldError) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Field)
	}
	return out
}

// An import registers every record, marked source = uas_gov_ge_import
// with its source id, and projects them after the commit (loose rows);
// a second run of the same file is unchanged and writes no entity row.
func TestImportOperatorsCreatesThenIsIdempotent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rows := []ImportedOperator{imported(1, "uas-1", numberA), imported(2, "uas-2", numberB)}
	rows[1].Status = StatusSuspended
	res, err := f.svc.ImportOperators(ctx, rows, opts(false), importer)
	if err != nil || !res.Applied() || res.Created != 2 || res.Version == 0 {
		t.Fatalf("first: %+v %v", res, err)
	}
	for _, r := range f.store.operators {
		if r.Source != SourceImport || (r.SourceRef != "uas-1" && r.SourceRef != "uas-2") {
			t.Fatalf("row %+v", r.Operator)
		}
	}
	if f.countEvents(audit.EventRegistryImported) != 1 || f.countEvents(audit.EventOperatorRegistered) != 2 {
		t.Fatalf("events %v", f.store.eventTypes())
	}
	if len(f.proj.operators) != 2 {
		t.Fatalf("projection %v", f.proj.operators)
	}
	suspended := false
	for _, p := range f.proj.operators {
		suspended = suspended || p.Status == string(StatusSuspended)
	}
	if !suspended {
		t.Fatal("the suspended record is not projected suspended")
	}
	writes := f.proj.writes
	again, err := f.svc.ImportOperators(ctx, rows, opts(false), importer)
	if err != nil || again.Unchanged != 2 || again.Created+again.Updated != 0 || !again.Applied() {
		t.Fatalf("again: %+v %v", again, err)
	}
	if f.countEvents(audit.EventOperatorRegistered) != 2 || f.countEvents(audit.EventRegistryImported) != 2 || f.proj.writes != writes {
		t.Fatalf("an unchanged import wrote: events %v, projection writes %d -> %d", f.store.eventTypes(), writes, f.proj.writes)
	}
}

// E-02: a dry run reports what the import would do and changes nothing
// but its events row; the same file then imported does it.
func TestImportDryRunChangesNothing(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rows := []ImportedOperator{imported(1, "uas-1", numberA)}
	res, err := f.svc.ImportOperators(ctx, rows, opts(true), importer)
	if err != nil {
		t.Fatal(err)
	}
	// Read the report: it says what would be done.
	if !res.DryRun || res.Applied() || res.Created != 1 || len(res.Outcomes) != 1 || res.Outcomes[0].Action != ImportCreated || res.Version != 0 {
		t.Fatalf("report %+v", res)
	}
	if len(f.store.operators) != 0 || len(f.store.changes) != 0 || len(f.proj.operators) != 0 || f.proj.writes != 0 {
		t.Fatalf("a dry run wrote: %d operators, %d changes, %d projected", len(f.store.operators), len(f.store.changes), len(f.proj.operators))
	}
	if got := f.store.eventTypes(); !slices.Equal(got, []string{audit.EventRegistryImportDryRun}) {
		t.Fatalf("events %v", got)
	}
	// E-01: the same records, not a dry run, are written.
	if res, err := f.svc.ImportOperators(ctx, rows, opts(false), importer); err != nil || res.Created != 1 || len(f.store.operators) != 1 {
		t.Fatalf("applied %+v %v", res, err)
	}
}

// All or nothing: one record with a problem refuses the whole file,
// every problem by record and field; nothing is written but the
// refusal's events row. Without the problem the same file imports.
func TestImportWithAProblemWritesNothing(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	bad := imported(2, "uas-2", numberB)
	bad.Operator.PII.ContactEmail = "not an address"
	bad.Operator.PII.FullName = ""
	rows := []ImportedOperator{imported(1, "uas-1", numberA), bad}
	res, err := f.svc.ImportOperators(ctx, rows, opts(false), importer)
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied() || len(f.store.operators) != 0 || f.proj.writes != 0 {
		t.Fatalf("refused import wrote: %+v", res)
	}
	got := problemFields(res.Problems)
	for _, want := range []string{"records[2].contact_email", "records[2].full_name"} {
		if !slices.Contains(got, want) {
			t.Errorf("no problem on %s: %v", want, got)
		}
	}
	if f.countEvents(audit.EventRegistryImportRefused) != 1 || f.countEvents(audit.EventOperatorRegistered) != 0 {
		t.Fatalf("events %v", f.store.eventTypes())
	}
	rows[1] = imported(2, "uas-2", numberB)
	if res, err := f.svc.ImportOperators(ctx, rows, opts(false), importer); err != nil || !res.Applied() || res.Created != 2 {
		t.Fatalf("clean file: %+v %v", res, err)
	}
}

// Problems the reader found before the registry saw a record refuse the
// import too, and the records that did map are still checked.
func TestImportPreProblemsRefuseAndTheRestIsChecked(t *testing.T) {
	f := newFixture(t)
	o := opts(false)
	o.Records = 3
	o.Problems = []*core.FieldError{{Field: "records[3].status", Reason: `column "Status": value "x" has no mapping`}}
	bad := imported(1, "uas-1", "GE-1")
	res, err := f.svc.ImportOperators(context.Background(), []ImportedOperator{bad, imported(2, "uas-2", numberB)}, o, importer)
	if err != nil {
		t.Fatal(err)
	}
	got := problemFields(res.Problems)
	if res.Applied() || res.Records != 3 || !slices.Contains(got, "records[3].status") || !slices.Contains(got, "records[1].registration_number") {
		t.Fatalf("%+v %v", res, got)
	}
	if got[0] != "records[1].registration_number" {
		t.Fatalf("problems not in record order: %v", got)
	}
	if len(f.store.operators) != 0 {
		t.Fatal("written")
	}
}

// The duplicates and identity changes an import refuses, each beside
// the record that is accepted.
func TestImportRefusesDuplicatesAndIdentityChanges(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A number registered by hand is not taken over by an import.
	f.operator(t, legalOperator(numberB))
	dupRef := imported(2, "uas-1", "GEOTEST00000003")
	dupNum := imported(3, "uas-3", strings.ToLower(numberA))
	res, err := f.svc.ImportOperators(ctx, []ImportedOperator{imported(1, "uas-1", numberA), dupRef, dupNum, imported(4, "uas-4", numberB)},
		opts(true), importer)
	if err != nil {
		t.Fatal(err)
	}
	got := problemFields(res.Problems)
	for _, want := range []string{"records[2].source_id", "records[3].registration_number", "records[4].registration_number"} {
		if !slices.Contains(got, want) {
			t.Errorf("no problem on %s: %v", want, got)
		}
	}
	if slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, "records[1].") }) {
		t.Errorf("record 1 is fine: %v", got)
	}
	// Imported once, a record's number, type and start never change.
	if _, err := f.svc.ImportOperators(ctx, []ImportedOperator{imported(1, "uas-1", numberA)}, opts(false), importer); err != nil {
		t.Fatal(err)
	}
	moved := imported(1, "uas-1", "GEOTEST00000009")
	legal := imported(2, "uas-1", numberA)
	legal.Operator = legalOperator(numberA)
	res, err = f.svc.ImportOperators(ctx, []ImportedOperator{moved}, opts(true), importer)
	if err != nil || !slices.Contains(problemFields(res.Problems), "records[1].registration_number") {
		t.Fatalf("number change: %+v %v", res.Problems, err)
	}
	res, err = f.svc.ImportOperators(ctx, []ImportedOperator{legal}, opts(true), importer)
	if err != nil || !slices.Contains(problemFields(res.Problems), "records[2].operator_type") {
		t.Fatalf("type change: %+v %v", res.Problems, err)
	}
}

// A record that differs is updated (names of the fields only); a status
// that tightens is projected before the commit; revoked is final.
func TestImportUpdatesAndTransitions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.ImportOperators(ctx, []ImportedOperator{imported(1, "uas-1", numberA)}, opts(false), importer); err != nil {
		t.Fatal(err)
	}
	row := imported(1, "uas-1", numberA)
	row.Operator.PII.ContactEmail = "new@example.test"
	row.Status = StatusSuspended
	res, err := f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer)
	if err != nil || res.Updated != 1 || !slices.Equal(res.Outcomes[0].Fields, []string{"contact_email", "status"}) {
		t.Fatalf("%+v %v", res, err)
	}
	var id string
	for k := range f.store.operators {
		id = k
	}
	if f.store.operators[id].Status != StatusSuspended || f.proj.operators[id].Status != string(StatusSuspended) {
		t.Fatalf("not suspended: %v / %v", f.store.operators[id].Status, f.proj.operators[id])
	}
	pii, err := f.svc.OperatorPersonalData(ctx, id, "test", registrar)
	if err != nil || pii.ContactEmail != "new@example.test" {
		t.Fatalf("pii %+v %v", pii, err)
	}
	row.Status = StatusRevoked
	if res, err := f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer); err != nil || res.Updated != 1 {
		t.Fatalf("revoke %+v %v", res, err)
	}
	row.Status = StatusActive
	res, err = f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer)
	if err != nil || !slices.Contains(problemFields(res.Problems), "records[1].status") {
		t.Fatalf("revoked reactivated: %+v %v", res, err)
	}
}

// An export that still lists a registration past its end as active
// leaves it expired (unchanged), and renews it once valid_until moves.
func TestImportLeavesAnExpiryAlone(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	row := imported(1, "uas-1", numberA)
	row.Operator.ValidFrom = t0.Add(-48 * time.Hour)
	row.Operator.ValidUntil = t0.Add(time.Hour)
	if _, err := f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer); err != nil {
		t.Fatal(err)
	}
	f.now = t0.Add(2 * time.Hour)
	if n, err := f.svc.ExpireDue(ctx); err != nil || n != 1 {
		t.Fatalf("expiry %d %v", n, err)
	}
	res, err := f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer)
	if err != nil || res.Unchanged != 1 {
		t.Fatalf("expired relisted: %+v %v", res, err)
	}
	row.Operator.ValidUntil = t0.AddDate(1, 0, 0)
	res, err = f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer)
	if err != nil || res.Updated != 1 || res.Outcomes[0].Status != StatusActive {
		t.Fatalf("renewal: %+v %v", res, err)
	}
}

// E-10: a file over the record bound is refused before it is read.
func TestImportBoundsTheRecords(t *testing.T) {
	f := newFixture(t)
	o := opts(true)
	o.Records = MaxImportRecords + 1
	if _, err := f.svc.ImportOperators(context.Background(), nil, o, importer); err == nil {
		t.Fatal("accepted past the bound")
	}
	o.Records = MaxImportRecords
	if _, err := f.svc.ImportOperators(context.Background(), nil, o, importer); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
}

// Aircraft name their owner by number; the owner must be registered;
// a re-import is unchanged; a serial change is refused; a status change
// moves the aircraft.
func TestImportUAS(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.ImportOperators(ctx, []ImportedOperator{imported(1, "op-1", numberA)}, opts(false), importer); err != nil {
		t.Fatal(err)
	}
	rows := []ImportedUAS{importedUAS(1, "u-1", numberA+"-x9z", serialC1, "C1"), importedUAS(2, "u-2", numberB, serialLegacy, "C0")}
	res, err := f.svc.ImportUAS(ctx, rows, opts(false), importer)
	if err != nil || res.Applied() || !slices.Contains(problemFields(res.Problems), "records[2].operator_registration_number") {
		t.Fatalf("unknown owner: %+v %v", res, err)
	}
	rows = rows[:1]
	res, err = f.svc.ImportUAS(ctx, rows, opts(false), importer)
	if err != nil || !res.Applied() || res.Created != 1 {
		t.Fatalf("create: %+v %v", res, err)
	}
	for _, u := range f.store.uas {
		if u.Source != SourceImport || u.SourceRef != "u-1" || f.proj.uas[u.ID].Status != string(StatusActive) {
			t.Fatalf("aircraft %+v projected %+v", u, f.proj.uas[u.ID])
		}
	}
	if res, err := f.svc.ImportUAS(ctx, rows, opts(false), importer); err != nil || res.Unchanged != 1 {
		t.Fatalf("again: %+v %v", res, err)
	}
	moved := importedUAS(1, "u-1", numberA, "TESTA0123456780", "C1")
	if res, err := f.svc.ImportUAS(ctx, []ImportedUAS{moved}, opts(true), importer); err != nil || !slices.Contains(problemFields(res.Problems), "records[1].serial") {
		t.Fatalf("serial change: %+v %v", res, err)
	}
	rows[0].Status = StatusSuspended
	rows[0].UAS.Model = "TEST-QUAD-2"
	res, err = f.svc.ImportUAS(ctx, rows, opts(false), importer)
	if err != nil || res.Updated != 1 || !slices.Equal(res.Outcomes[0].Fields, []string{"model", "status"}) {
		t.Fatalf("update: %+v %v", res, err)
	}
	// A duplicate in the file, differing only by case, is a problem.
	dup := []ImportedUAS{importedUAS(1, "u-9", numberA, "TEST-legacy-9", "C0"), importedUAS(2, "u-10", numberA, "test-LEGACY-9", "C0")}
	if res, err := f.svc.ImportUAS(ctx, dup, opts(true), importer); err != nil || !slices.Contains(problemFields(res.Problems), "records[2].serial") {
		t.Fatalf("fold duplicate: %+v %v", res, err)
	}
}

// The public check answers status and validity only, on the public part.
func TestCheckNumber(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	o := f.operator(t, naturalOperator(numberA))
	c, err := f.svc.CheckNumber(ctx, " "+strings.ToLower(numberA)+"-x9z ")
	if err != nil || c.Status != ValidityValid || c.ValidUntil == nil || !c.ValidUntil.Equal(o.ValidUntil) {
		t.Fatalf("registered: %+v %v", c, err)
	}
	if _, err := f.svc.SetOperatorStatus(ctx, o.ID, StatusSuspended, "test", registrar); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.svc.CheckNumber(ctx, numberA); c.Status != ValiditySuspended {
		t.Fatalf("suspended: %+v", c)
	}
	c, err = f.svc.CheckNumber(ctx, numberB)
	if err != nil || c.Status != ValidityUnknown || c.ValidUntil != nil {
		t.Fatalf("unknown: %+v %v", c, err)
	}
	wantProblem(t, func() error { _, err := f.svc.CheckNumber(ctx, "  "); return err }(), 400, "number")
	wantProblem(t, func() error { _, err := f.svc.CheckNumber(ctx, strings.Repeat("A", 65)); return err }(), 400, "number")
}

// NumberFree accepts a number the pattern takes and nobody holds.
func TestNumberFree(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.operator(t, naturalOperator(numberA))
	if p, free, err := f.svc.NumberFree(ctx, numberB); err != nil || !free || p != numberB {
		t.Fatalf("free: %q %v %v", p, free, err)
	}
	if _, free, err := f.svc.NumberFree(ctx, "GEOtest00000001"); err != nil || free {
		t.Fatalf("taken: %v %v", free, err)
	}
	if _, _, err := f.svc.NumberFree(ctx, "GE1"); err == nil {
		t.Fatal("a number the pattern refuses was free")
	}
}

// The applicant check is the registration's own.
func TestCheckApplicant(t *testing.T) {
	in := naturalOperator(numberA)
	if err := CheckApplicant(in.OperatorType, in.PII, in.Authorisations, t0); err != nil {
		t.Fatalf("accepted applicant refused: %v", err)
	}
	in.PII.ContactEmail = "x"
	if err := CheckApplicant(in.OperatorType, in.PII, []byte(`{}`), t0); err == nil ||
		!strings.Contains(err.Error(), "contact_email") || !strings.Contains(err.Error(), "authorisations") {
		t.Fatalf("got %v", err)
	}
}

// G-08 for an import: a tightening record whose projection write fails
// rolls the whole import back (503); a loosening one committed before
// its projection write stays, counted behind and repaired; with the
// projection up both write.
func TestImportProjectionFailsSafe(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.proj.failBegin = true
	res, err := f.svc.ImportOperators(ctx, []ImportedOperator{imported(1, "uas-1", numberA)}, opts(false), importer)
	if err != nil || !res.Applied() || len(f.store.operators) != 1 || f.svc.Counters.Get(CounterProjectionBehind) != 1 {
		t.Fatalf("loose: %+v %v behind=%d", res, err, f.svc.Counters.Get(CounterProjectionBehind))
	}
	row := imported(1, "uas-1", numberA)
	row.Status = StatusSuspended
	_, err = f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer)
	wantProblem(t, err, 503, "")
	for _, r := range f.store.operators {
		if r.Status != StatusActive {
			t.Fatalf("rolled-back suspension stored: %v", r.Status)
		}
	}
	f.proj.failBegin = false
	if res, err := f.svc.ImportOperators(ctx, []ImportedOperator{row}, opts(false), importer); err != nil || res.Updated != 1 {
		t.Fatalf("with the projection up: %+v %v", res, err)
	}
	for id, r := range f.store.operators {
		if r.Status != StatusSuspended || f.proj.operators[id].Status != string(StatusSuspended) {
			t.Fatalf("%v / %v", r.Status, f.proj.operators[id])
		}
	}
}
