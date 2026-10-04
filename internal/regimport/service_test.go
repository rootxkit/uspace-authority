package regimport

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store"
)

var registrar = audit.Actor{Type: audit.ActorUser, ID: "registrar-1", Realm: audit.RealmConsole}

// fakeRegistry answers an import as the registry would: applied unless
// a problem was handed to it or it is told to refuse.
type fakeRegistry struct {
	mu      sync.Mutex
	opRuns  []registry.ImportOptions
	uasRuns []registry.ImportOptions
	refuse  bool
	err     error
	// block makes an import wait for its context to end (a slow
	// transaction).
	block bool
	// blockCommit makes it end as a commit cut off by its context does.
	blockCommit bool
}

func (f *fakeRegistry) result(kind string, rows int, o registry.ImportOptions) registry.ImportResult {
	res := registry.ImportResult{Kind: kind, DryRun: o.DryRun, Records: o.Records, Problems: o.Problems, Created: rows}
	if f.refuse {
		res.Problems = append(res.Problems, &core.FieldError{Field: "records[1].contact_email", Reason: "not an e-mail address"})
	}
	if res.Applied() {
		res.Version = 7
	}
	return res
}

func (f *fakeRegistry) ImportOperators(ctx context.Context, rows []registry.ImportedOperator, o registry.ImportOptions, _ audit.Actor) (registry.ImportResult, error) {
	if f.block || f.blockCommit {
		<-ctx.Done()
		if f.blockCommit {
			return registry.ImportResult{}, fmt.Errorf("commit: %w: %w", store.ErrCommitUnknown, ctx.Err())
		}
		return registry.ImportResult{}, ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opRuns = append(f.opRuns, o)
	return f.result(registry.ImportKindOperators, len(rows), o), f.err
}

func (f *fakeRegistry) ImportUAS(_ context.Context, rows []registry.ImportedUAS, o registry.ImportOptions, _ audit.Actor) (registry.ImportResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uasRuns = append(f.uasRuns, o)
	return f.result(registry.ImportKindUAS, len(rows), o), f.err
}

type memLedger struct {
	mu      sync.Mutex
	entries []Entry
	fail    bool
}

func (l *memLedger) Record(_ context.Context, e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return errors.New("ledger down")
	}
	l.entries = append(l.entries, e)
	return nil
}

func (l *memLedger) Last(_ context.Context, kind, origin string) (Entry, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.entries) - 1; i >= 0; i-- {
		if e := l.entries[i]; e.Kind == kind && e.Origin == origin {
			return e, true, nil
		}
	}
	return Entry{}, false, nil
}

func newService(t *testing.T) (*Service, *fakeRegistry, *memLedger) {
	t.Helper()
	reg, led := &fakeRegistry{}, &memLedger{}
	return &Service{Registry: reg, Ledger: led, Rules: testRules(t), MaxBytes: 1 << 20, MaxRecords: 100, Counters: &core.Counters{}}, reg, led
}

func status(err error) int { return httpx.ProblemFromError(err).Status }

// E-02 and E-01: without a rules file an import is refused 503 naming
// the variable; with one the same request runs.
func TestRunWithoutRulesIsRefused(t *testing.T) {
	s, _, _ := newService(t)
	rules := s.Rules
	s.Rules = nil
	_, err := s.Run(context.Background(), Request{Kind: "operators", Format: FormatCSV, Body: readFile(t, "operators.csv")}, registrar)
	if status(err) != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "REGISTRY_IMPORT_RULES_FILE") ||
		s.Counters.Get(CounterNotConfigured) != 1 {
		t.Fatalf("%v", err)
	}
	s.Rules = rules
	if rep, err := s.Run(context.Background(), Request{Kind: "operators", Format: FormatCSV, Body: readFile(t, "operators.csv"), Origin: OriginUpload}, registrar); err != nil || !rep.Applied() {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestRunRefusesBeforeReading(t *testing.T) {
	s, reg, _ := newService(t)
	ctx := context.Background()
	if _, err := s.Run(ctx, Request{Kind: "pilots", Format: FormatCSV, Body: []byte("a\n")}, registrar); status(err) != http.StatusBadRequest {
		t.Fatalf("kind: %v", err)
	}
	s.MaxBytes = 10
	if _, err := s.Run(ctx, Request{Kind: "operators", Format: FormatCSV, Body: []byte(strings.Repeat("a", 11))}, registrar); status(err) != http.StatusRequestEntityTooLarge {
		t.Fatalf("size: %v", err)
	}
	s.MaxBytes = 1 << 20
	if _, err := s.Run(ctx, Request{Kind: "operators", Format: FormatCSV, Body: []byte("a;a\n")}, registrar); status(err) != http.StatusBadRequest ||
		s.Counters.Get(CounterUnreadable) != 2 {
		t.Fatalf("unreadable: %v", err)
	}
	if len(reg.opRuns) != 0 {
		t.Fatal("the registry saw a refused file")
	}
}

// A dry run reaches the registry as one and leaves no ledger row; an
// applied import and a refused one each leave theirs.
func TestRunLedger(t *testing.T) {
	s, reg, led := newService(t)
	ctx := context.Background()
	req := Request{Kind: "operators", Format: FormatCSV, Body: readFile(t, "operators.csv"), Origin: OriginUpload}
	req.DryRun = true
	rep, err := s.Run(ctx, req, registrar)
	if err != nil || !rep.DryRun || !reg.opRuns[0].DryRun || len(led.entries) != 0 || rep.RulesVersion != "synthetic-1" || len(rep.SHA256) != 64 {
		t.Fatalf("dry run: %+v %v %v", rep, err, led.entries)
	}
	req.DryRun = false
	if _, err := s.Run(ctx, req, registrar); err != nil || len(led.entries) != 1 || led.entries[0].Outcome != OutcomeApplied || led.entries[0].Version != 7 {
		t.Fatalf("applied: %v %+v", err, led.entries)
	}
	reg.refuse = true
	rep, err = s.Run(ctx, req, registrar)
	if err != nil || rep.Applied() || len(led.entries) != 2 || led.entries[1].Outcome != OutcomeRefused || led.entries[1].Problems != 1 {
		t.Fatalf("refused: %+v %v %+v", rep, err, led.entries)
	}
	// The registry's problem names the column the rules map it from.
	if !strings.HasPrefix(rep.Problems[0].Reason, `column "E-mail": `) {
		t.Fatalf("not annotated: %+v", rep.Problems[0])
	}
	// A ledger that cannot be written leaves the import standing, counted.
	reg.refuse, led.fail = false, true
	if rep, err := s.Run(ctx, req, registrar); err != nil || !rep.Applied() || s.Counters.Get(CounterLedgerFailed) != 1 {
		t.Fatalf("ledger down: %+v %v", rep, err)
	}
}

// Mapping problems reach the registry beside the rows that mapped, so
// the import is refused whole and the report lists both.
func TestRunPassesMappingProblems(t *testing.T) {
	s, reg, _ := newService(t)
	body := strings.Replace(string(readFile(t, "operators.csv")), ";Suspended", ";Lost", 1)
	rep, err := s.Run(context.Background(), Request{Kind: "operators", Format: FormatCSV, Body: []byte(body)}, registrar)
	if err != nil || rep.Applied() || len(reg.opRuns[0].Problems) != 1 || reg.opRuns[0].Records != 2 {
		t.Fatalf("%+v %v %+v", rep, err, reg.opRuns)
	}
}

func TestRunReadsJSON(t *testing.T) {
	s, reg, _ := newService(t)
	body := `[{"Record ID":"TEST-UAS-1","Serial":"TESTA0123456789","Operator":"GEOTEST00000001","Class":"C1","Mass kg":0.8,"Remote ID":"broadcast","Status":"Active"}]`
	rep, err := s.Run(context.Background(), Request{Kind: "uas", Format: FormatJSON, Body: []byte(body)}, registrar)
	if err != nil || !rep.Applied() || len(reg.uasRuns) != 1 || rep.Created != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestCheckURL(t *testing.T) {
	for _, ok := range []string{"https://registry.example.test/export/{kind}.csv", "http://127.0.0.1:8099/{kind}", "http://localhost/{kind}"} {
		if err := CheckURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"https://registry.example.test/export.csv", "http://registry.example.test/{kind}", "ftp://x/{kind}", "{kind}"} {
		if err := CheckURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

type memLocker struct {
	mu   sync.Mutex
	held bool
}

func (l *memLocker) TryLock(context.Context, string) (func(), bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return nil, false, nil
	}
	l.held = true
	return func() { l.mu.Lock(); l.held = false; l.mu.Unlock() }, true, nil
}

// exportServer serves the two exports, counting the requests.
type exportServer struct {
	mu   sync.Mutex
	body map[string]string
	code int
	hits int
	auth []string
}

func (e *exportServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.hits++
	e.auth = append(e.auth, r.Header.Get("Authorization"))
	if e.code != 0 {
		w.WriteHeader(e.code)
		return
	}
	kind := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/export/"), ".csv")
	_, _ = w.Write([]byte(e.body[kind]))
}

func newJob(t *testing.T) (*Job, *exportServer, *fakeRegistry, *memLedger) {
	t.Helper()
	s, reg, led := newService(t)
	srv := &exportServer{body: map[string]string{"operators": string(readFile(t, "operators.csv")), "uas": string(readFile(t, "uas.csv"))}}
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	j := &Job{Service: s, Locker: &memLocker{}, Fetcher: Fetcher{URL: ts.URL + "/export/{kind}.csv", Token: "test-token", MaxBytes: 1 << 20,
		Client: NewClient(5 * time.Second)}}
	return j, srv, reg, led
}

// The re-import fetches both kinds and imports them; content run to an
// outcome before is not run again, applied or refused; content that
// changed is.
func TestJobRunsChangedContentOnly(t *testing.T) {
	j, srv, reg, led := newJob(t)
	ctx := context.Background()
	out, err := j.RunOnce(ctx)
	if err != nil || len(out) != 2 || !out[0].Applied || !out[1].Applied || len(led.entries) != 2 || led.entries[0].Origin != OriginFetch {
		t.Fatalf("first: %+v %v %+v", out, err, led.entries)
	}
	if srv.auth[0] != "Bearer test-token" {
		t.Fatalf("auth %q", srv.auth[0])
	}
	out, err = j.RunOnce(ctx)
	if err != nil || !out[0].Unchanged || !out[1].Unchanged || len(reg.opRuns) != 1 || j.Service.Counters.Get(CounterFetchUnchanged) != 2 {
		t.Fatalf("second: %+v %v runs=%d", out, err, len(reg.opRuns))
	}
	// Changed content runs; refused, it is not run again until it changes.
	srv.mu.Lock()
	srv.body["operators"] += "TEST-OP-3;GEOTEST00000003;Physical person;Other Person;;03.01.1981;;3 Test Street;o3@example.test;+995 555 000 003;;;;31.12.2030;Active\n"
	srv.mu.Unlock()
	reg.refuse = true
	out, err = j.RunOnce(ctx)
	if err != nil || out[0].Applied || out[0].Problems == 0 || len(reg.opRuns) != 2 {
		t.Fatalf("refused: %+v %v", out, err)
	}
	reg.refuse = false
	if out, err = j.RunOnce(ctx); err != nil || !out[0].Unchanged || len(reg.opRuns) != 2 {
		t.Fatalf("a refusal ran again: %+v %v runs=%d", out, err, len(reg.opRuns))
	}
	// New rules make the same content new.
	j.Service.Rules.RulesVersion = "synthetic-2"
	if out, err = j.RunOnce(ctx); err != nil || !out[0].Applied || len(reg.opRuns) != 3 {
		t.Fatalf("new rules: %+v %v", out, err)
	}
}

func TestJobFailuresAreCountedAndChangeNothing(t *testing.T) {
	j, srv, reg, _ := newJob(t)
	ctx := context.Background()
	srv.code = http.StatusForbidden
	out, err := j.RunOnce(ctx)
	if err != nil || out[0].Err == nil || out[0].Fetched || len(reg.opRuns) != 0 || j.Service.Counters.Get(CounterFetchFailed) != 2 {
		t.Fatalf("%+v %v", out, err)
	}
	srv.code = 0
	j.Fetcher.MaxBytes = 10
	if out, _ := j.RunOnce(ctx); out[0].Err == nil || !strings.Contains(out[0].Err.Error(), "larger") || len(reg.opRuns) != 0 {
		t.Fatalf("too large: %+v", out)
	}
	// Another replica holds the job.
	l := j.Locker.(*memLocker)
	l.held = true
	if out, err := j.RunOnce(ctx); err != nil || out != nil || j.Service.Counters.Get(CounterFetchSkipped) != 1 {
		t.Fatalf("held: %+v %v", out, err)
	}
}

// G-11: a redirect away from the agreed URL is not followed.
func TestFetchRefusesARedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("scraped")) }))
	defer other.Close()
	ts := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusFound))
	defer ts.Close()
	f := Fetcher{URL: ts.URL + "/{kind}", MaxBytes: 100, Client: NewClient(5 * time.Second)}
	if _, err := f.Fetch(context.Background(), "operators"); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("followed: %v", err)
	}
}

// E-10: an import past its write bound is rolled back and answered 503
// import_timeout; within it, it applies.
func TestRunBoundsTheTransaction(t *testing.T) {
	s, reg, led := newService(t)
	s.WriteTimeout = 50 * time.Millisecond
	reg.block = true
	req := Request{Kind: "operators", Format: FormatCSV, Body: readFile(t, "operators.csv"), Origin: OriginUpload}
	_, err := s.Run(context.Background(), req, registrar)
	if p := httpx.ProblemFromError(err); p.Status != http.StatusServiceUnavailable || p.Slug() != SlugTimeout || s.Counters.Get(CounterTimeout) != 1 {
		t.Fatalf("%v", err)
	}
	if len(led.entries) != 0 {
		t.Fatal("a timed-out import reached the ledger")
	}
	reg.block = false
	if rep, err := s.Run(context.Background(), req, registrar); err != nil || !rep.Applied() {
		t.Fatalf("%+v %v", rep, err)
	}
}

// A deadline that falls during the COMMIT leaves the outcome unknown:
// the import is answered 503 import_outcome_unknown, never "rolled
// back", is counted apart from a timeout before the commit, and stays
// out of the ledger so the re-import runs it again.
func TestRunReportsACommitCutOffAsUnknown(t *testing.T) {
	s, reg, led := newService(t)
	s.WriteTimeout = 50 * time.Millisecond
	reg.blockCommit = true
	req := Request{Kind: "operators", Format: FormatCSV, Body: readFile(t, "operators.csv"), Origin: OriginUpload}
	_, err := s.Run(context.Background(), req, registrar)
	p := httpx.ProblemFromError(err)
	if p.Status != http.StatusServiceUnavailable || p.Slug() != SlugOutcomeUnknown || strings.Contains(p.Detail, "rolled back") {
		t.Fatalf("%v", err)
	}
	if s.Counters.Get(CounterCommitUnknown) != 1 || s.Counters.Get(CounterTimeout) != 0 {
		t.Fatalf("counters: unknown %d timeout %d", s.Counters.Get(CounterCommitUnknown), s.Counters.Get(CounterTimeout))
	}
	if len(led.entries) != 0 {
		t.Fatal("an import of unknown outcome reached the ledger")
	}
}
