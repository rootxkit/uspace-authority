package occurrences

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

var aware = time.Date(2026, 10, 3, 10, 5, 0, 0, time.UTC)

func problemOf(t *testing.T, err error) *httpx.Problem {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	return httpx.ProblemFromError(err)
}

func wantProblem(t *testing.T, err error, status int, slug string) {
	t.Helper()
	p := problemOf(t, err)
	if p.Status != status || p.Slug() != slug {
		t.Fatalf("got %d %s (%v), want %d %s", p.Status, p.Slug(), err, status, slug)
	}
}

func wantField(t *testing.T, err error, field string) {
	t.Helper()
	p := problemOf(t, err)
	for _, f := range p.Errors {
		if f.Field == field {
			return
		}
	}
	t.Fatalf("no error naming %s: %+v (%v)", field, p.Errors, err)
}

// 376/2014 Art. 4(7)-(8), E-01 on both sides of the boundary: exactly at
// the deadline is within, a microsecond later is late.
func TestWithinAtTheDeadline(t *testing.T) {
	d := 72 * time.Hour
	for _, c := range []struct {
		received time.Time
		want     bool
	}{
		{aware, true},
		{aware.Add(d - time.Microsecond), true},
		{aware.Add(d), true},
		{aware.Add(d + time.Microsecond), false},
		{aware.Add(30 * 24 * time.Hour), false},
	} {
		if got := Within(aware, c.received, d); got != c.want {
			t.Errorf("received %s after awareness: within %v, want %v", c.received.Sub(aware), got, c.want)
		}
	}
}

// The intake stores the flag the deadline gives, at both sides of it,
// and a late report is accepted, never refused.
func TestIntakeFlagsALateReportAndNeverRefusesIt(t *testing.T) {
	for _, c := range []struct {
		after time.Duration
		want  bool
	}{{72 * time.Hour, true}, {72*time.Hour + time.Millisecond, false}, {40 * 24 * time.Hour, false}} {
		s, _ := service(t, aware.Add(c.after), newSealer(t, "occ-test"))
		rc, err := s.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody))
		if err != nil {
			t.Fatalf("%s: %v", c.after, err)
		}
		if rc.Report.Within72h != c.want || rc.Replayed {
			t.Fatalf("%s: %+v", c.after, rc)
		}
		late := s.Counters.Snapshot()[CounterLate]
		if (late == 1) == c.want {
			t.Fatalf("%s: late counter %d", c.after, late)
		}
	}
}

// Idempotent on (reporter_org, report_ref): the same report again is the
// first receipt and writes nothing; other content under the reference is
// 409; the same reference from another sender is another report.
func TestIntakeIsIdempotentOnTheSenderAndItsReference(t *testing.T) {
	s, m := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	ctx := context.Background()
	first, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, anspBody))
	if err != nil || first.Replayed || first.Report.ReporterOrg != "ansp-01" || first.Report.State != StateReceived {
		t.Fatalf("%+v %v", first, err)
	}
	again, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, anspBody))
	if err != nil || !again.Replayed || again.Report.ID != first.Report.ID {
		t.Fatalf("replay: %+v %v", again, err)
	}
	if n := len(m.eventsOf("occurrence_received")); n != 1 {
		t.Fatalf("%d occurrence_received rows, want 1 (a replay writes none)", n)
	}
	other := mutate(t, anspBody, func(m map[string]any) { m["narrative"] = "Another account of it." })
	_, err = s.Intake(ctx, ClientOrigin(anspActor), input(t, other))
	wantProblem(t, err, http.StatusConflict, SlugRefConflict)
	wantField(t, err, "report_ref")
	third, err := s.Intake(ctx, ClientOrigin(usspActor), input(t, anspBody))
	if err != nil || third.Replayed || third.Report.ID == first.Report.ID || third.Report.ReporterOrg != "ussp-tst-01" {
		t.Fatalf("another sender: %+v %v", third, err)
	}
	snap := s.Counters.Snapshot()
	if snap[CounterReceived] != 2 || snap[CounterReplayed] != 1 || snap[CounterRefRefused] != 1 {
		t.Fatalf("counters %v", snap)
	}
}

// The reporter's person reference is sealed under the occurrence key,
// bound to the report's id, and never in the events row; without the key
// such a report is 503 and nothing is stored, while a report without a
// reference is still received (E-01 pair).
func TestPersonReferenceIsSealedOrTheReportWaits(t *testing.T) {
	sealer := newSealer(t, "occ-test")
	s, m := service(t, aware.Add(time.Hour), sealer)
	rc, err := s.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody))
	if err != nil {
		t.Fatal(err)
	}
	r := m.reports[rc.Report.ID]
	if strings.Contains(string(r.PersonSealed), "staff-0042") || r.PersonKeyID != "occ-test" {
		t.Fatalf("stored %q under %q", r.PersonSealed, r.PersonKeyID)
	}
	if p, err := sealer.Open(r.PersonKeyID, r.PersonSealed, []byte(r.ID)); err != nil || string(p) != "staff-0042" {
		t.Fatalf("opened %q %v", p, err)
	}
	if _, err := sealer.Open(r.PersonKeyID, r.PersonSealed, []byte("another-row")); err == nil {
		t.Fatal("the sealed reference opens under another row's id")
	}
	raw, _ := json.Marshal(m.events)
	if strings.Contains(string(raw), "staff-0042") || strings.Contains(string(raw), "Synthetic airprox") {
		t.Fatalf("the events row holds the reporter or the text: %s", raw)
	}

	nokey, m2 := service(t, aware.Add(time.Hour), nil)
	_, err = nokey.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody))
	wantProblem(t, err, http.StatusServiceUnavailable, SlugKeyUnavailable)
	if len(m2.reports) != 0 || len(m2.events) != 0 {
		t.Fatalf("stored %d reports and %d events without the key", len(m2.reports), len(m2.events))
	}
	anon := mutate(t, anspBody, func(m map[string]any) { m["reporter"] = map[string]any{"org": "ansp-01"} })
	rc, err = nokey.Intake(context.Background(), ClientOrigin(anspActor), input(t, anon))
	if err != nil || len(rc.Report.PersonSealed) != 0 {
		t.Fatalf("a report without a reference: %+v %v", rc, err)
	}
}

// became_aware_at ahead of the database clock by more than the skew is
// refused; within the skew it is received.
func TestBecameAwareAheadOfTheClock(t *testing.T) {
	s, _ := service(t, aware.Add(-4*time.Minute), newSealer(t, "occ-test"))
	if _, err := s.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody)); err != nil {
		t.Fatalf("within the skew: %v", err)
	}
	s, m := service(t, aware.Add(-6*time.Minute), newSealer(t, "occ-test"))
	_, err := s.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody))
	wantField(t, err, "became_aware_at")
	if len(m.reports) != 0 {
		t.Fatal("stored a refused report")
	}
}

// An operator's report (947 Art. 19(2)) is the mandatory channel under
// operator:<public part>, whatever channel it named.
func TestOperatorReportIsMandatoryUnderItsRegistration(t *testing.T) {
	s, _ := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	o, err := OperatorOrigin(officer, " FIN87astrdge12k8-xyz ", s.PublicPart)
	if err != nil || o.Org != "operator:FIN87astrdge12k8" || !o.Operator {
		t.Fatalf("%+v %v", o, err)
	}
	vol := mutate(t, anspBody, func(m map[string]any) { m["channel"] = "voluntary" })
	rc, err := s.Intake(context.Background(), o, input(t, vol))
	if err != nil || rc.Report.Channel != ChannelMandatory || rc.Report.Origin != OriginOperator || rc.Report.ReporterOrg != "operator:FIN87astrdge12k8" {
		t.Fatalf("%+v %v", rc.Report, err)
	}
	if s.Counters.Snapshot()[CounterChannelOverridden] != 1 || s.Counters.Snapshot()[CounterOrgIgnored] != 0 {
		t.Fatalf("counters %v", s.Counters.Snapshot())
	}
	if _, err := OperatorOrigin(officer, "  ", s.PublicPart); err == nil {
		t.Fatal("an empty registration is an origin")
	}
}

// reporter.org is informational: the token's sub is recorded, and a
// differing name is counted; the same name is not (E-01 pair).
func TestReporterOrgFromTheToken(t *testing.T) {
	s, _ := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	if _, err := s.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody)); err != nil {
		t.Fatal(err)
	}
	if n := s.Counters.Snapshot()[CounterOrgIgnored]; n != 0 {
		t.Fatalf("ignored %d with the same org", n)
	}
	rc, err := s.Intake(context.Background(), ClientOrigin(usspActor), input(t, anspBody))
	if err != nil || rc.Report.ReporterOrg != "ussp-tst-01" || s.Counters.Snapshot()[CounterOrgIgnored] != 1 {
		t.Fatalf("%+v %v %v", rc.Report, err, s.Counters.Snapshot())
	}
	if _, err := s.Intake(context.Background(), Origin{}, input(t, anspBody)); err == nil {
		t.Fatal("a report without a sender was received")
	}
}

// The reporter is read with a purpose, and the read is an events row
// with it (pii_view); a sealed reference without the key is 503 and a
// changed row does not open, neither audited as a read.
func TestReporterIsReadWithAPurposeAndAudited(t *testing.T) {
	sealer := newSealer(t, "occ-test")
	s, m := service(t, aware.Add(time.Hour), sealer)
	ctx := context.Background()
	rc, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, anspBody))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reporter(ctx, officer, rc.Report.ID, "  "); err == nil {
		t.Fatal("read without a purpose")
	}
	v, err := s.Reporter(ctx, officer, rc.Report.ID, "follow-up interview")
	if err != nil || v.PersonRef != "staff-0042" || v.ReporterOrg != "ansp-01" || v.ReportRef != "ANSP-OCC-2026-0001" || !v.HasPerson {
		t.Fatalf("%+v %v", v, err)
	}
	ev := m.eventsOf("occurrence_reporter_viewed")
	if len(ev) != 1 || ev[0].Purpose != "follow-up interview" || ev[0].Actor != officer {
		t.Fatalf("events %+v", ev)
	}
	if _, err := s.Reporter(ctx, officer, ulidOf(999), "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent report: %v", err)
	}
	s.Sealer = nil
	_, err = s.Reporter(ctx, officer, rc.Report.ID, "again")
	wantProblem(t, err, http.StatusServiceUnavailable, SlugKeyUnavailable)
	s.Sealer = newSealer(t, "occ-test")
	_, err = s.Reporter(ctx, officer, rc.Report.ID, "again")
	wantProblem(t, err, http.StatusInternalServerError, SlugReporterUnknown)
	if n := len(m.eventsOf("occurrence_reporter_viewed")); n != 1 {
		t.Fatalf("%d reads audited; refused reads return nothing and are not reads", n)
	}
}

// Classification from the configured scheme only, the state machine of
// the analysis, and a closed report frozen.
func TestClassificationAndAnalysisLifecycle(t *testing.T) {
	s, m := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	ctx := context.Background()
	rc, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, anspBody))
	if err != nil {
		t.Fatal(err)
	}
	id := rc.Report.ID
	st := func(v string) *string { return &v }
	_, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{Analysis: st("draft"), State: st(StateAnalysed)})
	wantProblem(t, err, http.StatusConflict, SlugNotClassified)
	_, err = s.Classify(ctx, officer, id, "catastrophic")
	wantField(t, err, "risk_classification")
	r, err := s.Classify(ctx, officer, id, "incident")
	if err != nil || r.State != StateClassified || r.RiskClassification != "incident" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err = s.Classify(ctx, officer, id, "serious_incident"); err != nil || r.State != StateClassified {
		t.Fatalf("reclassify: %+v %v", r, err)
	}
	_, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{State: st(StateAnalysed)})
	wantField(t, err, "analysis")
	_, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{State: st(StateClosed)})
	wantProblem(t, err, http.StatusConflict, SlugNotAnalysed)
	_, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{})
	wantField(t, err, "body")
	_, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{State: st(StateReceived)})
	wantField(t, err, "state")
	if r, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{Analysis: st("Loss of separation in class G."), FollowUp: st("Safety notice."), State: st(StateAnalysed)}); err != nil || r.State != StateAnalysed {
		t.Fatalf("analysed: %+v %v", r, err)
	}
	if r, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{State: st(StateClosed)}); err != nil || r.State != StateClosed || r.ClosedAt == nil {
		t.Fatalf("closed: %+v %v", r, err)
	}
	_, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{FollowUp: st("more")})
	wantProblem(t, err, http.StatusConflict, SlugClosed)
	_, err = s.Classify(ctx, officer, id, "incident")
	wantProblem(t, err, http.StatusConflict, SlugClosed)
	ev := m.eventsOf("occurrence_analysis_updated")
	if len(ev) != 2 {
		t.Fatalf("analysis events %+v", ev)
	}
	raw, _ := json.Marshal(ev)
	if strings.Contains(string(raw), "Loss of separation") || !strings.Contains(string(raw), `"changed":["analysis","follow_up","state"]`) {
		t.Fatalf("payload %s", raw)
	}
	if n := len(m.eventsOf("occurrence_classified")); n != 2 {
		t.Fatalf("%d classification events", n)
	}
	_, err = s.UpdateAnalysis(ctx, officer, id, AnalysisPatch{Analysis: st(strings.Repeat("a", MaxAnalysisBytes+1))})
	wantField(t, err, "analysis")
}

// The planted name of a reporter is everywhere a free-text or reporter
// field can carry it; the export holds it only in the narrative, which
// is exported as written and redacted by the officer (the record says
// so). The structured reporter fields, the officers' notes and the ids
// that lead back to an account are absent.
func TestExportLeavesTheReporterOut(t *testing.T) {
	const name = "Nino Testadze"
	s, m := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	ctx := context.Background()
	body := mutate(t, anspBody, func(m map[string]any) {
		m["report_ref"] = "REF " + name
		m["reporter"] = map[string]any{"org": name, "person_ref": name}
		m["aircraft"] = []any{map[string]any{"serial": "TESTSER0001", "operator_reg": "FIN87astrdge12k8-xyz",
			"flight_id": name, "authorisation_number": name}}
		m["intent_refs"] = []any{name}
		m["evidence_urls"] = []any{"https://evidence.example.test/" + strings.ReplaceAll(name, " ", "-")}
		m["narrative"] = "Reported by " + name + " on the ground."
	})
	rc, err := s.Intake(ctx, Origin{Actor: usspActor, Org: "org " + name}, input(t, body))
	if err != nil {
		t.Fatal(err)
	}
	st := func(v string) *string { return &v }
	if _, err := s.Classify(ctx, officer, rc.Report.ID, "incident"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateAnalysis(ctx, officer, rc.Report.ID, AnalysisPatch{Analysis: st("Spoke to " + name), FollowUp: st("Call " + name)}); err != nil {
		t.Fatal(err)
	}
	res, err := s.Export(ctx, officer, ExportRequest{From: aware, To: aware.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	content := string(res.Content)
	if n := strings.Count(content, name); n != 1 {
		t.Fatalf("the name appears %d times:\n%s", n, content)
	}
	if strings.Contains(content, strings.ReplaceAll(name, " ", "-")) {
		t.Fatal("the evidence URL is exported")
	}
	var doc struct {
		Format       string `json:"format"`
		Deidentified bool   `json:"deidentified"`
		RecordCount  int    `json:"record_count"`
		Records      []struct {
			Narrative          string `json:"narrative"`
			NarrativeRedaction string `json:"narrative_redaction"`
			Aircraft           []struct {
				SerialNumber         string `json:"serial_number"`
				OperatorRegistration string `json:"operator_registration"`
			} `json:"aircraft"`
			RiskClassification string `json:"risk_classification"`
			ReporterCategory   string `json:"reporter_category"`
		} `json:"records"`
	}
	if err := json.Unmarshal(res.Content, &doc); err != nil {
		t.Fatal(err)
	}
	rec := doc.Records[0]
	if doc.Format != FormatECCAIRSDraft || !doc.Deidentified || doc.RecordCount != 1 || !strings.Contains(rec.Narrative, name) ||
		!strings.HasPrefix(rec.NarrativeRedaction, "not_redacted") || rec.Aircraft[0].SerialNumber != "TESTSER0001" ||
		rec.Aircraft[0].OperatorRegistration != "FIN87astrdge12k8" || rec.RiskClassification != "incident" || rec.ReporterCategory != "organisation" {
		t.Fatalf("%+v", doc)
	}
	for _, absent := range []string{"staff-0042", "-xyz", "reporter_org", "report_ref", "person_ref", "analysis", "follow_up", "flight_id",
		"authorisation_number", "intent_refs", "evidence_urls"} {
		if strings.Contains(content, absent) {
			t.Errorf("the export holds %q", absent)
		}
	}
	sum := sha256.Sum256(res.Content)
	if res.Export.ContentHash != "sha256:"+hex.EncodeToString(sum[:]) || res.Export.SizeBytes != int64(len(res.Content)) || res.Export.RecordCount != 1 {
		t.Fatalf("export %+v", res.Export)
	}
	ev := m.eventsOf("occurrence_export_created")
	if len(ev) != 1 || ev[0].Payload.(map[string]any)["content_hash"] != res.Export.ContentHash || len(m.exports) != 1 ||
		m.exports[0].ContentHash != res.Export.ContentHash {
		t.Fatalf("recorded %+v %+v", ev, m.exports)
	}
}

// Every exporter of the build leaves the reporter out (the interface's
// contract): planted values in the reporter fields never appear.
func TestEveryExporterLeavesTheReporterOut(t *testing.T) {
	r := Report{ID: ulidOf(1), ReporterOrg: "PLANTED-ORG", ReportRef: "PLANTED-REF", PersonSealed: []byte("PLANTED-SEAL"), PersonKeyID: "PLANTED-KEY",
		Channel: ChannelMandatory, Origin: OriginClient, Category: "other", Analysis: "PLANTED-ANALYSIS", FollowUp: "PLANTED-FOLLOW",
		Aircraft:   []Aircraft{{Serial: "TESTSER2", FlightID: "PLANTED-FLIGHT", AuthorisationNumber: "PLANTED-AUTH"}},
		IntentRefs: []string{"PLANTED-INTENT"}, EvidenceURLs: []string{"https://x.example.test/PLANTED-URL"}, State: StateReceived}
	for name, ex := range DefaultExporters() {
		b, err := ex.Export(ExportMeta{ExportID: ulidOf(2), CreatedAt: aware, From: aware, To: aware.Add(time.Hour)}, []Report{r})
		if err != nil || ex.Format() != name {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(b), "PLANTED") {
			t.Errorf("%s exports a planted value:\n%s", name, b)
		}
		if !strings.Contains(string(b), "TESTSER2") {
			t.Errorf("%s leaves out the serial", name)
		}
	}
}

// E-10: an export over the bound is refused, never thinned; at the bound
// it is built. An unknown format and an empty window are refused.
func TestExportBoundsAndFormat(t *testing.T) {
	s, _ := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	s.MaxExportRecords = 2
	ctx := context.Background()
	for i := range 2 {
		body := mutate(t, anspBody, func(m map[string]any) { m["report_ref"] = fmt.Sprintf("ANSP-OCC-2026-%04d", i+1) })
		if _, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, body)); err != nil {
			t.Fatal(err)
		}
	}
	w := ExportRequest{From: aware, To: aware.Add(2 * time.Hour)}
	if res, err := s.Export(ctx, officer, w); err != nil || res.Export.RecordCount != 2 {
		t.Fatalf("at the bound: %+v %v", res.Export, err)
	}
	body := mutate(t, anspBody, func(m map[string]any) { m["report_ref"] = "ANSP-OCC-2026-0003" })
	if _, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, body)); err != nil {
		t.Fatal(err)
	}
	_, err := s.Export(ctx, officer, w)
	wantProblem(t, err, http.StatusBadRequest, SlugExportTooLarge)
	_, err = s.Export(ctx, officer, ExportRequest{From: aware, To: aware.Add(2 * time.Hour), Format: "e5x"})
	wantProblem(t, err, http.StatusBadRequest, SlugUnknownFormat)
	_, err = s.Export(ctx, officer, ExportRequest{From: aware, To: aware})
	wantField(t, err, "to")
	if res, err := s.Export(ctx, officer, ExportRequest{From: aware.Add(-48 * time.Hour), To: aware.Add(-24 * time.Hour)}); err != nil || res.Export.RecordCount != 0 {
		t.Fatalf("an empty window: %+v %v", res, err)
	}
	snap := s.Counters.Snapshot()
	if snap[CounterExportTooLarge] != 1 || snap[CounterExports] != 2 {
		t.Fatalf("counters %v", snap)
	}
}

func TestValidRiskClasses(t *testing.T) {
	if err := validRiskClasses([]string{"accident", "serious_incident"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{nil, {"Accident"}, {"a", "a"}, {strings.Repeat("a", 65)}} {
		if err := validRiskClasses(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestStoreErrorsPassThrough(t *testing.T) {
	s, _ := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	s.Store = failing{}
	if _, err := s.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody)); !errors.Is(err, errBoom) {
		t.Fatalf("%v", err)
	}
	if p := httpx.ProblemFromError(errBoom); p.Status != http.StatusInternalServerError {
		t.Fatalf("%+v", p)
	}
	var fe *core.FieldError
	if errors.As(errBoom, &fe) {
		t.Fatal("a store failure reads as a field error")
	}
}

// E-15: a zero deadline refuses the intake rather than judging every
// report on time; the configured one receives it (the tests above).
func TestZeroDeadlineRefusesTheIntake(t *testing.T) {
	s, m := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	s.Deadline = 0
	if _, err := s.Intake(context.Background(), ClientOrigin(anspActor), input(t, anspBody)); err == nil || len(m.reports) != 0 {
		t.Fatalf("received with no deadline: %v", err)
	}
}

type failing struct{}

func (failing) WithTx(context.Context, func(Tx) error) error { return errBoom }
func (failing) Get(context.Context, string) (Report, error)  { return Report{}, errBoom }
func (failing) List(context.Context, Filter) ([]Report, error) {
	return nil, errBoom
}

// The purpose of a reporter read is bounded at MaxPurposeBytes and holds
// no control character, like every text the service records: at the
// bound it is read and audited, a byte over it is refused and nothing is
// written (E-10 pair).
func TestReporterPurposeIsBounded(t *testing.T) {
	s, m := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	ctx := context.Background()
	rc, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, anspBody))
	if err != nil {
		t.Fatal(err)
	}
	atBound := strings.Repeat("p", MaxPurposeBytes)
	if v, err := s.Reporter(ctx, officer, rc.Report.ID, atBound); err != nil || v.PersonRef != "staff-0042" {
		t.Fatalf("a purpose at the bound: %+v %v", v, err)
	}
	for name, purpose := range map[string]string{
		"over the bound": strings.Repeat("p", MaxPurposeBytes+1),
		"a control char": "follow-up\x00interview",
		"invalid UTF-8":  "follow-up \xff",
	} {
		_, err := s.Reporter(ctx, officer, rc.Report.ID, purpose)
		wantField(t, err, "purpose")
		if n := len(m.eventsOf("occurrence_reporter_viewed")); n != 1 {
			t.Fatalf("%s: %d reads audited, want 1", name, n)
		}
	}
	if ev := m.eventsOf("occurrence_reporter_viewed"); ev[0].Purpose != atBound {
		t.Fatalf("audited purpose %q", ev[0].Purpose)
	}
}

// spyExporter records whether the store's transaction was open while the
// document was built: the memory store holds its lock for a whole
// transaction.
type spyExporter struct {
	m      *memStore
	inner  Exporter
	inTx   bool
	called int
}

func (e *spyExporter) Format() string { return e.inner.Format() }

func (e *spyExporter) Export(meta ExportMeta, reports []Report) ([]byte, error) {
	e.called++
	if e.m.mu.TryLock() {
		e.m.mu.Unlock()
	} else {
		e.inTx = true
	}
	return e.inner.Export(meta, reports)
}

// E-10: an export is bounded by its bytes as well as its records. At the
// byte bound it is built, sealed and recorded; a byte over it is refused
// (export_too_large), never truncated, and records nothing. The document
// is built outside any transaction of the store.
func TestExportByteBoundAndNoOpenTransaction(t *testing.T) {
	s, m := service(t, aware.Add(time.Hour), newSealer(t, "occ-test"))
	spy := &spyExporter{m: m, inner: ECCAIRSDraft{}}
	s.Exporters = Exporters{FormatECCAIRSDraft: spy}
	ctx := context.Background()
	for i := range 3 {
		body := mutate(t, anspBody, func(m map[string]any) { m["report_ref"] = fmt.Sprintf("ANSP-OCC-2026-%04d", i+1) })
		if _, err := s.Intake(ctx, ClientOrigin(anspActor), input(t, body)); err != nil {
			t.Fatal(err)
		}
	}
	w := ExportRequest{From: aware, To: aware.Add(2 * time.Hour)}
	s.MaxExportBytes = 1 << 20
	first, err := s.Export(ctx, officer, w)
	if err != nil || first.Export.RecordCount != 3 {
		t.Fatalf("%+v %v", first.Export, err)
	}
	if spy.inTx {
		t.Fatal("the export was built inside an open transaction")
	}
	size := first.Export.SizeBytes
	s.MaxExportBytes = size
	if res, err := s.Export(ctx, officer, w); err != nil || res.Export.SizeBytes != size {
		t.Fatalf("at the byte bound: %+v %v", res.Export, err)
	}
	exports, events := len(m.exports), len(m.eventsOf("occurrence_export_created"))
	s.MaxExportBytes = size - 1
	_, err = s.Export(ctx, officer, w)
	wantProblem(t, err, http.StatusBadRequest, SlugExportTooLarge)
	wantField(t, err, "to")
	if len(m.exports) != exports || len(m.eventsOf("occurrence_export_created")) != events {
		t.Fatal("a refused export was recorded")
	}
	s.MaxExportBytes = 0
	if _, err := s.Export(ctx, officer, w); err == nil {
		t.Fatal("an export without a byte bound")
	}
	snap := s.Counters.Snapshot()
	if snap[CounterExportTooLarge] != 1 || snap[CounterExports] != 2 || spy.inTx {
		t.Fatalf("counters %v, built in a transaction %v", snap, spy.inTx)
	}
}
