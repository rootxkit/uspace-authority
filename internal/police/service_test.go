package police

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/registry"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

const box = "44.7,41.6,44.9,41.8"

func problemOf(t *testing.T, err error) *httpx.Problem {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	return httpx.ProblemFromError(err)
}

func (k *kit) aircraft(ctx context.Context, t *testing.T, purpose string) gen.PoliceAircraftAnswer {
	t.Helper()
	out, err := k.svc.QueryAircraft(ctx, AircraftQuery{BBox: box, Purpose: purpose, CaseRef: "CASE-TEST-1"})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// E-01: a status-only purpose answers the aircraft without an identity
// and opens no personal data; a purpose of POLICE_PII_PURPOSES adds the
// identity, read through the registry with the purpose and annotated
// with the query, the case and the agency. Each is exactly one entry.
func TestAircraftIdentityOnlyForAPIIPurpose(t *testing.T) {
	k := newKit(t)
	k.track("TESTA0123456789", "GEOTEST00000001", ptr(uasID), k.now.Add(-2*time.Second), 2)
	ctx := as(officerID, insideIP)

	plain := k.aircraft(ctx, t, "public_order")
	if len(plain.Aircraft) != 1 || plain.Aircraft[0].Operator != nil || plain.PiiReleased || len(k.reg.reads) != 0 {
		t.Fatalf("status-only answer %+v, reads %v", plain, k.reg.reads)
	}
	if *plain.Aircraft[0].RegistrationNumber != "GEOTEST00000001" || plain.Mode != gen.PoliceAircraftAnswerModeLive {
		t.Fatalf("answer %+v", plain.Aircraft[0])
	}
	if e := k.led.entries[0]; e.Kind != KindAircraft || e.PII || e.ResultCount != 1 || e.Purpose != "public_order" || e.CaseRef != "CASE-TEST-1" {
		t.Fatalf("entry %+v", e)
	}

	pii := k.aircraft(ctx, t, "criminal_investigation")
	op := pii.Aircraft[0].Operator
	if op == nil || *op.FullName != "Test Person" || !pii.PiiReleased || len(k.reg.reads) != 1 {
		t.Fatalf("identity answer %+v", pii)
	}
	r := k.reg.reads[0]
	if r.purpose != "criminal_investigation" || r.annotations["case_ref"] != "CASE-TEST-1" || r.annotations["agency"] != agencyA ||
		r.annotations["police_query_id"] != pii.QueryId {
		t.Fatalf("personal-data read %+v", r)
	}
	if len(k.led.entries) != 2 || !k.led.entries[1].PII {
		t.Fatalf("entries %+v", k.led.entries)
	}
}

// The identity carries what reaches the person and nothing else (G-10).
func TestIdentityIsTheMinimalSubset(t *testing.T) {
	k := newKit(t)
	out, err := k.svc.QueryOperator(as(officerID, insideIP), LookupQuery{Key: "GEOTEST00000001", Purpose: "criminal_investigation", CaseRef: "C"})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustJSON(t, out)
	for _, kept := range []string{"Test Person", "1 Test Street", "p@example.test"} {
		if !strings.Contains(raw, kept) {
			t.Errorf("missing %q", kept)
		}
	}
	for _, dropped := range []string{"1990-01-01", "TEST-01", "TEST-INS"} {
		if strings.Contains(raw, dropped) {
			t.Errorf("the answer carries %q", dropped)
		}
	}
}

// E-01: inside the allow-list a query is answered; outside it is 403
// address_not_allowed, recorded as a refusal and never an entry. The
// account's row as it is now decides, not the session's start.
func TestAddressIsCheckedOnEveryQuery(t *testing.T) {
	k := newKit(t)
	k.aircraft(as(officerID, insideIP), t, "public_order")
	_, err := k.svc.QueryAircraft(as(officerID, outsideIP), AircraftQuery{BBox: box, Purpose: "public_order", CaseRef: "C"})
	if p := problemOf(t, err); p.Status != http.StatusForbidden || p.Slug() != SlugAddressNotAllowed {
		t.Fatalf("outside: %+v", p)
	}
	if len(k.led.entries) != 1 || len(k.led.refusals) != 1 || k.led.refusals[0]["reason"] != "address_not_allowed" ||
		k.led.refusals[0]["remote_ip"] != outsideIP {
		t.Fatalf("entries %d refusals %v", len(k.led.entries), k.led.refusals)
	}
	u := k.acc[officerID]
	u.IPAllow = []string{"203.0.113.0/24"}
	k.acc[officerID] = u
	if _, err := k.svc.QueryAircraft(as(officerID, insideIP), AircraftQuery{BBox: box, Purpose: "public_order", CaseRef: "C"}); problemOf(t, err).Slug() != SlugAddressNotAllowed {
		t.Fatal("a changed allow-list did not apply to an open session")
	}
}

// E-01: with a purpose and a case reference a query is answered; without
// either, or with a purpose off the list, it is 400 naming the field and
// nothing is recorded or read.
func TestPurposeAndCaseReferenceAreRequired(t *testing.T) {
	k := newKit(t)
	ctx := as(officerID, insideIP)
	for name, q := range map[string]AircraftQuery{
		"no purpose":       {BBox: box, CaseRef: "C"},
		"unknown purpose":  {BBox: box, Purpose: "curiosity", CaseRef: "C"},
		"no case":          {BBox: box, Purpose: "public_order"},
		"blank case":       {BBox: box, Purpose: "public_order", CaseRef: "  "},
		"control in case":  {BBox: box, Purpose: "public_order", CaseRef: "a\x00b"},
		"overlong case":    {BBox: box, Purpose: "public_order", CaseRef: strings.Repeat("c", MaxCaseRef+1)},
		"box too large":    {BBox: "44,41,45.5,42", Purpose: "public_order", CaseRef: "C"},
		"box out of range": {BBox: "44,91,45,92", Purpose: "public_order", CaseRef: "C"},
	} {
		_, err := k.svc.QueryAircraft(ctx, q)
		if p := problemOf(t, err); p.Status != http.StatusBadRequest {
			t.Errorf("%s: %+v", name, p)
		}
	}
	if len(k.led.entries) != 0 || len(k.reg.reads) != 0 || len(k.tel.asked) != 0 {
		t.Fatalf("a refused request was recorded or read: %d %d %d", len(k.led.entries), len(k.reg.reads), len(k.tel.asked))
	}
	k.aircraft(ctx, t, "public_order")
	if len(k.led.entries) != 1 {
		t.Fatal("the accepted twin was not recorded")
	}
}

// A console session, an unknown account, a console account and a
// disabled one reach no police query (the route admits only the police
// realm; the service checks again).
func TestOnlyAnActivePoliceAccountQueries(t *testing.T) {
	k := newKit(t)
	console := apiserver.WithIdentity(context.Background(), apiserver.Identity{ActorType: "user", Subject: officerID, Realm: apiserver.RealmConsole, Session: true})
	if _, err := k.svc.QuerySerial(console, LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); problemOf(t, err).Status != http.StatusForbidden {
		t.Fatal("a console session queried")
	}
	if _, err := k.svc.QuerySerial(as("ffffffffffffffffffffffffffffffff", insideIP), LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); problemOf(t, err).Status != http.StatusForbidden {
		t.Fatal("an unknown account queried")
	}
	u := k.acc[officerID]
	u.Status = "disabled"
	k.acc[officerID] = u
	if _, err := k.svc.QuerySerial(as(officerID, insideIP), LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); problemOf(t, err).Status != http.StatusForbidden {
		t.Fatal("a disabled account queried")
	}
	u.Status = "active"
	k.acc[officerID] = u
	if _, err := k.svc.QuerySerial(as(officerID, insideIP), LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); err != nil {
		t.Fatalf("the active twin: %v", err)
	}
}

// E-10: the user's budget is spent at its bound (429 with Retry-After
// through the handler, a refusal recorded), and frees after the window;
// the agency's budget holds across its accounts.
func TestBudgetsPerUserAndPerAgency(t *testing.T) {
	k := newKit(t)
	ctx := as(officerID, insideIP)
	h := Handler{Service: k.svc}
	for range k.svc.Budget.User {
		if _, err := k.svc.QuerySerial(ctx, LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := h.QueryPoliceSerial(ctx, gen.QueryPoliceSerialRequestObject{Serial: "TESTA0123456789",
		Params: gen.QueryPoliceSerialParams{Purpose: "public_order", CaseRef: "C"}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := resp.VisitQueryPoliceSerialResponse(rec); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("past the user's budget: %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if r := k.led.refusals; len(r) != 1 || r[0]["reason"] != "budget_spent_user" {
		t.Fatalf("refusals %v", r)
	}
	k.led.now = k.led.now.Add(time.Minute)
	if _, err := k.svc.QuerySerial(ctx, LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); err != nil {
		t.Fatalf("after the window: %v", err)
	}
	// A second account of the agency spends the agency's budget, the
	// first's query in the window counting against it.
	k.svc.Budget.Agency = 3
	second := "fedcba9876543210fedcba9876543210"
	u := k.acc[officerID]
	u.ID = second
	k.acc[second] = u
	for i := range 2 {
		if _, err := k.svc.QuerySerial(as(second, insideIP), LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"}); err != nil {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	_, err = k.svc.QuerySerial(as(second, insideIP), LookupQuery{Key: "TESTA0123456789", Purpose: "public_order", CaseRef: "C"})
	var spent *BudgetSpentError
	if !errors.As(err, &spent) || spent.Scope != "agency" {
		t.Fatalf("past the agency's budget: %v", err)
	}
}

// Live, the answer holds the newest positions oldest first, says when
// they were truncated and when the picture is stale or gapped; at an
// instant the window is placed around it, and the future and the time
// before retention are refused.
func TestAircraftWindowsPositionsAndSources(t *testing.T) {
	k := newKit(t)
	k.track("TRACK-A", "GEOTEST00000001", nil, k.now.Add(-time.Second), 5)
	ctx := as(officerID, insideIP)
	out := k.aircraft(ctx, t, "public_order")
	a := out.Aircraft[0]
	if len(a.Positions) != 3 || !a.PositionsTruncated || !a.Positions[0].At.Before(a.Positions[2].At) || a.Positions[2].At != k.now.Add(-time.Second) {
		t.Fatalf("positions %+v truncated %v", a.Positions, a.PositionsTruncated)
	}
	if out.Sources.Degraded || *out.Sources.NewestTrackAgeS != 2 || !out.WindowTo.Equal(k.now) || !out.WindowFrom.Equal(k.now.Add(-30*time.Second)) {
		t.Fatalf("sources %+v window %v %v", out.Sources, out.WindowFrom, out.WindowTo)
	}
	k.tel.newestAge = 300
	if out := k.aircraft(ctx, t, "public_order"); !out.Sources.Degraded {
		t.Fatal("a picture five minutes old is not degraded")
	}
	k.tel.newestAge, k.tel.gaps.Gaps, k.tel.gaps.Causes = 2, 1, []string{"stream_retention"}
	if out := k.aircraft(ctx, t, "public_order"); !out.Sources.Degraded || out.Sources.WriterGapCauses[0] != "stream_retention" {
		t.Fatal("a gapped window is not degraded")
	}
	at := k.now.Add(-time.Hour)
	out, err := k.svc.QueryAircraft(ctx, AircraftQuery{BBox: box, At: &at, Purpose: "public_order", CaseRef: "C"})
	if err != nil || out.Mode != gen.PoliceAircraftAnswerModeAt || !out.WindowFrom.Equal(at.Add(-time.Minute)) || !out.WindowTo.Equal(at.Add(time.Minute)) {
		t.Fatalf("at: %+v %v", out, err)
	}
	for name, bad := range map[string]time.Time{"future": k.now.Add(time.Second), "before retention": k.now.Add(-91 * 24 * time.Hour)} {
		if _, err := k.svc.QueryAircraft(ctx, AircraftQuery{BBox: box, At: &bad, Purpose: "public_order", CaseRef: "C"}); problemOf(t, err).Status != http.StatusBadRequest {
			t.Errorf("%s accepted", name)
		}
	}
	// E-10: more aircraft than an answer holds is truncated, said so.
	for i := range 11 {
		k.track("TRACK-"+string(rune('B'+i)), "", nil, k.now, 1)
	}
	if out := k.aircraft(ctx, t, "public_order"); len(out.Aircraft) != 10 || !out.Truncated {
		t.Fatalf("%d aircraft truncated %v", len(out.Aircraft), out.Truncated)
	}
}

// For a personal-data purpose an aircraft without an identification, or
// one the registry does not hold, says why it has no identity.
func TestAircraftUnresolvedIdentityIsSaid(t *testing.T) {
	k := newKit(t)
	k.track("NOREG", "", nil, k.now, 1)
	k.track("UNKNOWN", "GEOTEST99999999", nil, k.now.Add(-time.Second), 1)
	out := k.aircraft(as(officerID, insideIP), t, "criminal_investigation")
	got := map[string]string{}
	for _, a := range out.Aircraft {
		if a.Operator != nil || a.OperatorUnresolved == nil {
			t.Fatalf("%s: %+v", a.TrackId, a)
		}
		got[a.TrackId] = *a.OperatorUnresolved
	}
	if got["NOREG"] != UnresolvedNotIdentified || got["UNKNOWN"] != UnresolvedNotRegistered || out.PiiReleased {
		t.Fatalf("reasons %v released %v", got, out.PiiReleased)
	}
}

// Operator and serial lookups: found with the fleet, and an unknown key a
// 404 after the query is recorded with result_count 0.
func TestLookups(t *testing.T) {
	k := newKit(t)
	ctx := as(officerID, insideIP)
	op, err := k.svc.QueryOperator(ctx, LookupQuery{Key: " GEOTEST00000001 ", Purpose: "public_order", CaseRef: "C"})
	if err != nil || op.Operator.RegistrationNumber != "GEOTEST00000001" || len(op.Fleet) != 1 || op.Identity != nil {
		t.Fatalf("operator: %+v %v", op, err)
	}
	sn, err := k.svc.QuerySerial(ctx, LookupQuery{Key: "TESTA0123456789", Purpose: "criminal_investigation", CaseRef: "C"})
	if err != nil || sn.Uas.Serial != "TESTA0123456789" || sn.Operator.RegistrationNumber != "GEOTEST00000001" || sn.Identity == nil {
		t.Fatalf("serial: %+v %v", sn, err)
	}
	if _, err := k.svc.QueryOperator(ctx, LookupQuery{Key: "GEOTEST00000009", Purpose: "criminal_investigation", CaseRef: "C"}); problemOf(t, err).Status != http.StatusNotFound {
		t.Fatal("unknown operator")
	}
	if _, err := k.svc.QuerySerial(ctx, LookupQuery{Key: "TESTNONE", Purpose: "public_order", CaseRef: "C"}); problemOf(t, err).Status != http.StatusNotFound {
		t.Fatal("unknown serial")
	}
	last := k.led.entries[len(k.led.entries)-1]
	if len(k.led.entries) != 4 || last.ResultCount != 0 || last.PII || k.led.entries[2].PII {
		t.Fatalf("entries %+v", k.led.entries)
	}
	if len(k.reg.reads) != 1 {
		t.Fatalf("personal-data reads %v", k.reg.reads)
	}
	k.reg.operators["op-2"] = k.reg.operators[opID]
	if _, err := k.svc.QueryOperator(ctx, LookupQuery{Key: "GEOTEST00000001", Purpose: "public_order", CaseRef: "C"}); problemOf(t, err).Status != http.StatusConflict {
		t.Fatal("an ambiguous number was answered")
	}
}

// Exports: a status-only purpose is refused; one of incident_id and query
// is required; an incident export is a legal pack with a personal-data
// role, annotated; an area export opens an incident first; more aircraft
// than a case file holds is 413 and none is 422 after the record.
func TestExports(t *testing.T) {
	k := newKit(t)
	ctx := as(officerID, insideIP)
	from, to := k.now.Add(-time.Hour), k.now
	if _, err := k.svc.Export(ctx, ExportRequest{Purpose: "public_order", CaseRef: "C", From: from, To: to, IncidentID: "01J9ZZQYB1C2D3E4F5G6H7J8K9"}); problemOf(t, err).Slug() != SlugPurposeNotPII {
		t.Fatal("a status-only purpose exported")
	}
	b := box
	for name, r := range map[string]ExportRequest{
		"neither": {Purpose: "criminal_investigation", CaseRef: "C", From: from, To: to},
		"both":    {Purpose: "criminal_investigation", CaseRef: "C", From: from, To: to, IncidentID: "01J9ZZQYB1C2D3E4F5G6H7J8K9", BBox: &b},
		"window":  {Purpose: "criminal_investigation", CaseRef: "C", From: to, To: from, IncidentID: "01J9ZZQYB1C2D3E4F5G6H7J8K9"},
		"id":      {Purpose: "criminal_investigation", CaseRef: "C", From: from, To: to, IncidentID: "not-an-id"},
	} {
		if _, err := k.svc.Export(ctx, r); problemOf(t, err).Status != http.StatusBadRequest {
			t.Errorf("%s accepted", name)
		}
	}
	if len(k.led.entries) != 0 {
		t.Fatal("a refused export was recorded")
	}
	k.inc.views["01J9ZZQYB1C2D3E4F5G6H7J8K9"] = incidents.View{Aircraft: make([]pggen.ListIncidentAircraftRow, 2)}
	out, err := k.svc.Export(ctx, ExportRequest{Purpose: "criminal_investigation", CaseRef: "CASE-9", From: from, To: to, IncidentID: "01J9ZZQYB1C2D3E4F5G6H7J8K9"})
	if err != nil || out.IncidentOpened || out.Download != "/v1/police/exports/01JTESTPACK000000000000000/download" {
		t.Fatalf("incident export: %+v %v", out, err)
	}
	c := k.packs.created[0]
	if !c.piiRole || c.req.Kind != incidents.KindLegal || c.req.CaseRef != "CASE-9" || c.annotations["police_query_id"] != out.QueryId {
		t.Fatalf("pack call %+v", c)
	}
	if x := k.led.exports[out.PackId]; x.Agency != agencyA || x.QueryID != out.QueryId || k.led.entries[0].ResultCount != 2 {
		t.Fatalf("export link %+v entry %+v", x, k.led.entries[0])
	}
	// The area form: none -> 422 after the record; one -> an incident.
	if _, err := k.svc.Export(ctx, ExportRequest{Purpose: "criminal_investigation", CaseRef: "C", From: from, To: to, BBox: &b}); problemOf(t, err).Slug() != SlugNothingToExport {
		t.Fatal("an empty area exported")
	}
	if len(k.led.entries) != 2 || len(k.inc.opened) != 0 {
		t.Fatal("the empty area export was not recorded, or opened an incident")
	}
	k.track("TRACK-A", "GEOTEST00000001-xyz", ptr(uasID), k.now.Add(-time.Minute), 1)
	out, err = k.svc.Export(ctx, ExportRequest{Purpose: "criminal_investigation", CaseRef: "C", From: from, To: to, BBox: &b})
	if err != nil || !out.IncidentOpened || len(k.inc.opened) != 1 || k.inc.opened[0].Agency != agencyA || len(k.inc.opened[0].Aircraft) != 1 {
		t.Fatalf("area export: %+v %v %+v", out, err, k.inc.opened)
	}
	for i := range incidents.MaxAircraft {
		k.track("MANY-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "", nil, k.now, 1)
	}
	if _, err := k.svc.Export(ctx, ExportRequest{Purpose: "criminal_investigation", CaseRef: "C", From: from, To: to, BBox: &b}); problemOf(t, err).Status != http.StatusRequestEntityTooLarge {
		t.Fatal("more aircraft than a case file holds")
	}
}

// E-01: the requesting agency downloads its export (recorded, annotated,
// as a personal-data role); another agency gets 404 and a refusal row.
func TestDownloadOnlyByTheExportingAgency(t *testing.T) {
	k := newKit(t)
	k.led.exports["01JTESTPACK000000000000000"] = Export{PackID: "01JTESTPACK000000000000000", IncidentID: "01J9ZZQYB1C2D3E4F5G6H7J8K9",
		QueryID: "q", Agency: agencyA}
	data, _, err := k.svc.Download(as(officerID, insideIP), "01JTESTPACK000000000000000", "criminal_investigation", "C")
	if err != nil || string(data) != "zip" || len(k.packs.downloaded) != 1 || !k.packs.downloaded[0].piiRole ||
		k.packs.downloaded[0].annotations["case_ref"] != "C" || k.led.entries[0].Kind != KindDownload {
		t.Fatalf("own download: %v %+v", err, k.packs.downloaded)
	}
	u := k.acc[officerID]
	u.Agency = "TEST-OTHER"
	k.acc[officerID] = u
	if _, _, err := k.svc.Download(as(officerID, insideIP), "01JTESTPACK000000000000000", "criminal_investigation", "C"); problemOf(t, err).Status != http.StatusNotFound {
		t.Fatal("another agency downloaded")
	}
	if len(k.packs.downloaded) != 1 || len(k.led.refusals) != 1 || k.led.refusals[0]["reason"] != "not_this_agency" {
		t.Fatalf("downloads %d refusals %v", len(k.packs.downloaded), k.led.refusals)
	}
	if _, _, err := k.svc.Download(as(officerID, insideIP), "01JTESTPACK000000000000000", "public_order", "C"); problemOf(t, err).Slug() != SlugPurposeNotPII {
		t.Fatal("a status-only purpose downloaded a legal pack")
	}
}

// The DPO report: the month's bounds, the case reference of a police
// personal-data read from its payload, truncation, and police_query
// itself not listed twice.
func TestDPOReport(t *testing.T) {
	k := newKit(t)
	k.svc.Limits.DPOMaxRows = 2
	q := pggen.PoliceQuery{ID: "q1", At: k.now, Kind: KindAircraft, Query: []byte(`{"bbox":"x"}`), Pii: true}
	k.led.dpo = DPORecords{
		Queries: []pggen.PoliceQuery{q, q, q},
		Views: []pggen.PIIEventsInRangeRow{{ID: 7, EventType: audit.EventRegistryPIIViewed, ActorID: officerID,
			Payload: []byte(`{"case_ref":"CASE-1","agency":"TEST-POLICE","police_query_id":"q1"}`)}, {ID: 8, EventType: audit.EventRIDFramesViewed, Payload: []byte(`{}`)}},
	}
	out, err := k.svc.DPOReport(context.Background(), audit.Actor{Type: audit.ActorUser, ID: "auditor-1"}, "2026-10")
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated || len(out.PoliceQueries) != 2 || out.Totals.PoliceQueriesWithPii != 2 || len(out.PiiViews) != 2 ||
		*out.PiiViews[0].CaseRef != "CASE-1" || *out.PiiViews[0].PoliceQueryId != "q1" || out.PiiViews[1].CaseRef != nil {
		t.Fatalf("report %+v", out)
	}
	if !out.From.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || !out.To.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("month %v %v", out.From, out.To)
	}
	for _, typ := range k.led.dpoSeen {
		if typ == audit.EventPoliceQuery {
			t.Fatal("police_query listed among the events views")
		}
	}
	if len(k.led.dpoSeen) < 5 {
		t.Fatalf("view types %v", k.led.dpoSeen)
	}
	for _, bad := range []string{"2026-13", "2026-1", "202610", "", "2026-10-01"} {
		if _, err := k.svc.DPOReport(context.Background(), audit.Actor{Type: audit.ActorUser, ID: "a"}, bad); problemOf(t, err).Status != http.StatusBadRequest {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewPurposes(t *testing.T) {
	if _, err := NewPurposes([]string{"a_b", "c"}, []string{"c"}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string][2][]string{
		"empty":      {nil, nil},
		"bad code":   {{"Bad"}, nil},
		"twice":      {{"a", "a"}, nil},
		"pii not in": {{"a"}, {"b"}},
		"pii twice":  {{"a"}, {"a", "a"}},
	} {
		if _, err := NewPurposes(c[0], c[1]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseBBox(f *testing.F) {
	for _, s := range []string{box, "1,2,3", "NaN,0,1,1", "-180,-90,180,90", "0,0,0.5,0.5"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := ParseBBox("bbox", s, 1)
		if err != nil {
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field != "bbox" {
				t.Fatalf("%q: an error that names no field: %v", s, err)
			}
			return
		}
		if !(b.MinLon < b.MaxLon) || !(b.MinLat < b.MaxLat) || b.MaxLon-b.MinLon > 1 || b.MaxLat-b.MinLat > 1 {
			t.Fatalf("%q accepted as %+v", s, b)
		}
		if again, err := ParseBBox("bbox", b.String(), 1); err != nil || again != b {
			t.Fatalf("%q round trip %+v %v", s, again, err)
		}
	})
}

func FuzzCheckCaseRef(f *testing.F) {
	for _, s := range []string{"CASE-1", "", " x ", "a\x00", strings.Repeat("ქ", 101)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := CheckCaseRef(s)
		if err != nil {
			return
		}
		if v == "" || len([]rune(v)) > MaxCaseRef || strings.ContainsAny(v, "\x00\n\r\t") {
			t.Fatalf("%q accepted as %q", s, v)
		}
	})
}

func FuzzParseMonth(f *testing.F) {
	for _, s := range []string{"2026-10", "2026-13", "x", "0000-01"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		from, to, err := ParseMonth(s)
		if err != nil {
			return
		}
		if from.Format("2006-01") != s || to.Sub(from) < 28*24*time.Hour || to.Sub(from) > 31*24*time.Hour {
			t.Fatalf("%q -> %v %v", s, from, to)
		}
	})
}

// E-10: an operator's fleet past POLICE_MAX_FLEET is cut and said so.
func TestFleetBound(t *testing.T) {
	k := newKit(t)
	for i := range k.svc.Limits.MaxFleet {
		id := "uas-extra-" + string(rune('a'+i))
		k.reg.uas[id] = registry.UAS{ID: id, OperatorID: opID, Serial: "TESTX" + string(rune('A'+i)), Status: registry.StatusActive}
	}
	out, err := k.svc.QueryOperator(as(officerID, insideIP), LookupQuery{Key: "GEOTEST00000001", Purpose: "public_order", CaseRef: "C"})
	if err != nil || len(out.Fleet) != k.svc.Limits.MaxFleet || !out.FleetTruncated {
		t.Fatalf("%d aircraft, truncated %v, %v", len(out.Fleet), out.FleetTruncated, err)
	}
	delete(k.reg.uas, "uas-extra-a")
	if out, _ := k.svc.QueryOperator(as(officerID, insideIP), LookupQuery{Key: "GEOTEST00000001", Purpose: "public_order", CaseRef: "C"}); out.FleetTruncated {
		t.Fatal("a fleet at the bound was said truncated")
	}
}
