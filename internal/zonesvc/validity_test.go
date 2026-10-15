package zonesvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// The period of validity (valid_from, valid_to; 2019/947 Art. 15(3)) is
// published as the feature's limitedApplicability, the only per-zone
// validity ED-318 has, and bounds every applicability answer. Before
// this a zone that ended in 2027 was published with no end, and the
// CISP answered "applies" for it in 2028.

var (
	validFrom = time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	validTo   = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
)

func draftBetween(f string, from, to time.Time) DraftInput {
	return DraftInput{Feature: []byte(f), ValidFrom: ptr(from), ValidTo: ptr(to)}
}

// publishedFeature publishes f with the period and returns the one
// feature of the outbox payload, the bytes the CISP is sent.
func publishedFeature(t *testing.T, s *Service, st *memStore, f string, from, to time.Time) (ed318.Feature, []byte) {
	t.Helper()
	ctx := context.Background()
	v, err := s.Draft(ctx, DatasetZones, draftBetween(f, from, to), true, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetZones, v.Identifier, v.ZoneVersion, admin); err != nil {
		t.Fatal(err)
	}
	p, err := s.Publish(ctx, DatasetZones, admin)
	if err != nil {
		t.Fatal(err)
	}
	payload := st.payload(p.Publication.ID)
	fc, probs := ed318.Parse(payload, ed318.Limits{})
	if probs != nil {
		t.Fatalf("the payload is refused by ed318.Parse: %v", probs)
	}
	for i := range fc.Features {
		if fc.Features[i].Properties.Identifier == v.Identifier {
			return fc.Features[i], payload
		}
	}
	t.Fatalf("%s is not in the payload: %s", v.Identifier, payload)
	return ed318.Feature{}, nil
}

// appliesAt is the consumer's judgement of a published feature: core's
// ed318.Applies, which the CISP's internal/applicability calls.
func appliesAt(t *testing.T, f *ed318.Feature, at time.Time) bool {
	t.Helper()
	ok, err := ed318.Applies(f.Properties.LimitedApplicability, at, featureCentre(f), NoDaylight{})
	if err != nil {
		t.Fatalf("at %s: %v", at, err)
	}
	return ok
}

// A zone without limitedApplicability is published with one TimePeriod
// from valid_from to valid_to: a consumer finds it applying before the
// end (presence) and not after it (absence), and not before the start.
func TestPublishedZoneCarriesItsPeriodOfValidity(t *testing.T) {
	s, st, _, _ := newService(t)
	f, payload := publishedFeature(t, s, st, feature(zoneOpts{}), t0, t1)
	if !strings.Contains(string(payload), `"limitedApplicability":[{"startDateTime":"2026-10-01T00:00:00Z","endDateTime":"2027-10-01T00:00:00Z"}]`) {
		t.Fatalf("the payload does not carry the period of validity: %s", payload)
	}
	for at, want := range map[time.Time]bool{
		t0:                     true,
		t0.Add(-time.Second):   false,
		t1.Add(-time.Hour):     true,
		t1:                     true, // both ends included, as InForce
		t1.Add(time.Second):    false,
		t1.AddDate(0, 3, 14):   false, // the 2028 read of the defect, by its shape
		testNow.Add(time.Hour): true,
	} {
		if got := appliesAt(t, &f, at); got != want {
			t.Errorf("applies at %s = %v, want %v", at.Format(time.RFC3339), got, want)
		}
	}
	// The stored master copy is not rewritten: the period is added when
	// the feature leaves the authority.
	v, err := s.Get(context.Background(), DatasetZones, "TST001")
	if err != nil || strings.Contains(string(v.Feature), "limitedApplicability") {
		t.Fatalf("%v %s", err, v.Feature)
	}
}

// A schedule without dates gets the period's dates and keeps its
// schedule; dates wider than the period are clipped to it; a narrower
// period is kept as written; a period wholly outside is dropped.
func TestPublishedApplicabilityIsClippedToThePeriodOfValidity(t *testing.T) {
	s, st, _, _ := newService(t)
	limited := `[{"schedule":[{"day":["MON"],"startTime":"08:00:00Z","endTime":"18:00:00Z"}]},` +
		`{"startDateTime":"2026-01-01T00:00:00Z","endDateTime":"2026-10-16T12:00:00Z"},` +
		`{"startDateTime":"2026-10-17T06:00:00+04:00","endDateTime":"2026-10-17T07:00:00+04:00"},` +
		`{"startDateTime":"2026-11-01T00:00:00Z","endDateTime":"2026-12-01T00:00:00Z"}]`
	f, _ := publishedFeature(t, s, st, feature(zoneOpts{limited: limited}), validFrom, validTo)
	tps := f.Properties.LimitedApplicability
	if len(tps) != 3 {
		t.Fatalf("%d periods, want 3: %+v", len(tps), tps)
	}
	type span struct{ start, end string }
	got := make([]span, 0, len(tps))
	for _, tp := range tps {
		got = append(got, span{tp.StartDateTime.Time.UTC().Format(time.RFC3339), tp.EndDateTime.Time.UTC().Format(time.RFC3339)})
	}
	want := []span{
		{"2026-10-15T00:00:00Z", "2026-10-18T00:00:00Z"},
		{"2026-10-15T00:00:00Z", "2026-10-16T12:00:00Z"},
		{"2026-10-17T02:00:00Z", "2026-10-17T03:00:00Z"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("period %d = %v, want %v", i, got[i], want[i])
		}
	}
	if len(tps[0].Schedule) != 1 || tps[0].Schedule[0].Day[0] != "MON" {
		t.Errorf("the schedule was lost: %+v", tps[0])
	}
	if tps[2].StartDateTime.Text != "2026-10-17T06:00:00+04:00" {
		t.Errorf("a period inside the validity was rewritten: %q", tps[2].StartDateTime.Text)
	}
	// Monday 2026-10-19 08:00 would apply by the schedule alone; it is
	// after valid_to.
	if appliesAt(t, &f, time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)) {
		t.Error("applies after valid_to")
	}
	if !appliesAt(t, &f, time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)) {
		t.Error("does not apply inside the period of validity")
	}
}

// The authority's own applicability answer (the console's "Applicability
// at a time") is bounded by the period of validity: TEST01, valid
// 2026-10-15 to 2026-10-18 without limitedApplicability, applies on the
// 16th and not on the 20th nor on the 14th.
func TestAppliesIsBoundedByThePeriodOfValidity(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	if _, err := s.Draft(ctx, DatasetZones, draftBetween(feature(zoneOpts{identifier: "TEST01"}), validFrom, validTo), true, inspector); err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]Applicability{
		time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC): Applies,
		validTo:                  Applies,
		validTo.Add(time.Second): NotApplicable,
		time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC): NotApplicable,
		validFrom.Add(-time.Second):                    NotApplicable,
	} {
		a, err := s.Applies(ctx, "TEST01", 0, at)
		if err != nil || a.Answer != want {
			t.Errorf("at %s: %v %+v, want %s", at.Format(time.RFC3339), err, a, want)
		}
	}
	// A weekday schedule: the 19th is a Monday, inside the schedule and
	// outside the period.
	weekdays := `[{"schedule":[{"day":["MON","TUE","WED","THU","FRI","SAT","SUN"],"startTime":"08:00:00Z","endTime":"18:00:00Z"}]}]`
	if _, err := s.Draft(ctx, DatasetZones, draftBetween(feature(zoneOpts{identifier: "TEST02", limited: weekdays}), validFrom, validTo), true, inspector); err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]Applicability{
		time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC): Applies,
		time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC): NotApplicable,
		time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC): NotApplicable,
	} {
		if a, err := s.Applies(ctx, "TEST02", 0, at); err != nil || a.Answer != want {
			t.Errorf("TEST02 at %s: %v %+v, want %s", at.Format(time.RFC3339), err, a, want)
		}
	}
}

// The export (applies_at and at) is bounded the same way, and every
// exported feature carries its period.
func TestExportCarriesAndHonoursThePeriodOfValidity(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	publishOne(t, s, feature(zoneOpts{}))
	out, err := s.Export(ctx, ExportInput{AppliesAt: ptr(t1.Add(-time.Hour))}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if got := applicabilityOfExport(t, out); got["TST001"] != "applies" {
		t.Fatalf("%v", got)
	}
	if !strings.Contains(string(out), `"endDateTime":"2027-10-01T00:00:00Z"`) {
		t.Fatalf("the export does not carry the period: %s", out)
	}
	out, err = s.Export(ctx, ExportInput{}, admin)
	if err != nil || !strings.Contains(string(out), `"endDateTime":"2027-10-01T00:00:00Z"`) {
		t.Fatalf("%v %s", err, out)
	}
}

// A U-space airspace's designation period is published the same way.
func TestUSpacePublicationCarriesTheDesignationPeriod(t *testing.T) {
	ctx := context.Background()
	s, st, _, _ := newService(t)
	in := DraftInput{Feature: []byte(feature(zoneOpts{typ: "USPACE", identifier: "TSU001"})), ValidFrom: ptr(validFrom), ValidTo: ptr(validTo),
		Designation: testDesignation()}
	v, err := s.Draft(ctx, DatasetUSpace, in, true, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetUSpace, v.Identifier, v.ZoneVersion, admin); err != nil {
		t.Fatal(err)
	}
	p, err := s.Publish(ctx, DatasetUSpace, admin)
	if err != nil {
		t.Fatal(err)
	}
	fc, probs := ed318.Parse(st.payload(p.Publication.ID), ed318.Limits{})
	if probs != nil || len(fc.Features) != 1 {
		t.Fatalf("%v", probs)
	}
	f := fc.Features[0]
	if !appliesAt(t, &f, validTo.Add(-time.Minute)) || appliesAt(t, &f, validTo.Add(time.Minute)) {
		t.Fatalf("%+v", f.Properties.LimitedApplicability)
	}
}

// A zone whose limitedApplicability never meets its period of validity
// would never apply, which ED-318 cannot publish: the draft and the
// import are refused at the field; the overlapping twin is accepted.
func TestApplicabilityOutsideThePeriodOfValidityIsRefused(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	outside := `[{"startDateTime":"2026-11-01T00:00:00Z","endDateTime":"2026-12-01T00:00:00Z"}]`
	_, err := s.Draft(ctx, DatasetZones, draftBetween(feature(zoneOpts{limited: outside}), validFrom, validTo), true, inspector)
	mustProblem(t, err, http.StatusBadRequest, "feature.properties.limitedApplicability", "never apply")
	overlapping := `[{"startDateTime":"2026-10-17T00:00:00Z","endDateTime":"2026-12-01T00:00:00Z"}]`
	if _, err := s.Draft(ctx, DatasetZones, draftBetween(feature(zoneOpts{limited: overlapping}), validFrom, validTo), true, inspector); err != nil {
		t.Fatal(err)
	}

	doc := collection(feature(zoneOpts{identifier: "IMP001"}), feature(zoneOpts{identifier: "IMP002", limited: outside}))
	_, _, err = s.Import(ctx, ImportInput{Body: []byte(doc), ValidFrom: ptr(validFrom), ValidTo: ptr(validTo), Source: "file"}, inspector)
	mustProblem(t, err, http.StatusBadRequest, "features[1].properties.limitedApplicability", "never apply")
	if _, err := s.Get(ctx, DatasetZones, "IMP001"); err == nil {
		t.Fatal("the refused import stored a zone")
	}
	_, vs, err := s.Import(ctx, ImportInput{Body: []byte(doc), ValidFrom: ptr(validFrom), ValidTo: ptr(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)), Source: "file"}, inspector)
	if err != nil || len(vs) != 2 {
		t.Fatalf("%v %d", err, len(vs))
	}
}

// withinValidity on its own: the error names the field and the period;
// a feature that meets it is bounded.
func TestWithinValidity(t *testing.T) {
	fc, err := collect([]json.RawMessage{json.RawMessage(feature(zoneOpts{limited: `[{"startDateTime":"2027-01-01T00:00:00Z"}]`}))})
	if err != nil {
		t.Fatal(err)
	}
	f := fc.Features[0]
	err = withinValidity(&f, validFrom, validTo)
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != FieldLimitedApplicability || !strings.Contains(fe.Reason, "2026-10-18T00:00:00Z") {
		t.Fatalf("%v", err)
	}
	f = fc.Features[0]
	if err := withinValidity(&f, validFrom, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if tp := f.Properties.LimitedApplicability[0]; !tp.StartDateTime.Time.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!tp.EndDateTime.Time.Equal(time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", tp)
	}
}

// A zone whose period starts after the publication is published, as not
// applying until it starts (before, it was left out until a publication
// made after its start); an ended one is not; per identifier the
// version in force wins over a later one, and of later ones the first
// to start.
func TestPublicationSetIsInForceNowOrLater(t *testing.T) {
	day := func(d int) time.Time { return testNow.AddDate(0, 0, d) }
	v := func(id string, n int, from, to time.Time) Version {
		return Version{Dataset: DatasetZones, Identifier: id, ZoneVersion: n, ValidFrom: from, ValidTo: to}
	}
	rows := []Version{
		v("CUR001", 1, day(-10), day(10)), v("CUR001", 2, day(20), day(30)), // in force wins over later
		v("FUT001", 1, day(5), day(9)), v("FUT001", 2, day(3), day(4)), // the first to start
		v("NEW001", 1, day(-10), day(10)), v("NEW001", 2, day(-1), day(10)), // the newest in force
		v("TIE001", 1, day(2), day(9)), v("TIE001", 2, day(2), day(9)), // starting together: the newest
		v("END001", 1, day(-10), day(-1)), // ended
		{Dataset: DatasetUSpace, Identifier: "TSU001", ZoneVersion: 1, ValidFrom: day(-1), ValidTo: day(1)},
	}
	got := map[string]int{}
	var order []string
	for _, r := range publicationSet(rows, DatasetZones, testNow) {
		got[r.Identifier] = r.ZoneVersion
		order = append(order, r.Identifier)
	}
	want := map[string]int{"CUR001": 1, "FUT001": 2, "NEW001": 2, "TIE001": 2}
	if len(got) != len(want) || strings.Join(order, ",") != "CUR001,FUT001,NEW001,TIE001" {
		t.Fatalf("%v (%v), want %v", got, order, want)
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s@%d, want @%d", id, got[id], n)
		}
	}

	s, st, _, _ := newService(t)
	f, _ := publishedFeature(t, s, st, feature(zoneOpts{identifier: "FUT002"}), day(3), day(4))
	if appliesAt(t, &f, day(2)) || !appliesAt(t, &f, day(3).Add(time.Hour)) || appliesAt(t, &f, day(5)) {
		t.Fatalf("%+v", f.Properties.LimitedApplicability)
	}
}
