package zonesvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

func TestVersionTransitions(t *testing.T) {
	ctx := context.Background()
	s, st, _, _ := newService(t)
	v1, err := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{})), true, inspector)
	if err != nil {
		t.Fatal(err)
	}
	// Creating an identifier that exists is refused; replacing it makes
	// version 2 and supersedes the unpublished version 1.
	_, err = s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{})), true, inspector)
	mustProblem(t, err, http.StatusConflict, "identifier", "exists")
	in := draftIn(feature(zoneOpts{}))
	in.Identifier = "TST001"
	v2, err := s.Draft(ctx, DatasetZones, in, false, inspector)
	if err != nil || v2.ZoneVersion != 2 {
		t.Fatalf("%v %+v", err, v2)
	}
	if old, _ := st.Version(ctx, "TST001", v1.ZoneVersion); old.State != StateSuperseded {
		t.Fatalf("version 1 is %s", old.State)
	}
	// Replacing an identifier that does not exist is 404; a path that
	// does not match the feature is refused.
	in.Identifier = "NOPE01"
	_, err = s.Draft(ctx, DatasetZones, in, false, inspector)
	mustProblem(t, err, http.StatusBadRequest, "feature.properties.identifier", "path's identifier")
	in = draftIn(feature(zoneOpts{identifier: "NOPE01"}))
	in.Identifier = "NOPE01"
	_, err = s.Draft(ctx, DatasetZones, in, false, inspector)
	mustProblem(t, err, http.StatusNotFound, "identifier", "does not exist")

	// Only the newest version, and only a draft, is approved.
	_, err = s.Approve(ctx, DatasetZones, "TST001", 1, admin)
	mustProblem(t, err, http.StatusConflict, "zone_version", "not the newest")
	a, err := s.Approve(ctx, DatasetZones, "TST001", 2, admin)
	if err != nil || a.State != StateApproved || a.ApprovedBy != admin.ID {
		t.Fatalf("%v %+v", err, a)
	}
	_, err = s.Approve(ctx, DatasetZones, "TST001", 2, admin)
	mustProblem(t, err, http.StatusConflict, "zone_version", "not a draft")
	_, err = s.Approve(ctx, DatasetUSpace, "TST001", 2, admin)
	mustProblem(t, err, http.StatusNotFound, "identifier", "does not exist")

	p, err := s.Publish(ctx, DatasetZones, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Versions) != 1 || p.Versions[0].State != StatePublished || *p.Versions[0].PublishedVersion != p.ZonesVersion {
		t.Fatalf("%+v", p)
	}
	// A newer version, once published, supersedes the published one.
	in = draftIn(feature(zoneOpts{}))
	in.Identifier = "TST001"
	v3, err := s.Draft(ctx, DatasetZones, in, false, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if old, _ := st.Version(ctx, "TST001", 2); old.State != StatePublished {
		t.Fatalf("a published version stays in force until its successor is published: %s", old.State)
	}
	if _, err := s.Approve(ctx, DatasetZones, "TST001", v3.ZoneVersion, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, DatasetZones, admin); err != nil {
		t.Fatal(err)
	}
	if old, _ := st.Version(ctx, "TST001", 2); old.State != StateSuperseded {
		t.Fatalf("version 2 is %s", old.State)
	}
	vs, err := s.Versions(ctx, DatasetZones, "TST001", 0, 10)
	if err != nil || len(vs) != 3 || vs[0].ZoneVersion != 3 {
		t.Fatalf("%v %+v", err, vs)
	}
}

func TestIdentifiersAreUniqueAcrossDatasets(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	if _, err := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{identifier: "SHARED"})), true, inspector); err != nil {
		t.Fatal(err)
	}
	in := uspaceIn(feature(zoneOpts{identifier: "SHARED", typ: "USPACE"}), testDesignation())
	_, err := s.Draft(ctx, DatasetUSpace, in, true, admin)
	mustProblem(t, err, http.StatusConflict, "identifier", "unique across zones and U-space airspaces")
	if _, err := s.Get(ctx, DatasetUSpace, "SHARED"); err == nil {
		t.Fatal("a zone is not a U-space airspace")
	}
	if _, err := s.Get(ctx, DatasetZones, "SHARED"); err != nil {
		t.Fatal(err)
	}
}

func publishOne(t *testing.T, s *Service, f string) Published {
	t.Helper()
	ctx := context.Background()
	v, err := s.Draft(ctx, DatasetZones, draftIn(f), true, inspector)
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
	return p
}

// A-M1 zone item: author, approve, publish, and the outbox row is
// pending with no signature until WP-6 signs it.
func TestPublishWritesThePendingUnsignedOutboxRowTheProjectionAndTheAnnouncement(t *testing.T) {
	s, st, pr, pub := newService(t)
	p := publishOne(t, s, feature(zoneOpts{}))
	if p.Publication.State != "pending" {
		t.Fatalf("state %s", p.Publication.State)
	}
	if p.Publication.Signature != nil {
		t.Fatalf("signature %q: nothing here signs; WP-6 does", *p.Publication.Signature)
	}
	payload := st.payload(p.Publication.ID)
	sum := sha256.Sum256(payload)
	if p.Publication.PayloadHash != hex.EncodeToString(sum[:]) || p.Publication.FeatureCount != 1 {
		t.Fatalf("%+v", p.Publication)
	}
	fc, probs := ed318.Parse(payload, ed318.Limits{})
	if probs != nil {
		t.Fatalf("the payload is refused by ed318.Parse: %v", probs)
	}
	if fc.Metadata == nil || fc.Metadata.Issued == nil || !fc.Metadata.Issued.Time.Equal(testNow) || *fc.Metadata.Provider[0].Text != "Test authority" {
		t.Fatalf("metadata %+v", fc.Metadata)
	}
	if !strings.Contains(string(payload), `"issued"`) || strings.Contains(string(payload), "creationDateTime") {
		t.Fatalf("metadata names: %s", payload)
	}
	if keys := pr.keys(); len(keys) != 1 || keys[0] != "zones/TST001/1" || pr.version != p.ZonesVersion {
		t.Fatalf("projection %v %d", keys, pr.version)
	}
	if len(pub.versions) != 1 || pub.versions[0] != p.ZonesVersion {
		t.Fatalf("announced %v", pub.versions)
	}
	evs := st.events()
	if last := evs[len(evs)-1]; last.EventType != "zones_published" {
		t.Fatalf("%+v", last)
	}
	// A second publication supersedes the pending row (one pending
	// snapshot per dataset, E-10).
	publishOne(t, s, feature(zoneOpts{identifier: "TST002"}))
	pubs := st.publications()
	if len(pubs) != 2 || pubs[0].State != "superseded" || pubs[1].State != "pending" || pubs[1].FeatureCount != 2 {
		t.Fatalf("%+v", pubs)
	}
}

func TestPublishWithNothingApprovedIsRefused(t *testing.T) {
	s, st, pr, _ := newService(t)
	if _, err := s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{})), true, inspector); err != nil {
		t.Fatal(err)
	}
	_, err := s.Publish(context.Background(), DatasetZones, admin)
	if p := problemOf(t, err); p.Status != http.StatusConflict || p.Slug() != SlugNothing {
		t.Fatalf("%+v", p)
	}
	if len(st.publications()) != 0 || pr.writes != 0 {
		t.Fatal("a refused publication wrote something")
	}
}

// G-08: a failed projection write rolls the publication back, 503
// naming the cause; nothing is published, nothing is queued.
func TestPublishRolledBackWhenTheProjectionFails(t *testing.T) {
	ctx := context.Background()
	s, st, pr, pub := newService(t)
	v, err := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{})), true, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetZones, v.Identifier, 1, admin); err != nil {
		t.Fatal(err)
	}
	pr.fail = errInjected
	_, err = s.Publish(ctx, DatasetZones, admin)
	if p := problemOf(t, err); p.Status != http.StatusServiceUnavailable || p.Slug() != SlugProjection || !errors.Is(err, ErrProjection) {
		t.Fatalf("%+v %v", p, err)
	}
	if got, _ := st.Latest(ctx, "TST001"); got.State != StateApproved {
		t.Fatalf("state %s after a rolled-back publication", got.State)
	}
	if len(st.publications()) != 0 || len(pub.versions) != 0 || s.Counters.Get(CounterProjectionWriteFailed) != 1 {
		t.Fatal("a rolled-back publication left a trace")
	}
	// With the projection back, the same publication goes through.
	pr.fail = nil
	if _, err := s.Publish(ctx, DatasetZones, admin); err != nil {
		t.Fatal(err)
	}
}

// The relational commit failing after the projection committed leaves
// the projection ahead: counted, and a repair requested at once.
func TestProjectionAheadRequestsARepair(t *testing.T) {
	ctx := context.Background()
	s, st, _, _ := newService(t)
	v, _ := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{})), true, inspector)
	if _, err := s.Approve(ctx, DatasetZones, v.Identifier, 1, admin); err != nil {
		t.Fatal(err)
	}
	st.failTx = errInjected
	if _, err := s.Publish(ctx, DatasetZones, admin); !errors.Is(err, errInjected) {
		t.Fatalf("%v", err)
	}
	if s.Counters.Get(CounterProjectionAhead) != 1 {
		t.Fatal("not counted")
	}
	select {
	case <-s.repairs():
	default:
		t.Fatal("no repair requested")
	}
	// Without the failure no repair is requested.
	st.failTx = nil
	if _, err := s.Publish(ctx, DatasetZones, admin); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.repairs():
		t.Fatal("a repair requested after a good publication")
	default:
	}
}

func TestAnnounceFailureIsCountedAndThePublicationStands(t *testing.T) {
	s, st, _, pub := newService(t)
	pub.fail = errInjected
	p := publishOne(t, s, feature(zoneOpts{}))
	if s.Counters.Get(CounterAnnounceFailed) != 1 || len(st.publications()) != 1 || p.ZonesVersion == 0 {
		t.Fatal("an announcement failure lost the publication or went uncounted")
	}
	pub.fail = nil
	publishOne(t, s, feature(zoneOpts{identifier: "TST002"}))
	if s.Counters.Get(CounterAnnounceFailed) != 1 || len(pub.versions) != 1 {
		t.Fatal("a good announcement was counted as failed")
	}
}

// Reproject repairs a projection that lost a row and deletes one the
// relational state does not hold.
func TestReprojectRepairsAndDeletes(t *testing.T) {
	ctx := context.Background()
	s, _, pr, _ := newService(t)
	publishOne(t, s, feature(zoneOpts{}))
	pr.rows = map[string]ProjectedZone{"zones/GHOST/1": {Dataset: DatasetZones, Identifier: "GHOST", ZoneVersion: 1}}
	r, err := s.Reproject(ctx)
	if err != nil || !r.Ran || r.Rows != 1 {
		t.Fatalf("%v %+v", err, r)
	}
	if keys := pr.keys(); len(keys) != 1 || keys[0] != "zones/TST001/1" {
		t.Fatalf("%v", keys)
	}
	if s.Counters.Get(CounterProjectionDeleted) != 1 || s.Counters.Get(CounterReprojected) != 1 {
		t.Fatal(s.Counters.Snapshot())
	}
	pr.fail = errInjected
	if _, err := s.Reproject(ctx); err == nil || s.Counters.Get(CounterReprojectFailed) != 1 {
		t.Fatalf("%v", err)
	}
}

func applicabilityOfExport(t *testing.T, out []byte) map[string]string {
	t.Helper()
	fc, probs := ed318.Parse(out, ed318.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	got := map[string]string{}
	for i := range fc.Features {
		p := &fc.Features[i].Properties
		got[p.Identifier] = strings.Trim(string(p.ExtendedProperties[ApplicabilityKey]), `"`)
	}
	return got
}

// M17 / E-01: applies_at annotates every feature with each of the three
// values; at keeps applies and unknown and drops not_applicable.
func TestExportAnnotatesAndFilters(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	weekdays := `[{"schedule":[{"day":["MON","TUE","WED","THU","FRI"],"startTime":"08:00:00Z","endTime":"18:00:00Z"}]}]`
	weekend := `[{"schedule":[{"day":["SAT","SUN"],"startTime":"08:00:00Z","endTime":"18:00:00Z"}]}]`
	daylight := `[{"startDateTime":"2026-10-01T00:00:00Z","endDateTime":"2026-10-08T00:00:00Z","schedule":[{"day":["ANY"],"startEvent":"SR","endEvent":"SS"}]}]`
	for _, f := range []string{
		feature(zoneOpts{identifier: "APP001", limited: weekdays}),
		feature(zoneOpts{identifier: "NOT001", limited: weekend}),
		feature(zoneOpts{identifier: "UNK001", limited: daylight}),
	} {
		publishOne(t, s, f)
	}
	out, err := s.Export(ctx, ExportInput{AppliesAt: ptr(testNow)}, admin)
	if err != nil {
		t.Fatal(err)
	}
	got := applicabilityOfExport(t, out)
	if got["APP001"] != "applies" || got["NOT001"] != "not_applicable" || got["UNK001"] != "unknown" || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	out, err = s.Export(ctx, ExportInput{At: ptr(testNow)}, admin)
	if err != nil {
		t.Fatal(err)
	}
	got = applicabilityOfExport(t, out)
	if _, ok := got["NOT001"]; ok || got["UNK001"] != "unknown" || got["APP001"] != "" || len(got) != 2 {
		t.Fatalf("at: %v", got)
	}
	out, err = s.Export(ctx, ExportInput{}, admin)
	if err != nil || len(applicabilityOfExport(t, out)) != 3 || strings.Contains(string(out), ApplicabilityKey) {
		t.Fatalf("plain: %v %s", err, out)
	}
	_, err = s.Export(ctx, ExportInput{At: ptr(testNow), AppliesAt: ptr(testNow)}, admin)
	if p := problemOf(t, err); p.Status != http.StatusBadRequest || p.Slug() != SlugFilterConflict {
		t.Fatalf("%+v", p)
	}
}

func TestExportIsTheVersionInForceAtTheInstant(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	publishOne(t, s, feature(zoneOpts{}))
	change := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	in := DraftInput{Identifier: "TST001", Feature: []byte(feature(zoneOpts{typ: "CONDITIONAL"})), ValidFrom: ptr(change), ValidTo: ptr(t1)}
	v2, err := s.Draft(ctx, DatasetZones, in, false, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, DatasetZones, "TST001", v2.ZoneVersion, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, DatasetZones, admin); err != nil {
		t.Fatal(err)
	}
	for at, want := range map[time.Time]string{change.Add(-time.Second): "PROHIBITED", change.Add(time.Second): "CONDITIONAL"} {
		out, err := s.Export(ctx, ExportInput{AppliesAt: ptr(at)}, admin)
		if err != nil {
			t.Fatal(err)
		}
		fc, _ := ed318.Parse(out, ed318.Limits{})
		if len(fc.Features) != 1 || string(fc.Features[0].Properties.Type) != want {
			t.Fatalf("at %s: %+v", at, fc.Features)
		}
	}
	// After every period has ended nothing is in force.
	out, _ := s.Export(ctx, ExportInput{AppliesAt: ptr(t1.Add(time.Hour))}, admin)
	if fc, _ := ed318.Parse(out, ed318.Limits{}); len(fc.Features) != 0 {
		t.Fatalf("%s", out)
	}
}

func TestAppliesPreview(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	weekdays := `[{"schedule":[{"day":["MON"],"startTime":"08:00:00Z","endTime":"18:00:00Z"}]}]`
	if _, err := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{limited: weekdays})), true, inspector); err != nil {
		t.Fatal(err)
	}
	a, err := s.Applies(ctx, "TST001", 0, testNow)
	if err != nil || a.Answer != Applies {
		t.Fatalf("%v %+v", err, a)
	}
	a, err = s.Applies(ctx, "TST001", 1, testNow.Add(24*time.Hour))
	if err != nil || a.Answer != NotApplicable {
		t.Fatalf("%v %+v", err, a)
	}
	_, err = s.Applies(ctx, "TST001", 7, testNow)
	mustProblem(t, err, http.StatusNotFound, "zone_version", "no version 7")

	// A daylight schedule is refused while no daylight source is wired
	// (never guessed) and answered once one is.
	daylight := `[{"startDateTime":"2026-10-01T00:00:00Z","endDateTime":"2026-10-08T00:00:00Z","schedule":[{"day":["ANY"],"startEvent":"SR","endEvent":"SS"}]}]`
	if _, err := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{identifier: "DAY001", limited: daylight})), true, inspector); err != nil {
		t.Fatal(err)
	}
	_, err = s.Applies(ctx, "DAY001", 0, testNow)
	if p := problemOf(t, err); p.Status != http.StatusServiceUnavailable || p.Slug() != SlugDaylight {
		t.Fatalf("%+v", p)
	}
	s.Daylight = ed318.FixedDaylight{"2026-10-05": {
		ed318.EventSR: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC), ed318.EventSS: time.Date(2026, 10, 5, 14, 30, 0, 0, time.UTC),
	}}
	a, err = s.Applies(ctx, "DAY001", 0, testNow)
	if err != nil || a.Answer != Applies {
		t.Fatalf("%v %+v", err, a)
	}
	// An event the source cannot resolve is unknown, with the reason.
	a, err = s.Applies(ctx, "DAY001", 0, testNow.Add(24*time.Hour))
	if err != nil || a.Answer != Unknown || a.Reason == "" {
		t.Fatalf("%v %+v", err, a)
	}
}

func TestNoDaylightRefusesEveryEventByName(t *testing.T) {
	for _, ev := range []string{ed318.EventBMCT, ed318.EventSR, ed318.EventSS, ed318.EventEECT} {
		_, err := NoDaylight{}.Event(ev, testNow, core.LatLon{LatDeg: 41.7, LonDeg: 44.8})
		if !errors.Is(err, ErrDaylightUnavailable) || !strings.Contains(err.Error(), ev) {
			t.Errorf("%s: %v", ev, err)
		}
	}
}

func TestListPagesInIdentifierOrder(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	for _, id := range []string{"C", "A", "B"} {
		if _, err := s.Draft(ctx, DatasetZones, draftIn(feature(zoneOpts{identifier: id})), true, inspector); err != nil {
			t.Fatal(err)
		}
	}
	vs, err := s.List(ctx, ListFilter{Dataset: DatasetZones, Limit: 2})
	if err != nil || len(vs) != 2 || vs[0].Identifier != "A" || vs[1].Identifier != "B" {
		t.Fatalf("%v %+v", err, vs)
	}
	vs, _ = s.List(ctx, ListFilter{Dataset: DatasetZones, After: "B", Limit: 2})
	if len(vs) != 1 || vs[0].Identifier != "C" {
		t.Fatalf("%+v", vs)
	}
	if _, err := s.List(ctx, ListFilter{Dataset: DatasetZones, State: "bogus"}); err == nil {
		t.Fatal("an unknown state is refused")
	}
}
