package zonesvc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/ed318"
)

func TestDraftAcceptedAndStoredExactlyAsExported(t *testing.T) {
	s, st, _, _ := newService(t)
	f := feature(zoneOpts{})
	v, err := s.Draft(context.Background(), DatasetZones, draftIn(f), true, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if v.ZoneVersion != 1 || v.State != StateDraft || v.Type != "PROHIBITED" {
		t.Fatalf("%+v", v)
	}
	// The stored feature is the master copy: what ed318.Export wrote, and
	// Export(Parse(stored)) equals it by value.
	if !sameJSON(t, v.Feature, []byte(f)) {
		t.Fatalf("stored %s\nwant %s", v.Feature, f)
	}
	fc, probs := ed318.Parse(wrapFeature(v.Feature), ed318.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	again, err := ed318.Export(fc)
	if err != nil {
		t.Fatal(err)
	}
	feats, _ := splitFeatures(again)
	if !bytes.Equal(feats[0], v.Feature) {
		t.Fatalf("Export(Parse(stored)) %s differs from stored %s", feats[0], v.Feature)
	}
	if evs := st.events(); len(evs) != 1 || evs[0].EventType != "zone_drafted" {
		t.Fatalf("events %+v", evs)
	}
}

func TestDraftWithoutAPeriodOfValidityIsRefused(t *testing.T) {
	s, st, _, _ := newService(t)
	in := DraftInput{Feature: []byte(feature(zoneOpts{}))}
	_, err := s.Draft(context.Background(), DatasetZones, in, true, inspector)
	mustProblem(t, err, http.StatusBadRequest, "valid_from", "947 Art. 15(3)")
	mustProblem(t, err, http.StatusBadRequest, "valid_to", "947 Art. 15(3)")
	in = DraftInput{Feature: []byte(feature(zoneOpts{})), ValidFrom: ptr(t1), ValidTo: ptr(t0)}
	_, err = s.Draft(context.Background(), DatasetZones, in, true, inspector)
	mustProblem(t, err, http.StatusBadRequest, "valid_to", "after valid_from")
	if len(st.events()) != 0 || s.Counters.Get(CounterRefused) != 2 {
		t.Fatalf("events %d refused %d", len(st.events()), s.Counters.Get(CounterRefused))
	}
}

func TestBadRingRefusedBesideAClosedOne(t *testing.T) {
	s, _, _, _ := newService(t)
	open := `{"type":"Polygon","coordinates":[[[44.79,41.69],[44.81,41.69],[44.81,41.71],[44.79,41.71],[44.795,41.69]]],"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":"AMSL","uom":"m"}}`
	_, err := s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{geometry: open})), true, inspector)
	p := problemOf(t, err)
	if p.Status != http.StatusBadRequest || !strings.HasPrefix(p.Errors[0].Field, "feature.geometry") {
		t.Fatalf("%+v", p)
	}
	if _, err := s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{})), true, inspector); err != nil {
		t.Fatalf("a closed ring: %v", err)
	}
}

// A schedule by daylight events needs end dates for the judgement's view
// (ed318.ToZones); without them the zone could never be judged, so it is
// refused at authoring.
func TestUnevaluableScheduleRefusedBesideAnEvaluableOne(t *testing.T) {
	s, _, _, _ := newService(t)
	open := `[{"schedule":[{"day":["ANY"],"startEvent":"BMCT","endEvent":"EECT"}]}]`
	_, err := s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{limited: open})), true, inspector)
	mustProblem(t, err, http.StatusBadRequest, "feature.properties.limitedApplicability[0]", "without startDateTime and endDateTime")
	bounded := `[{"startDateTime":"2026-10-01T00:00:00Z","endDateTime":"2026-10-08T00:00:00Z","schedule":[{"day":["ANY"],"startEvent":"BMCT","endEvent":"EECT"}]}]`
	if _, err := s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{limited: bounded})), true, inspector); err != nil {
		t.Fatalf("bounded events: %v", err)
	}
}

func TestWGS84AcceptedAndFlaggedAMSLNot(t *testing.T) {
	s, _, _, _ := newService(t)
	v, err := s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{upperRef: "WGS84"})), true, inspector)
	if err != nil {
		t.Fatal(err)
	}
	ext := v.Extensions()
	if len(ext) != 1 || ext[0].Field != "geometry.layer.upperReference" || !strings.Contains(ext[0].Reason, "Z-05") {
		t.Fatalf("%+v", ext)
	}
	v, err = s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{identifier: "TST002"})), true, inspector)
	if err != nil || len(v.Extensions()) != 0 {
		t.Fatalf("AMSL: %v %+v", err, v.Extensions())
	}
}

func TestCircleStoredAsCentreAndRadiusPolygonAsGeometry(t *testing.T) {
	cs, errs, _ := checkDocument([]byte(collection(feature(zoneOpts{geometry: circle(41.7151, 44.8271, 1500)}))), DatasetZones, identity)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	c := cs[0].columns
	if c.GeometryGeoJSON != nil || c.CenterLatDeg == nil || *c.CenterLatDeg != 41.7151 || *c.CenterLonDeg != 44.8271 || *c.RadiusM != 1500 {
		t.Fatalf("circle columns %+v", c)
	}
	// Feet are converted exactly; the original unit stays in ed318_extra.
	if *c.UpperM != 2500*0.3048 || !strings.Contains(string(c.ED318Extra), `"uom":"ft"`) || !strings.Contains(string(c.ED318Extra), `"upper":2500`) {
		t.Fatalf("limits %v %s", *c.UpperM, c.ED318Extra)
	}
	cs, errs, _ = checkDocument([]byte(collection(feature(zoneOpts{}))), DatasetZones, identity)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	c = cs[0].columns
	if c.GeometryGeoJSON == nil || c.CenterLatDeg != nil || c.RadiusM != nil || !strings.HasPrefix(*c.GeometryGeoJSON, `{"type":"Polygon"`) {
		t.Fatalf("polygon columns %+v", c)
	}
}

func TestTwoLayerZoneKeepsEveryLayerAndNoSingleLimit(t *testing.T) {
	g := `{"type":"GeometryCollection","geometries":[` + polygon(41.7, 44.8, 0.01, "AGL") + `,` + circle(41.7, 44.8, 300) + `]}`
	g = strings.Replace(g, `"upper":120,"upperReference":"AGL"`, `"upper":50,"upperReference":"AGL"`, 1)
	cs, errs, _ := checkDocument([]byte(collection(feature(zoneOpts{geometry: g}))), DatasetZones, identity)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	c := cs[0].columns
	var layers []layerColumn
	if err := json.Unmarshal(c.Layers, &layers); err != nil || len(layers) != 2 || c.LowerM != nil || c.UpperM != nil {
		t.Fatalf("%v %s %+v", err, c.Layers, c)
	}
	if c.GeometryGeoJSON == nil || !strings.Contains(*c.GeometryGeoJSON, "GeometryCollection") {
		t.Fatalf("%v", c.GeometryGeoJSON)
	}
}

func TestUSpaceTypeBelongsToItsDataset(t *testing.T) {
	f := collection(feature(zoneOpts{typ: "USPACE"}))
	_, errs, _ := checkDocument([]byte(f), DatasetZones, identity)
	if len(errs) != 1 || !strings.Contains(errs[0].Reason, "/v1/uspace") {
		t.Fatalf("%v", errs)
	}
	if _, errs, _ := checkDocument([]byte(f), DatasetUSpace, identity); len(errs) > 0 {
		t.Fatalf("in its dataset: %v", errs)
	}
	_, errs, _ = checkDocument([]byte(collection(feature(zoneOpts{}))), DatasetUSpace, identity)
	if len(errs) != 1 || !strings.Contains(errs[0].Reason, "/v1/zones") {
		t.Fatalf("%v", errs)
	}
}

func TestReservedIdentifierRefusedBesideAnOrdinaryOne(t *testing.T) {
	_, errs, _ := checkDocument([]byte(collection(feature(zoneOpts{identifier: "export"}))), DatasetZones, identity)
	if len(errs) != 1 || !strings.HasSuffix(errs[0].Field, "properties.identifier") {
		t.Fatalf("%v", errs)
	}
	if _, errs, _ := checkDocument([]byte(collection(feature(zoneOpts{identifier: "EXP001"}))), DatasetZones, identity); len(errs) > 0 {
		t.Fatal(errs)
	}
}

func TestSingleFeaturePathsNameTheFeatureMember(t *testing.T) {
	for in, want := range map[string]string{
		"$": "feature", "features[0]": "feature", "features[0].properties.type": "feature.properties.type", "other": "other",
	} {
		if got := singleFeature(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestDocumentPastTheByteCapRefusedWithTheReason(t *testing.T) {
	big := bytes.Repeat([]byte(" "), MaxDocumentBytes+1)
	_, errs, _ := readImport(big, "", DatasetZones)
	if len(errs) != 1 || errs[0].Field != "$" || !strings.Contains(errs[0].Reason, fmt.Sprintf("at most %d", MaxDocumentBytes)) {
		t.Fatalf("%v", errs)
	}
	// Just under the cap, padding a valid document, is read.
	doc := []byte(collection(feature(zoneOpts{})))
	doc = append(doc, bytes.Repeat([]byte(" "), MaxDocumentBytes-len(doc))...)
	if _, errs, _ := readImport(doc, "", DatasetZones); len(errs) > 0 {
		t.Fatalf("at the cap: %v", errs)
	}
}

func TestProblemsCappedAt100WithTheRestCounted(t *testing.T) {
	var fs []string
	for i := range 120 {
		fs = append(fs, feature(zoneOpts{identifier: fmt.Sprintf("U%05d", i), typ: "USPACE"}))
	}
	s, _, _, _ := newService(t)
	_, _, err := s.Import(context.Background(), ImportInput{Body: []byte(collection(fs...)), ValidFrom: ptr(t0), ValidTo: ptr(t1)}, inspector)
	p := problemOf(t, err)
	if len(p.Errors) != 100 || !p.Truncated {
		t.Fatalf("%d errors truncated %v", len(p.Errors), p.Truncated)
	}
}
