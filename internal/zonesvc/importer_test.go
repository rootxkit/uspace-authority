package zonesvc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/ed269"
)

// ed269Zone is an ED-269 zone (uas_standards' UASZoneVersion) with one
// polygon volume unless volumes is given.
func ed269Zone(id, restriction string, volumes ...string) string {
	if len(volumes) == 0 {
		volumes = []string{ed269Volume(41.7, 44.8, 0.01)}
	}
	return fmt.Sprintf(`{"identifier":%q,"country":"GEO","name":"Test %s","type":"COMMON","restriction":%q,"reason":["SENSITIVE"],
		"applicability":[{"permanent":"YES"}],"zoneAuthority":[{"name":"Test authority","purpose":"AUTHORIZATION"}],
		"geometry":[%s]}`, id, id, restriction, strings.Join(volumes, ","))
}

func ed269Volume(lat, lon, d float64) string {
	return fmt.Sprintf(`{"uomDimensions":"M","lowerVerticalReference":"AGL","upperVerticalReference":"AMSL","lowerLimit":0,"upperLimit":500,
		"horizontalProjection":{"type":"Polygon","coordinates":%s}}`, square(lat, lon, d))
}

func ed269Doc(zones ...string) string {
	return `{"title":"Test ED-269","features":[` + strings.Join(zones, ",") + `]}`
}

func TestDetectByWrapper(t *testing.T) {
	for doc, want := range map[string]Format{
		`{"type":"FeatureCollection","features":[]}`: FormatED318,
		`{"features":[]}`:                  FormatED269,
		`{"UASZoneList":[]}`:               FormatED269,
		"\xEF\xBB\xBF" + `{"features":[]}`: FormatED269,
		`not json`:                         FormatED318,
	} {
		if got := detect([]byte(doc)); got != want {
			t.Errorf("%q: %s, want %s", doc, got, want)
		}
	}
}

func importDoc(t *testing.T, s *Service, doc string) ([]Version, error) {
	t.Helper()
	_, vs, err := s.Import(context.Background(), ImportInput{Body: []byte(doc), ValidFrom: ptr(t0), ValidTo: ptr(t1)}, inspector)
	return vs, err
}

func TestED269ImportedThroughFromED269(t *testing.T) {
	s, st, _, _ := newService(t)
	vs, err := importDoc(t, s, ed269Doc(ed269Zone("TSA001", "REQ_AUTHORISATION"), ed269Zone("TSA002", "PROHIBITED")))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].Type != "REQ_AUTHORIZATION" || vs[0].State != StateDraft {
		t.Fatalf("%+v", vs)
	}
	evs := st.events()
	if len(evs) != 1 || evs[0].EventType != "zones_imported" {
		t.Fatalf("%+v", evs)
	}
	// A second import of the same identifiers makes their next versions.
	vs, err = importDoc(t, s, ed269Doc(ed269Zone("TSA001", "REQ_AUTHORISATION")))
	if err != nil || vs[0].ZoneVersion != 2 {
		t.Fatalf("%v %+v", err, vs)
	}
}

// LESSONS Z-04: the ED-318 spelling in an ED-269 file is refused by name.
func TestZSpellingInED269Refused(t *testing.T) {
	s, st, _, _ := newService(t)
	_, err := importDoc(t, s, ed269Doc(ed269Zone("TSA001", "REQ_AUTHORIZATION")))
	mustProblem(t, err, http.StatusBadRequest, "features[0].restriction", "REQ_AUTHORISATION")
	if len(st.events()) != 0 {
		t.Fatal("a refused import recorded an event")
	}
}

// LESSONS Z-04: a zone with two volumes is refused, never half-imported.
func TestTwoVolumesRefusedWholeFile(t *testing.T) {
	s, st, _, _ := newService(t)
	two := ed269Zone("TSA002", "PROHIBITED", ed269Volume(41.7, 44.8, 0.01), ed269Volume(41.8, 44.9, 0.01))
	_, err := importDoc(t, s, ed269Doc(ed269Zone("TSA001", "PROHIBITED"), two))
	p := problemOf(t, err)
	if p.Status != http.StatusBadRequest || !strings.HasPrefix(p.Errors[0].Field, "features[1].geometry") {
		t.Fatalf("%+v", p)
	}
	if _, err := st.Latest(context.Background(), "TSA001"); err == nil {
		t.Fatal("the valid zone of a refused file was imported")
	}
}

// What ED-318 cannot hold is refused by name (ed318.FromED269).
func TestForeignTerritoryRefusedByTheMapping(t *testing.T) {
	s, _, _, _ := newService(t)
	z := strings.Replace(ed269Zone("TSA001", "PROHIBITED"), `"reason":["SENSITIVE"]`, `"reason":["FOREIGN_TERRITORY"]`, 1)
	_, err := importDoc(t, s, ed269Doc(z))
	mustProblem(t, err, http.StatusBadRequest, "reason[0]", "FOREIGN_TERRITORY")
}

func TestImportPeriodFromMetadataOrParametersElseRefused(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	doc := collection(feature(zoneOpts{}))
	_, _, err := s.Import(ctx, ImportInput{Body: []byte(doc)}, inspector)
	mustProblem(t, err, http.StatusBadRequest, "valid_from", "947 Art. 15(3)")
	withMeta := strings.Replace(doc, `"features"`, `"metadata":{"validFrom":"2026-10-01T00:00:00Z","validTo":"2027-10-01T00:00:00Z"},"features"`, 1)
	_, vs, err := s.Import(ctx, ImportInput{Body: []byte(withMeta)}, inspector)
	if err != nil || !vs[0].ValidFrom.Equal(t0) || !vs[0].ValidTo.Equal(t1) {
		t.Fatalf("%v %+v", err, vs)
	}
}

func TestImportRefusesAnIdentifierOfTheOtherDataset(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	if _, err := s.Draft(ctx, DatasetUSpace, uspaceIn(uspaceFeature("TSU001"), testDesignation()), true, admin); err != nil {
		t.Fatal(err)
	}
	_, err := importDoc(t, s, collection(feature(zoneOpts{identifier: "TST001"}), feature(zoneOpts{identifier: "TSU001"})))
	mustProblem(t, err, http.StatusBadRequest, "features[1].properties.identifier", "unique across zones and U-space airspaces")
	if _, err := s.Get(ctx, DatasetZones, "TST001"); err == nil {
		t.Fatal("part of a refused import was stored")
	}
}

// airspace.gov.ge (Z-13): a synthetic points.js and page in the site's
// format (no real data).
const (
	govGePoints = `// zones
var TST_CTR_points = [[41.60, 44.70], [41.60, 44.90], [41.80, 44.90], [41.80, 44.70]];
var TS2_EPR_point = [41.70, 44.80];
var TS3_MIL_points = [[41.90, 44.70], [41.90, 44.80], [42.00, 44.80], [41.90, 44.70]];
`
	govGePage = `<script>L.circle(TS2_EPR_point, {color: 'red', radius: 5000}).addTo(map);</script>`
)

func govGeRules() *GovGeRules {
	upper := 120.0
	lower := 0.0
	kind := func(restriction, uom string) GovGeKind {
		return GovGeKind{Restriction: restriction, Uom: uom, LowerReference: "AGL", UpperReference: "AGL", LowerLimit: &lower,
			UpperLimit: &upper, Applicability: []json.RawMessage{json.RawMessage(`{"permanent":"YES"}`)}, Reason: []string{"AIR_TRAFFIC"}}
	}
	return &GovGeRules{
		Country: "GEO", Authority: map[string]string{"name": "Test authority", "purpose": "AUTHORIZATION"},
		Kinds: map[string]GovGeKind{"CTR": kind("REQ_AUTHORISATION", "M"), "EPR": kind("PROHIBITED", "FT"), "MIL": kind("PROHIBITED", "M")},
	}
}

func TestGovGeConvertedWithTheRulesAndImported(t *testing.T) {
	doc, errs := GovGeToED269(govGePoints, govGePage, govGeRules())
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	parsed, probs := ed269.Parse(doc, ed269.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	if len(parsed.Zones) != 3 {
		t.Fatalf("%d zones", len(parsed.Zones))
	}
	// [lat, lon] on the site, [lon, lat] in ED-269; the open ring closed.
	ring := parsed.Zones[0].Geometry[0].Projection.Rings[0]
	if ring[0].LonDeg != 44.70 || ring[0].LatDeg != 41.60 || ring[0] != ring[len(ring)-1] {
		t.Fatalf("%+v", ring)
	}
	// The page's metres become the volume's feet, read back as metres.
	if r := parsed.Zones[1].Geometry[0].RadiusM(); r == nil || *r < 4999.999 || *r > 5000.001 {
		t.Fatalf("radius %v", r)
	}
	s, _, _, _ := newService(t)
	vs, err := importDoc(t, s, string(doc))
	if err != nil || len(vs) != 3 || vs[0].Identifier != "TSTCTR" {
		t.Fatalf("%v %+v", err, vs)
	}
}

func TestGovGeRefusesWhatTheRulesDoNotCover(t *testing.T) {
	rules := govGeRules()
	delete(rules.Kinds, "MIL")
	_, errs := GovGeToED269(govGePoints, govGePage, rules)
	if len(errs) != 1 || errs[0].Field != "points_js.TS3_MIL" || !strings.Contains(errs[0].Reason, `kind "MIL" has no rule`) {
		t.Fatalf("%v", errs)
	}
	_, errs = GovGeToED269(govGePoints, "<p>no circles</p>", govGeRules())
	if len(errs) != 1 || errs[0].Field != "points_js.TS2_EPR" || !strings.Contains(errs[0].Reason, "no radius") {
		t.Fatalf("%v", errs)
	}
	long := strings.Replace(govGePoints, "TST_CTR", "LONGNAME_CTR", 1)
	_, errs = GovGeToED269(long, govGePage, govGeRules())
	if len(errs) != 1 || !strings.Contains(errs[0].Reason, "longer than 7") {
		t.Fatalf("%v", errs)
	}
	rules = govGeRules()
	rules.Identifiers = map[string]string{"LONGNAME_CTR": "LNG001"}
	if _, errs = GovGeToED269(long, govGePage, rules); len(errs) > 0 {
		t.Fatalf("an identifier from the rules: %v", errs)
	}
	_, errs = GovGeToED269("var x = 1;", govGePage, govGeRules())
	if len(errs) != 1 || !strings.Contains(errs[0].Reason, "no zone variable") {
		t.Fatalf("%v", errs)
	}
	_, errs = GovGeToED269(`var BAD_CTR_points = [[1, "a"]];`, govGePage, govGeRules())
	if len(errs) != 1 || !strings.Contains(errs[0].Reason, "list of [lat, lon]") {
		t.Fatalf("%v", errs)
	}
}

func TestGovGeShapesBounded(t *testing.T) {
	var b strings.Builder
	for i := range maxGovGeShapes + 1 {
		fmt.Fprintf(&b, "var Z%d_CTR_point = [41.7, 44.8];\n", i)
	}
	_, errs := GovGeToED269(b.String(), govGePage, govGeRules())
	if len(errs) != 1 || !strings.Contains(errs[0].Reason, fmt.Sprintf("more than %d zones", maxGovGeShapes)) {
		t.Fatalf("%v", errs[:min(len(errs), 3)])
	}
}

// Audit B-N7, E-01: an import says which identifiers already existed
// (a new version made over a held one, a draft superseded): the
// zones_imported event lists them as replaced; a first import replaces
// none.
func TestImportEventNamesTheReplacedIdentifiers(t *testing.T) {
	s, st, _, _ := newService(t)
	if _, err := importDoc(t, s, ed269Doc(ed269Zone("TSA001", "PROHIBITED"))); err != nil {
		t.Fatal(err)
	}
	if _, err := importDoc(t, s, ed269Doc(ed269Zone("TSA001", "PROHIBITED"), ed269Zone("TSA002", "PROHIBITED"))); err != nil {
		t.Fatal(err)
	}
	evs := st.events()
	if len(evs) != 2 {
		t.Fatalf("%d events", len(evs))
	}
	first, _ := evs[0].Payload.(map[string]any)
	second, _ := evs[1].Payload.(map[string]any)
	if r, _ := first["replaced"].([]string); first == nil || len(r) != 0 {
		t.Fatalf("first import %v", first)
	}
	if r, _ := second["replaced"].([]string); len(r) != 1 || r[0] != "TSA001" {
		t.Fatalf("second import %v", second)
	}
}
