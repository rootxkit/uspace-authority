package incidents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

func builder(src *fakeSources, tel *fakeTelemetry) *Builder {
	b := &Builder{Sources: src, MaxRows: 100, MaxRecords: 4, MaxZones: 10, PublicPart: PublicPartOf(nil)}
	if tel != nil {
		b.Telemetry = tel
	}
	return b
}

func buildIn(kind string) BuildInput {
	in := BuildInput{Incident: incidentView(), PackID: testPackID, Kind: kind, From: at(0), To: at(60), Purpose: "oversight review",
		Actor: officer, CreatedAt: at(120)}
	if kind == KindLegal {
		in.CaseRef = "CASE-TEST-1"
	}
	return in
}

func mustBuild(t *testing.T, b *Builder, in BuildInput) (Manifest, map[string][]byte, []byte) {
	t.Helper()
	m, entries, err := b.Build(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	archive, mj, err := Seal(m, entries)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	read, err := ReadArchive(archive, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range read {
		files[e.Path] = e.Data
	}
	if !bytes.Equal(bytes.TrimSpace(files["manifest.json"]), mj) {
		t.Fatal("manifest.json differs from the manifest column")
	}
	var out Manifest
	if err := json.Unmarshal(mj, &out); err != nil {
		t.Fatal(err)
	}
	return out, files, archive
}

func trackFile(t *testing.T, files map[string][]byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(files["tracks/0001.json"], &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// The pack holds every section, the track cut with each hole labelled
// (a sample without a position at 2.5 s, a silence with a recorded
// writer gap between 3 s and 9 s), and the AGL number with its ground.
func TestBuildHoldsEverySectionAndLabelsTheHoles(t *testing.T) {
	src, tel := richSources()
	m, files, _ := mustBuild(t, builder(src, tel), buildIn(KindOversight))
	for _, s := range []string{SecIncident, SecViolations, SecTracks, SecFrames, SecWriterGaps, SecUSSPFlights, SecManned, SecZones, SecPolicies, SecEvents, SecGround} {
		if m.Sections[s].State != StateIncluded {
			t.Errorf("section %s: %+v", s, m.Sections[s])
		}
	}
	if m.Sections[SecManned].Basis != BasisReceived || m.Sections[SecManned].Count != 1 {
		t.Errorf("manned %+v", m.Sections[SecManned])
	}
	if len(m.Tracks) != 1 || m.Tracks[0].Segments != 3 || m.Tracks[0].Holes != 2 || m.Tracks[0].Samples != 5 {
		t.Fatalf("tracks %+v", m.Tracks)
	}
	doc := trackFile(t, files)
	holes := doc["holes"].([]any)
	causes := func(i int) string {
		var out []string
		for _, c := range holes[i].(map[string]any)["causes"].([]any) {
			out = append(out, c.(string))
		}
		return strings.Join(out, ",")
	}
	if causes(0) != CauseNoPosition || causes(1) != CauseWriterGap+","+CauseSilence {
		t.Fatalf("hole causes %q %q", causes(0), causes(1))
	}
	if len(m.AGLNumbers) != 1 || m.AGLNumbers[0].State != StateIncluded || !strings.Contains(string(m.AGLNumbers[0].TerrainSource), "GLO-30") {
		t.Fatalf("agl %+v", m.AGLNumbers)
	}
	for _, f := range []string{"incident.json", "violations.json", "raw_frames.json", "zones.json", "policies.json", "events.json",
		"writer_gaps.json", "ussp_flights.json", "manned_tracks.json", "manifest.json"} {
		if _, ok := files[f]; !ok {
			t.Errorf("no %s in the archive", f)
		}
	}
	if len(m.Files) != len(files)-1 {
		t.Fatalf("manifest lists %d files, the archive holds %d besides it", len(m.Files), len(files)-1)
	}
	for _, d := range m.Files {
		if ContentHash(files[d.Path]) != d.SHA256 {
			t.Errorf("%s: digest differs", d.Path)
		}
	}
	if len(m.Inferred) == 0 {
		t.Error("the manifest states no inference (E-04)")
	}
	if m.Segmenting.MaxGapS != 3 || m.Segmenting.PolicyVersion != 1 {
		t.Errorf("segmenting %+v", m.Segmenting)
	}
}

const piiName = "Jane Test-Person"

func personal() *fakePersonal {
	return &fakePersonal{known: map[string]map[string]string{testReg: {"full_name": piiName, "contact_email": "jane@example.test"}}}
}

// 06 §2 T6: an oversight pack carries no personal data (the System
// frame's payload and the Display Provider's details are withheld, the
// registration is its public part, no personal_data file); a legal pack
// carries it, read from the registry with the pack, case and purpose.
// The manifest holds none in either.
func TestRedactionPerKind(t *testing.T) {
	src, tel := richSources()
	b := builder(src, tel)
	pd := personal()
	b.Personal = pd
	m, files, archive := mustBuild(t, b, buildIn(KindOversight))
	if bytes.Contains(archive, []byte(piiName)) || len(pd.reads) != 0 {
		t.Fatal("an oversight pack read or holds personal data")
	}
	if _, ok := files["personal_data/operators.json"]; ok || m.Sections[SecPersonalData].State != StateWithheld {
		t.Fatalf("personal data in an oversight pack: %+v", m.Sections[SecPersonalData])
	}
	var frames []map[string]any
	if err := json.Unmarshal(files["raw_frames.json"], &frames); err != nil {
		t.Fatal(err)
	}
	if frames[0]["payload_b64"] == nil || frames[1]["payload_b64"] != nil || frames[1]["payload_withheld"] == nil || m.FramesWithheld != 1 {
		t.Fatalf("frames %v withheld %d", frames, m.FramesWithheld)
	}
	if bytes.Contains(files["ussp_flights.json"], []byte("41.4")) {
		t.Fatal("the remote pilot position is in an oversight pack")
	}
	tf := string(files["tracks/0001.json"])
	if strings.Contains(tf, testReg+"-abc") || !strings.Contains(tf, testReg) {
		t.Fatal("a registration's secret part reached the pack, or the public part is missing")
	}

	pd2 := personal()
	b.Personal = pd2
	lm, lfiles, larchive := mustBuild(t, b, buildIn(KindLegal))
	if !strings.Contains(string(lfiles["personal_data/operators.json"]), piiName) || lm.Sections[SecPersonalData].State != StateIncluded {
		t.Fatalf("the legal pack lacks the personal data: %+v", lm.Sections[SecPersonalData])
	}
	if len(pd2.reads) != 1 || !strings.Contains(pd2.reads[0], "CASE-TEST-1") || !strings.Contains(pd2.reads[0], testPackID) {
		t.Fatalf("registry reads %v", pd2.reads)
	}
	if err := json.Unmarshal(lfiles["raw_frames.json"], &frames); err != nil {
		t.Fatal(err)
	}
	if frames[1]["payload_b64"] == nil || !bytes.Contains(lfiles["ussp_flights.json"], []byte("41.4")) {
		t.Fatal("the legal pack withholds what it should carry")
	}
	for _, mj := range [][]byte{mustJSON(t, m), mustJSON(t, lm)} {
		if bytes.Contains(mj, []byte(piiName)) || bytes.Contains(mj, []byte("jane@example.test")) {
			t.Fatal("a manifest holds personal data")
		}
	}
	if !bytes.Contains(larchive, []byte("personal_data/operators.json")) {
		t.Fatal("the legal archive has no personal data entry")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Two builds of the same evidence are the same bytes; a different
// evidence is not.
func TestBuildIsDeterministic(t *testing.T) {
	src, tel := richSources()
	_, _, a1 := mustBuild(t, builder(src, tel), buildIn(KindOversight))
	src2, tel2 := richSources()
	_, _, a2 := mustBuild(t, builder(src2, tel2), buildIn(KindOversight))
	if !bytes.Equal(a1, a2) {
		t.Fatal("two builds of the same evidence differ")
	}
	tel2.tracks = tel2.tracks[:4]
	_, _, a3 := mustBuild(t, builder(src2, tel2), buildIn(KindOversight))
	if bytes.Equal(a1, a3) {
		t.Fatal("a different evidence gave the same archive")
	}
}

// B-13: an unreadable source is a section unavailable with the reason,
// never silently missing; its readable twin is included (above).
func TestUnreadableSourcesAreUnavailable(t *testing.T) {
	src, tel := richSources()
	src.violationsErr = errors.New("permission denied for table violations")
	m, _, _ := mustBuild(t, builder(src, tel), buildIn(KindOversight))
	if s := m.Sections[SecViolations]; s.State != StateUnavailable || !strings.Contains(s.Reason, "permission denied") {
		t.Fatalf("violations %+v", s)
	}
	if m.Sections[SecGround].State != StateUnavailable {
		t.Fatalf("ground %+v", m.Sections[SecGround])
	}
	m, _, _ = mustBuild(t, builder(src, nil), buildIn(KindOversight))
	for _, s := range []string{SecTracks, SecFrames, SecWriterGaps, SecUSSPFlights} {
		if m.Sections[s].State != StateUnavailable || m.Sections[s].Reason == "" {
			t.Errorf("%s %+v", s, m.Sections[s])
		}
	}
	tel.err = errors.New("telemetry down")
	m, _, _ = mustBuild(t, builder(&fakeSources{}, tel), buildIn(KindOversight))
	if m.Sections[SecTracks].State != StateUnavailable || !strings.Contains(m.Sections[SecTracks].Reason, "telemetry down") {
		t.Fatalf("tracks %+v", m.Sections[SecTracks])
	}
	// The policy that cuts the tracks must be readable.
	_, _, err := builder(&fakeSources{policyErr: errors.New("down")}, tel).Build(context.Background(), buildIn(KindOversight))
	if p := httpx.ProblemFromError(err); p.Status != http.StatusServiceUnavailable || p.Slug() != SlugPolicyUnavailable {
		t.Fatalf("%v", err)
	}
}

// E-10: a section past MaxRows refuses the pack (413), never thinned;
// at the bound it is built.
func TestSectionPastTheBoundIsRefused(t *testing.T) {
	src, tel := richSources()
	b := builder(src, tel)
	b.MaxRows = len(tel.tracks)
	if _, _, err := b.Build(context.Background(), buildIn(KindOversight)); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	b.MaxRows = len(tel.tracks) - 1
	_, _, err := b.Build(context.Background(), buildIn(KindOversight))
	if p := httpx.ProblemFromError(err); p.Status != http.StatusRequestEntityTooLarge || p.Slug() != SlugPackTooLarge {
		t.Fatalf("%v", err)
	}
}

func TestPersonalDataStates(t *testing.T) {
	src, tel := richSources()
	b := builder(src, tel)
	m, _, _ := mustBuild(t, b, buildIn(KindLegal))
	if m.Sections[SecPersonalData].State != StateUnavailable {
		t.Fatalf("without a registry %+v", m.Sections[SecPersonalData])
	}
	b.Personal = &fakePersonal{known: map[string]map[string]string{}}
	m, files, _ := mustBuild(t, b, buildIn(KindLegal))
	if m.Sections[SecPersonalData].State != StateUnavailable || !strings.Contains(string(files["personal_data/operators.json"]), "no operator") {
		t.Fatalf("unknown operator %+v", m.Sections[SecPersonalData])
	}
	if got := registryPurpose(testPackID, "C", strings.Repeat("x", 300)); len([]rune(got)) != 200 {
		t.Fatalf("purpose of %d runes", len([]rune(got)))
	}
}

// fakeTokens hands out a fixed token, or fails.
type fakeTokens struct{ err error }

func (f fakeTokens) Token(context.Context, string, ...string) (string, error) { return "tok", f.err }

// The USSP's record: fetched with a token of scope ussp.records and kept
// verbatim in a legal pack (by hash in an oversight one); every way it
// cannot be had is unavailable with the reason.
func TestUSSPRecords(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		if strings.HasSuffix(r.URL.Path, "/DOWN") {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"flight_id":"F1","alerts":[]}`))
	}))
	t.Cleanup(srv.Close)
	src, tel := richSources()
	src.usspBases = []gen.PackUSSPBaseURLsRow{{Code: "USSPA", ClientID: "ussp-USSPA-01", BaseUrl: srv.URL}}
	b := builder(src, tel)
	b.Records = &Records{Tokens: fakeTokens{}, MaxBytes: 1 << 20}

	m, files, _ := mustBuild(t, b, buildIn(KindLegal))
	if len(m.USSPRecords) != 1 || m.USSPRecords[0].State != StateIncluded || gotAuth != "Bearer tok" || gotPath != "/v1/records/flights/F1" {
		t.Fatalf("records %+v auth %q path %q", m.USSPRecords, gotAuth, gotPath)
	}
	if !strings.Contains(string(files[m.USSPRecords[0].File]), `"alerts"`) {
		t.Fatal("the record is not in the pack")
	}
	m, _, _ = mustBuild(t, b, buildIn(KindOversight))
	if m.USSPRecords[0].State != StateWithheld || m.USSPRecords[0].SHA256 == "" || m.Sections[SecUSSPRecords].State != StateWithheld {
		t.Fatalf("oversight records %+v", m.USSPRecords)
	}

	unavailable := func(mutate func(b *Builder, src *fakeSources, tel *fakeTelemetry), want string) {
		t.Helper()
		src, tel := richSources()
		src.usspBases = []gen.PackUSSPBaseURLsRow{{Code: "USSPA", ClientID: "ussp-USSPA-01", BaseUrl: srv.URL}}
		b := builder(src, tel)
		b.Records = &Records{Tokens: fakeTokens{}, MaxBytes: 1 << 20}
		mutate(b, src, tel)
		m, _, _ := mustBuild(t, b, buildIn(KindLegal))
		if len(m.USSPRecords) == 0 || m.USSPRecords[0].State != StateUnavailable || !strings.Contains(m.USSPRecords[0].Reason, want) ||
			m.Sections[SecUSSPRecords].State != StateUnavailable {
			t.Fatalf("want %q: %+v %+v", want, m.USSPRecords, m.Sections[SecUSSPRecords])
		}
	}
	unavailable(func(b *Builder, _ *fakeSources, _ *fakeTelemetry) { b.Records = nil }, "RECORDS_CLIENT_SECRET_FILE")
	unavailable(func(b *Builder, _ *fakeSources, _ *fakeTelemetry) {
		b.Records.Tokens = fakeTokens{err: errors.New("issuer down")}
	}, "issuer down")
	unavailable(func(_ *Builder, src *fakeSources, _ *fakeTelemetry) { src.usspBases = nil }, "holds no certificate in the register")
	unavailable(func(_ *Builder, src *fakeSources, _ *fakeTelemetry) { src.usspBasesErr = errors.New("register down") }, "register down")
	unavailable(func(_ *Builder, _ *fakeSources, tel *fakeTelemetry) { tel.ussp[0].FlightID = "DOWN" }, "answered 503")
	unavailable(func(b *Builder, _ *fakeSources, _ *fakeTelemetry) { b.MaxRecords = 0 }, "past the bound")
	// No USSP flight at all: none, said so.
	src, tel = richSources()
	tel.ussp = nil
	m, _, _ = mustBuild(t, builder(src, tel), buildIn(KindLegal))
	if m.Sections[SecUSSPRecords].State != StateNone {
		t.Fatalf("%+v", m.Sections[SecUSSPRecords])
	}
}

func TestRecordParsers(t *testing.T) {
	for _, ok := range []string{"https://ussp.example.test", "http://127.0.0.1:8080/base", "http://localhost:1"} {
		if _, err := CheckBaseURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://ussp.example.test", "ftp://x", "https://u:p@x", "https://x?a=1", "relative", "https://x#f"} {
		if _, err := CheckBaseURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, err := ParseRecord([]byte(` {"a": 1} `), 100); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`[1]`, `"x"`, ``, `{"a":`, `{"a":1}{"b":2}`} {
		if _, err := ParseRecord([]byte(bad), 100); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseRecord([]byte(`{"a":"`+strings.Repeat("x", 200)+`"}`), 100); err == nil {
		t.Error("a record past the bound accepted")
	}
}

func FuzzParseRecord(f *testing.F) {
	f.Add([]byte(`{"a":1}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := ParseRecord(b, 1<<16)
		if err == nil && (!json.Valid(out) || out[0] != '{') {
			t.Fatalf("accepted %q as %q", b, out)
		}
	})
}

func TestFetchRefusesOversizeAndNoClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"a":"` + strings.Repeat("x", 2000) + `"}`))
	}))
	t.Cleanup(srv.Close)
	r := &Records{Tokens: fakeTokens{}, MaxBytes: 1024}
	if _, err := r.Fetch(context.Background(), srv.URL, "F1"); err == nil {
		t.Fatal("an oversize record accepted")
	}
	r.MaxBytes = 4096
	if _, err := r.Fetch(context.Background(), srv.URL, "F1"); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Records{}).Fetch(context.Background(), srv.URL, "F1"); !errors.Is(err, ErrNoRecordsClient) {
		t.Fatal(err)
	}
	if _, err := r.Fetch(context.Background(), srv.URL, ""); err == nil {
		t.Fatal("an empty flight id accepted")
	}
}

// Zones: the version a violation names is included; one not in
// geo_zones is said; a zone in force over the evidence is included.
func TestZonesNamedAndInForce(t *testing.T) {
	src, tel := richSources()
	src.inForce = []gen.PackZonesInForceRow{{Dataset: "zones", Country: "GEO", Identifier: "Z2", ZoneVersion: 4, State: "published",
		Type: "REQ_AUTHORIZATION", Feature: []byte(`{}`), ValidFrom: at(-1), ValidTo: at(1000)}}
	_, files, _ := mustBuild(t, builder(src, tel), buildIn(KindOversight))
	var zones []map[string]any
	if err := json.Unmarshal(files["zones.json"], &zones); err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0]["zone_id"] != "GEO/SC7" || zones[1]["zone_id"] != "GEO/Z2" || zones[1]["in_force_over_the_evidence"] != true {
		t.Fatalf("zones %v", zones)
	}
	src.zones = nil
	m, _, _ := mustBuild(t, builder(src, tel), buildIn(KindOversight))
	if !strings.Contains(m.Sections[SecZones].Reason, "GEO/SC7 version 1 is not in geo_zones") {
		t.Fatalf("%+v", m.Sections[SecZones])
	}
}

// WP-15, WP-17, E-01: the manned section holds the ANSP's manned traffic
// around the evidence (its extent padded by the margin, in the window),
// the two altitudes apart; with none recorded it says none and why an
// empty section is not an empty sky; with the telemetry unreadable it
// says unavailable; with more rows than a pack carries the pack is
// refused, never thinned.
func TestMannedSectionAroundTheEvidence(t *testing.T) {
	src, tel := richSources()
	b := builder(src, tel)
	b.MannedMarginM = 5000
	_, files, _ := mustBuild(t, b, buildIn(KindOversight))
	var rows []map[string]any
	if err := json.Unmarshal(files["manned_tracks.json"], &rows); err != nil || len(rows) != 1 {
		t.Fatalf("manned_tracks.json %v %d", err, len(rows))
	}
	if rows[0]["alt_pressure_m"] != 450.0 || rows[0]["alt_wgs84_m"] != nil || rows[0]["trust"] != "surveillance" {
		t.Fatalf("row %v", rows[0])
	}
	a := tel.mannedArg
	if !a.FromTs.Equal(at(0)) || !a.ToTs.Equal(at(60)) || a.MinLat >= 41.5 || a.MaxLat <= 41.5 || a.MinLon >= 44.6 || a.MaxLon <= 44.6 || a.MaxLat-a.MinLat < 0.08 || a.RowLimit != 101 {
		t.Fatalf("query %+v", a)
	}

	tel.manned = nil
	m, _, _ := mustBuild(t, builder(src, tel), buildIn(KindOversight))
	if s := m.Sections[SecManned]; s.State != StateNone || !strings.Contains(s.Reason, "empty sky") {
		t.Fatalf("none %+v", s)
	}

	_, broken := richSources()
	broken.err = errors.New("telemetry down")
	m, _, _ = mustBuild(t, builder(src, broken), buildIn(KindOversight))
	if s := m.Sections[SecManned]; s.State != StateUnavailable {
		t.Fatalf("unreadable %+v", s)
	}
	m, _, _ = mustBuild(t, builder(src, nil), buildIn(KindOversight))
	if s := m.Sections[SecManned]; s.State != StateUnavailable {
		t.Fatalf("no telemetry %+v", s)
	}
	_, mannedDown := richSources()
	mannedDown.mannedErr = errors.New("manned_tracks unreadable")
	m, _, _ = mustBuild(t, builder(src, mannedDown), buildIn(KindOversight))
	if s := m.Sections[SecManned]; s.State != StateUnavailable || !strings.Contains(s.Reason, "manned_tracks unreadable") ||
		m.Sections[SecTracks].State != StateIncluded {
		t.Fatalf("manned unreadable %+v", s)
	}

	_, many := richSources()
	for range 101 {
		many.manned = append(many.manned, many.manned[0])
	}
	if _, _, err := builder(src, many).Build(context.Background(), buildIn(KindOversight)); err == nil {
		t.Fatal("a manned section past MaxRows did not refuse the pack")
	}
}
