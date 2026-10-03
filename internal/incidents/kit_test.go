package incidents

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

// Test fixtures: GEO-TEST-* registrations and TEST* serials (CLAUDE.md
// rule 11); keys are generated at test time.

var t0 = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func at(s float64) time.Time { return t0.Add(time.Duration(s * float64(time.Second))) }

func sp(s string) *string { return &s }

func i16(v int16) *int16 { return &v }

func f64(v float64) *float64 { return &v }

var officer = audit.Actor{Type: audit.ActorUser, ID: "officer-1", Realm: audit.RealmConsole}

// fakeSources is the relational side of a pack.
type fakeSources struct {
	violations    []gen.PackViolationsRow
	violationsErr error
	zones         []gen.PackZoneVersionsRow
	inForce       []gen.PackZonesInForceRow
	policyErr     error
	events        []gen.Event
	usspBases     []gen.PackUSSPBaseURLsRow
	usspBasesErr  error
}

func (f *fakeSources) PackViolations(context.Context, gen.PackViolationsParams) ([]gen.PackViolationsRow, error) {
	return f.violations, f.violationsErr
}

func (f *fakeSources) PackZoneVersions(context.Context, gen.PackZoneVersionsParams) ([]gen.PackZoneVersionsRow, error) {
	return f.zones, nil
}

func (f *fakeSources) PackZonesInForce(context.Context, gen.PackZonesInForceParams) ([]gen.PackZonesInForceRow, error) {
	return f.inForce, nil
}

func (f *fakeSources) PackPolicies(_ context.Context, versions []int64) ([]gen.PackPoliciesRow, error) {
	out := make([]gen.PackPoliciesRow, 0, len(versions))
	for _, v := range versions {
		out = append(out, gen.PackPoliciesRow{Version: v, Policy: []byte(`{"max_gap_s":3}`)})
	}
	return out, nil
}

func (f *fakeSources) PackActivePolicy(context.Context) (gen.PackActivePolicyRow, error) {
	if f.policyErr != nil {
		return gen.PackActivePolicyRow{}, f.policyErr
	}
	return gen.PackActivePolicyRow{Version: 1, MaxGapS: 3, Policy: []byte(`{"version":1}`)}, nil
}

func (f *fakeSources) PackEvents(context.Context, gen.PackEventsParams) ([]gen.Event, error) {
	return f.events, nil
}

func (f *fakeSources) PackUSSPBaseURLs(context.Context, int32) ([]gen.PackUSSPBaseURLsRow, error) {
	if f.usspBasesErr != nil {
		return nil, f.usspBasesErr
	}
	return f.usspBases, nil
}

// fakeTelemetry is the telemetry side of a pack.
type fakeTelemetry struct {
	trackIDs []string
	tracks   []reader.EvidenceTracksRow
	txs      []string
	frames   []reader.EvidenceFramesRow
	gaps     []reader.EvidenceWriterGapsRow
	ussp     []reader.EvidenceUSSPFlightsRow
	manned   []reader.EvidenceMannedTracksRow
	// mannedArg is the last manned query.
	mannedArg reader.EvidenceMannedTracksParams
	mannedErr error
	err       error
}

func (f *fakeTelemetry) EvidenceMannedTracks(_ context.Context, arg reader.EvidenceMannedTracksParams) ([]reader.EvidenceMannedTracksRow, error) {
	f.mannedArg = arg
	if f.mannedErr != nil {
		return nil, f.mannedErr
	}
	return f.manned, f.err
}

func (f *fakeTelemetry) EvidenceTrackIDs(context.Context, reader.EvidenceTrackIDsParams) ([]string, error) {
	return f.trackIDs, f.err
}

func (f *fakeTelemetry) EvidenceTracks(context.Context, reader.EvidenceTracksParams) ([]reader.EvidenceTracksRow, error) {
	return f.tracks, f.err
}

func (f *fakeTelemetry) EvidenceTransmitters(context.Context, reader.EvidenceTransmittersParams) ([]string, error) {
	return f.txs, f.err
}

func (f *fakeTelemetry) EvidenceFrames(context.Context, reader.EvidenceFramesParams) ([]reader.EvidenceFramesRow, error) {
	return f.frames, f.err
}

func (f *fakeTelemetry) EvidenceWriterGaps(context.Context, reader.EvidenceWriterGapsParams) ([]reader.EvidenceWriterGapsRow, error) {
	return f.gaps, f.err
}

func (f *fakeTelemetry) EvidenceUSSPFlights(context.Context, reader.EvidenceUSSPFlightsParams) ([]reader.EvidenceUSSPFlightsRow, error) {
	return f.ussp, f.err
}

func (f *fakeTelemetry) EvidenceOldestUSSPFlight(context.Context) (time.Time, error) {
	return t0, f.err
}

// fakePersonal answers personal data for registrations it knows.
type fakePersonal struct {
	mu    sync.Mutex
	reads []string
	known map[string]map[string]string
}

func (f *fakePersonal) Operator(_ context.Context, reg, purpose string, _ audit.Actor) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads = append(f.reads, reg+"|"+purpose)
	if d, ok := f.known[reg]; ok {
		return d, nil
	}
	return nil, errors.New("no operator of the registry has this registration")
}

// memStorage keeps archives in memory.
type memStorage struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func (m *memStorage) Put(incidentID, packID string, data []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs == nil {
		m.objs = map[string][]byte{}
	}
	ref := "mem:" + incidentID + "/" + packID
	if _, ok := m.objs[ref]; ok {
		return "", errors.New("exists")
	}
	m.objs[ref] = append([]byte(nil), data...)
	return ref, nil
}

func (m *memStorage) Discard(ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objs[ref]; !ok {
		return errors.New("no such object")
	}
	delete(m.objs, ref)
	return nil
}

func (m *memStorage) Get(ref string, maxBytes int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.objs[ref]
	if !ok {
		return nil, errors.New("no such object")
	}
	if int64(len(d)) > maxBytes {
		return nil, ErrTooLarge
	}
	return append([]byte(nil), d...), nil
}

// ring is a publication key ring generated at test time.
func ring(t *testing.T, kid string, i int) *auth.KeyRing {
	t.Helper()
	r, err := auth.NewKeyRing(auth.SigningKey{KID: kid, Key: tokentest.Key(t, i)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	testSerial = "TESTSERIAL0001"
	testReg    = "GEOTESTOPER00001"
	testTx     = "AA:BB:CC:00:00:01"
	testTrack  = "track-test-1"
)

// Ids of the fixtures (ULIDs).
var (
	testIncID  = "01K6A0000000000000000NC001"
	testPackID = "01K6A0000000000000000PACK1"
	testVioID  = "01K6A00000000000000000V001"
)

// incidentView is an incident with one aircraft.
func incidentView() View {
	return View{
		Incident: gen.Incident{IncidentID: testIncID, Kind: KindViolationEscalated, OccurredAt: at(0), OpenedFrom: FromViolation,
			SourceViolationID: sp(testVioID), IntentRefs: []string{}, Severity: "critical", Status: StatusOpen,
			OpenedBy: "inspector-1", CreatedAt: at(100), UpdatedAt: at(100)},
		Aircraft: []gen.ListIncidentAircraftRow{{ID: 1, Serial: sp(testSerial), OperatorReg: sp(testReg), TrackIds: []string{testTrack},
			Identification: []byte(`{"evidence_trust":"broadcast"}`), AddedBy: "inspector-1", AddedAt: at(100)}},
		Notes: []gen.ListIncidentNotesRow{{ID: 1, Author: "inspector-1", Body: "seen over the park", CreatedAt: at(101)}},
	}
}

func trackRow(s float64) reader.EvidenceTracksRow {
	return reader.EvidenceTracksRow{CapturedAt: at(s), TrackID: testTrack, MsgID: "m", RxTs: at(s), TimeSource: "broadcast",
		Source: "direct_rid", SourceInstance: "rx-1", Trust: "broadcast", LatDeg: 41.5, LonDeg: 44.6, AltSource: "geodetic",
		AltAmslM: f64(500), IdentStatus: "registered", IdentReason: "matched", IdentBasis: "as_broadcast", Serial: sp(testSerial),
		OperatorReg: sp(testReg + "-abc")}
}

// richSources is a pack with a violation, tracks, frames (a Location,
// a System and a positionless Location), a recorded gap and a
// Display Provider row.
func richSources() (*fakeSources, *fakeTelemetry) {
	src := &fakeSources{
		violations: []gen.PackViolationsRow{{ViolationID: testVioID, Kind: "height_120m", Severity: "critical",
			AlertKey: "h", TrackID: testTrack, Serial: sp(testSerial), OperatorReg: sp(testReg), ZoneID: sp("GEO/SC7"),
			ZoneVersion: func() *int64 { v := int64(1); return &v }(), DetectorState: "cleared", OpenedAt: at(1), ClosedAt: func() *time.Time { x := at(9); return &x }(),
			ClearReason: sp("resolved"), LastCapturedAt: at(9), PolicyVersion: 1, PeakName: sp("height_agl_m"), PeakValue: f64(178),
			Detail: []byte(`{}`), TerrainSource: []byte(`{"dataset":"COP-DEM GLO-30","spacing_m":30}`), EvidenceTrust: "broadcast",
			EvidenceRefs: []byte(`[]`), EvidenceTrackIds: []string{testTrack}, EvidenceExcerpt: []byte(`[{"lat":41.5,"lng":44.6}]`),
			Cell5: "c5:1:1", Status: "escalated", CreatedAt: at(1)}},
		zones: []gen.PackZoneVersionsRow{{Dataset: "zones", Country: "GEO", Identifier: "SC7", ZoneVersion: 1, State: "published",
			Type: "PROHIBITED", Feature: []byte(`{"type":"Feature"}`), ValidFrom: at(-3600), ValidTo: at(86400)}},
		events: []gen.Event{{ID: 1, Ts: at(1), ActorType: "system", ActorID: "detect", EntityType: "violation",
			EntityID: sp(testVioID), EventType: "violation_raised", Payload: []byte(`{}`), PrevHash: "0", Hash: "1"}},
	}
	tel := &fakeTelemetry{
		trackIDs: []string{testTrack},
		tracks:   []reader.EvidenceTracksRow{trackRow(1), trackRow(2), trackRow(3), trackRow(9), trackRow(10)},
		txs:      []string{testTx},
		frames: []reader.EvidenceFramesRow{
			{IngestTs: at(1), FrameID: "f1", ReceiverID: "rx-1", Transmitter: testTx, MsgType: i16(1), Payload: []byte{1, 2, 3},
				PayloadSha256: []byte{9}, Serial: sp(testSerial), LatDeg: f64(41.5), LonDeg: f64(44.6), CapturedAt: func() *time.Time { x := at(1); return &x }()},
			{IngestTs: at(2), FrameID: "f2", ReceiverID: "rx-1", Transmitter: testTx, MsgType: i16(4), Payload: []byte{4, 5, 6},
				PayloadSha256: []byte{8}},
			{IngestTs: at(2.5), FrameID: "f3", ReceiverID: "rx-1", Transmitter: testTx, MsgType: i16(1), Payload: []byte{7},
				PayloadSha256: []byte{7}, CapturedAt: func() *time.Time { x := at(2.5); return &x }()},
		},
		gaps: []reader.EvidenceWriterGapsRow{{DedupeKey: "g1", TableName: "tracks", Stream: "TSW", FromSeq: 1, ToSeq: 2, Cause: "dropped",
			Count: 3, CountUnit: "rows", At: at(6)}},
		ussp: []reader.EvidenceUSSPFlightsRow{{RxTs: at(1), UsspID: "USSPA", UssBaseUrl: "https://ussp.example.test/rid", FlightID: "F1",
			TrackID: testTrack, StateTs: at(1), Flight: []byte(`{"id":"F1"}`), Details: []byte(`{"operator_location":{"lat":41.4,"lng":44.5}}`)}},
		manned: []reader.EvidenceMannedTracksRow{{CapturedAt: at(2), SourceCapturedAt: at(1.7), RxTs: at(2.3), TimeSource: "provider",
			Icao24: "4ca7b5", Callsign: sp("TST123"), LatDeg: 41.52, LonDeg: 44.61, AltPressureM: f64(450), SourceClass: "ads_b",
			Quality: []byte(`{"nic":8}`), Trust: "surveillance", Source: "ansp_feed", SourceInstance: "adsb-tbs", State: "live"}},
	}
	return src, tel
}
