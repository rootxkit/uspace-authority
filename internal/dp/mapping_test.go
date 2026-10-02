package dp

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"
	"github.com/rootxkit/uspace-core/timeplace"

	"github.com/rootxkit/uspace-authority/internal/track"
)

type constGeoid struct{ n float64 }

func (g constGeoid) UndulationM(core.LatLon) (float64, error) { return g.n, nil }

func mapOne(t *testing.T, st *f3411.RIDAircraftState, d *f3411.RIDFlightDetails, deps MapDeps) (*Mapped, bool) {
	t.Helper()
	f := flight("fl-1", st)
	if deps.Network == (timeplace.NetworkPolicy{}) {
		deps.Network = timeplace.DefaultNetworkPolicy()
	}
	resp := st.Timestamp.Value.Add(500 * time.Millisecond)
	return Map(&Input{USSID: "ussp-lab-01", ISAID: "isa-1", Flight: &f, Details: d, ResponseTS: &resp, RxTS: resp.Add(time.Second)}, deps)
}

// 04 §3.1: trust provider, source network_rid, source_instance the
// Service Provider; the values as received, AMSL from HAE through the
// geoid; the flight id kept.
func TestMapIsAProviderTrackOnTheFormat(t *testing.T) {
	m, ok := mapOne(t, state(t0, baseLatDeg, baseLonDeg), nil, MapDeps{Geoid: constGeoid{n: 20}})
	if !ok {
		t.Fatal("not mapped")
	}
	b := m.Message.Body
	if b.Trust != core.TrustProvider || b.Source != track.SourceNetworkRID || b.SourceInstance != "ussp-lab-01" {
		t.Fatalf("trust %s source %s instance %s", b.Trust, b.Source, b.SourceInstance)
	}
	if b.AltWGS84M == nil || *b.AltWGS84M != 600 || b.AltAMSLM == nil || *b.AltAMSLM != 580 || b.AltSource != core.AltGeodetic {
		t.Fatalf("altitude %v %v %s", b.AltWGS84M, b.AltAMSLM, b.AltSource)
	}
	if *b.SpeedMS != 5 || *b.TrackDeg != 90 || *b.VSpeedMS != 0.5 || b.FlightID == nil || *b.FlightID != "fl-1" {
		t.Fatalf("velocity %v %v %v flight %v", *b.SpeedMS, *b.TrackDeg, *b.VSpeedMS, b.FlightID)
	}
	if m.Message.Backlog || m.Message.Producer != Producer || !m.Airborne {
		t.Fatalf("envelope %+v airborne %v", m.Message.Message, m.Airborne)
	}
	if err := m.Message.Validate(); err != nil {
		t.Fatal(err)
	}
}

// R-01, R-10, 04 §3.1: every special value of Table 1 is null, never a
// number; beside it, the same state with the values present carries
// them (E-01).
func TestSpecialValuesAreNull(t *testing.T) {
	st := state(t0, baseLatDeg, baseLonDeg)
	st.Speed, st.Track, st.VerticalSpeed = f32(f3411.SpecialSpeed), f32(f3411.SpecialTrackDirection), f32(f3411.SpecialVerticalSpeed)
	st.Position.Alt, st.Position.PressureAltitude = f32(f3411.SpecialHeight), f32(f3411.SpecialHeight)
	st.Position.Height = &f3411.RIDHeight{Distance: f32(f3411.SpecialHeight), Reference: f3411.GroundLevel}
	m, ok := mapOne(t, st, nil, MapDeps{Geoid: constGeoid{n: 20}})
	if !ok {
		t.Fatal("not mapped")
	}
	b := m.Message.Body
	for name, v := range map[string]*float64{"speed_ms": b.SpeedMS, "track_deg": b.TrackDeg, "vspeed_ms": b.VSpeedMS,
		"alt_wgs84_m": b.AltWGS84M, "alt_pressure_m": b.AltPressureM, "height_m": b.HeightM, "alt_amsl_m": b.AltAMSLM} {
		if v != nil {
			t.Errorf("%s is %v, want null", name, *v)
		}
	}
	if b.HeightRef != nil || b.AltSource != core.AltNone {
		t.Errorf("height_ref %v alt_source %s", b.HeightRef, b.AltSource)
	}

	present := state(t0, baseLatDeg, baseLonDeg)
	present.Position.PressureAltitude = f32(610)
	present.Position.Height = &f3411.RIDHeight{Distance: f32(55), Reference: f3411.GroundLevel}
	m, _ = mapOne(t, present, nil, MapDeps{})
	b = m.Message.Body
	if b.HeightM == nil || *b.HeightM != 55 || b.HeightRef == nil || *b.HeightRef != f3411.GroundLevel {
		t.Fatalf("height %v %v", b.HeightM, b.HeightRef)
	}
	// R-08: without a geoid the pressure altitude is kept, never AMSL.
	if b.AltPressureM == nil || *b.AltPressureM != 610 || b.AltAMSLM != nil || b.AltSource != core.AltNone {
		t.Fatalf("pressure %v amsl %v source %s", b.AltPressureM, b.AltAMSLM, b.AltSource)
	}
}

// R-08: with no geodetic altitude the pressure altitude is the source,
// and never written to alt_amsl_m.
func TestPressureAltitudeIsNeverAMSL(t *testing.T) {
	st := state(t0, baseLatDeg, baseLonDeg)
	st.Position.Alt, st.Position.PressureAltitude = nil, f32(610)
	m, _ := mapOne(t, st, nil, MapDeps{Geoid: constGeoid{n: 20}})
	b := m.Message.Body
	if b.AltSource != core.AltPressure || b.AltAMSLM != nil || *b.AltPressureM != 610 {
		t.Fatalf("source %s amsl %v pressure %v", b.AltSource, b.AltAMSLM, b.AltPressureM)
	}
}

// D6, I-05, SC-06 row 3: a CTA serial in the details gives the track id
// of the direct broadcast of the same serial (rid.AircraftID, ID type
// 1); without details, or with a serial that is not a CTA serial, the
// id is the flight's (rid.UnidentifiedID).
func TestTrackIDIsTheDirectBroadcastsForACTASerial(t *testing.T) {
	id, cta := TrackID("fl-1", details("fl-1", ctaSerial, ""))
	if !cta || id != rid.AircraftID(odid.IDTypeSerial, ctaSerial) {
		t.Fatalf("%s %v", id, cta)
	}
	for name, d := range map[string]*f3411.RIDFlightDetails{
		"no details": nil, "not a CTA serial": details("fl-1", "TEST-NOT-CTA", ""), "blank serial": details("fl-1", "  ", ""),
	} {
		id, cta := TrackID("fl-1", d)
		if cta || id != rid.UnidentifiedID("fl-1") {
			t.Errorf("%s: %s %v", name, id, cta)
		}
	}
}

// Q-A8: the identification of a provider flight is resolved as a
// broadcast is (identify.ResolveBroadcast) on the provider basis; a
// registered serial with its owner's number is registered, an absent
// projection is registry_unavailable.
func TestIdentificationIsOnTheProviderBasis(t *testing.T) {
	op := "00000000-0000-0000-0000-000000000001"
	snap := identify.NewSnapshot(
		[]identify.OperatorFacts{{OperatorID: op, RegistrationNumber: "GEOabcd1234efgh", Status: "active"}},
		[]identify.UASFacts{{DroneID: "00000000-0000-0000-0000-00000000000a", Serial: ctaSerial, RegistrationStatus: "active", OperatorID: &op, InRegistry: true}},
	)
	id := Identify(snap, details("fl-1", ctaSerial, "GEOabcd1234efgh"))
	if id.Status != core.IdentRegistered || id.Reason != core.ReasonMatched || id.Basis != core.BasisProvider {
		t.Fatalf("%+v", id)
	}
	id = Identify(nil, details("fl-1", ctaSerial, "GEOabcd1234efgh"))
	if id.Reason != core.ReasonRegistryUnavailable || id.Basis != core.BasisProvider {
		t.Fatalf("no projection: %+v", id)
	}
	id = Identify(snap, nil)
	if id.Status != core.IdentUnidentified || id.Reason != core.ReasonNoSerial {
		t.Fatalf("no details: %+v", id)
	}
}

// T-02: a state more than MaxAgeS behind its response is not published;
// one within it is, placed against the response timestamp (E-01).
func TestStateOlderThanMaxAgeIsNotPublished(t *testing.T) {
	cnt := &core.Counters{}
	st := state(t0, baseLatDeg, baseLonDeg)
	f := flight("fl-1", st)
	resp := t0.Add(61 * time.Second)
	if _, ok := Map(&Input{USSID: "u", Flight: &f, ResponseTS: &resp, RxTS: resp}, MapDeps{Network: timeplace.DefaultNetworkPolicy(), Counters: cnt}); ok {
		t.Fatal("a state 61 s behind its response was published")
	}
	if cnt.Snapshot()[CounterStateTooOld] != 1 {
		t.Fatalf("counters %v", cnt.Snapshot())
	}
	resp = t0.Add(2 * time.Second)
	rx := resp.Add(300 * time.Millisecond)
	m, ok := Map(&Input{USSID: "u", Flight: &f, ResponseTS: &resp, RxTS: rx}, MapDeps{Network: timeplace.DefaultNetworkPolicy(), Counters: cnt})
	if !ok {
		t.Fatal("a recent state was not published")
	}
	if want := rx.Add(-2 * time.Second); !m.Times.CapturedAt.Equal(want) || m.Times.Source != core.TimeBroadcast {
		t.Fatalf("captured_at %v source %s, want %v broadcast", m.Times.CapturedAt, m.Times.Source, want)
	}
}

// A flight without a current state or a position publishes nothing,
// counted.
func TestFlightWithoutStateOrPositionIsCounted(t *testing.T) {
	cnt := &core.Counters{}
	f := f3411.RIDFlight{Id: "x"}
	if _, ok := Map(&Input{USSID: "u", Flight: &f, RxTS: t0}, MapDeps{Counters: cnt}); ok {
		t.Fatal("published without a state")
	}
	st := state(t0, baseLatDeg, baseLonDeg)
	st.Position.Lat = nil
	f = flight("y", st)
	if _, ok := Map(&Input{USSID: "u", Flight: &f, RxTS: t0}, MapDeps{Counters: cnt, Network: timeplace.DefaultNetworkPolicy()}); ok {
		t.Fatal("published without a position")
	}
	if s := cnt.Snapshot(); s[CounterStateAbsent] != 1 || s[CounterNoPosition] != 1 {
		t.Fatalf("counters %v", s)
	}
}

// WP-13's rule: the operator position travels as operator_position when
// the details carry it, and is absent otherwise (E-01).
func TestOperatorPositionTravelsOnlyWhenGiven(t *testing.T) {
	d := details("fl-1", ctaSerial, "GEOabcd1234efgh")
	d.OperatorLocation = &f3411.OperatorLocation{Position: f3411.LatLngPoint{Lat: 41.7, Lng: 44.8}}
	m, _ := mapOne(t, state(t0, baseLatDeg, baseLonDeg), d, MapDeps{})
	raw, err := m.Message.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if m.Message.OperatorPosition == nil || !contains(string(raw), `"operator_position":{"lat":41.7,"lng":44.8}`) {
		t.Fatalf("%s", raw)
	}
	m, _ = mapOne(t, state(t0, baseLatDeg, baseLonDeg), details("fl-1", ctaSerial, ""), MapDeps{})
	raw, _ = m.Message.Marshal()
	if m.Message.OperatorPosition != nil || contains(string(raw), "operator_position") {
		t.Fatalf("%s", raw)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func BenchmarkFlightMapping(b *testing.B) {
	op := "00000000-0000-0000-0000-000000000001"
	snap := identify.NewSnapshot(
		[]identify.OperatorFacts{{OperatorID: op, RegistrationNumber: "GEOabcd1234efgh", Status: "active"}},
		[]identify.UASFacts{{DroneID: "d", Serial: ctaSerial, RegistrationStatus: "active", OperatorID: &op, InRegistry: true}},
	)
	f := flight("fl-1", state(t0, baseLatDeg, baseLonDeg))
	d := details("fl-1", ctaSerial, "GEOabcd1234efgh")
	resp := t0.Add(time.Second)
	in := &Input{USSID: "ussp-lab-01", Flight: &f, Details: d, ResponseTS: &resp, RxTS: resp}
	deps := MapDeps{Registry: snap, Geoid: constGeoid{n: 20}, Network: timeplace.DefaultNetworkPolicy(), Counters: &core.Counters{}}
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := Map(in, deps); !ok {
			b.Fatal("not mapped")
		}
	}
}
