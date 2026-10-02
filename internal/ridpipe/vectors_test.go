package ridpipe

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"
	"github.com/rootxkit/uspace-core/timeplace"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// The knowledge vectors run through this repository's adapters: each
// test maps the vector's wire shape onto what a receiver sends (frames
// encoded with uspace-core odid.Encode), runs the batch through the
// Pipeline, and compares what the adapter produced (the row's decoded
// columns, the published track) with the vector. None re-implements a
// judgement; the expected values are the vector's.

// tsOffset derives where the Location timestamp sits in the frames build
// makes, by encoding two frames that differ only in it and diffing them
// (E-03: never a wire offset from memory). The field is two bytes,
// little-endian, in tenths of a second.
func tsOffset(t *testing.T, build func(secondsAfterHour float64) []byte) int {
	t.Helper()
	a, b := build(1.0), build(2.5)
	if len(a) != len(b) {
		t.Fatalf("frames of %d and %d bytes", len(a), len(b))
	}
	var diff []int
	for i := range a {
		if a[i] != b[i] {
			diff = append(diff, i)
		}
	}
	if len(diff) == 0 || len(diff) > 2 || diff[len(diff)-1]-diff[0] > 1 {
		t.Fatalf("timestamps differ in bytes %v, want one 16-bit field", diff)
	}
	off := diff[0]
	if binary.LittleEndian.Uint16(a[off:]) != 10 || binary.LittleEndian.Uint16(b[off:]) != 25 {
		t.Fatalf("offset %d does not hold the tenths little-endian: %x / %x", off, a[off:off+2], b[off:off+2])
	}
	return off
}

// E-03: the derivation itself, pinned for a lone Location and for a
// Location second in a pack, and checked against the decoder: a frame
// patched at the derived offset decodes to the patched time, and the two
// values Encode refuses (0xFFFF unknown, 3600.0 s invalid) decode to
// unknown and to 3600.0.
func TestTimestampOffsetIsDerivedFromTwoEncodedFrames(t *testing.T) {
	lone := func(s float64) []byte { l := loc(baseLatDeg, baseLonDeg); l.SecondsAfterHour = &s; return frame(t, l) }
	pack := func(s float64) []byte {
		l := loc(baseLatDeg, baseLonDeg)
		l.SecondsAfterHour = &s
		return frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTTS0001"}, l)
	}
	for name, build := range map[string]func(float64) []byte{"lone": lone, "pack": pack} {
		off := tsOffset(t, build)
		f := build(1.0)
		for _, tenths := range []uint16{0, 20963, 35999, timeplace.TimestampUnknown, 36000} {
			binary.LittleEndian.PutUint16(f[off:], tenths)
			msgs, err := odid.Decode(f, odid.DecodeOptions{})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			var got *float64
			for _, m := range msgs {
				if l, ok := m.(odid.Location); ok {
					got = l.SecondsAfterHour
				}
			}
			switch {
			case tenths == timeplace.TimestampUnknown && got != nil:
				t.Errorf("%s: 0xFFFF decoded to %v, want unknown", name, *got)
			case tenths != timeplace.TimestampUnknown && (got == nil || *got != float64(tenths)/10):
				t.Errorf("%s: %d tenths decoded to %v", name, tenths, got)
			}
			l := odid.Location{SecondsAfterHour: got}
			if timestampTenths(&l) != tenths {
				t.Errorf("%s: the adapter reads %d tenths back as %d", name, tenths, timestampTenths(&l))
			}
		}
	}
}

// --- odid_decode.json: frame -> the decoded columns of the row -------

type vecOdidInput struct {
	Hex         string          `json:"hex"`
	EncodedFrom json.RawMessage `json:"encoded_from"`
}

type vecOdidMsg struct {
	Type              string   `json:"type"`
	IDType            *int     `json:"id_type"`
	UAType            *int     `json:"ua_type"`
	UAID              *string  `json:"ua_id"`
	Status            *int     `json:"status"`
	DirectionDeg      *float64 `json:"direction_deg"`
	SpeedHorizontalMS *float64 `json:"speed_horizontal_ms"`
	SpeedVerticalMS   *float64 `json:"speed_vertical_ms"`
	LatDeg            *float64 `json:"lat_deg"`
	LonDeg            *float64 `json:"lon_deg"`
	AltBaroM          *float64 `json:"alt_baro_m"`
	AltHAEM           *float64 `json:"alt_hae_m"`
	HeightReference   *int     `json:"height_reference"`
	HeightM           *float64 `json:"height_m"`
	OperatorID        *string  `json:"operator_id"`
}

type vecOdidExpected struct {
	Messages      []map[string]json.RawMessage `json:"messages"`
	Error         *string                      `json:"error"`
	ErrorContains string                       `json:"error_contains"`
}

// odidColumns is what the adapter must write into a row for the
// vector's expected messages: the Basic ID of type 1 as serial and its
// type (the first Basic ID's type when none is a serial), the Operator
// ID, and the Location's values under the column names with the F3411
// spellings of the status and the height reference.
type odidColumns struct {
	serial, operator *string
	idType           *int
	lat, lon, hae    *float64
	baro, height     *float64
	speed, dir, vs   *float64
	heightRef        *string
	status           *string
}

var vecStatusNames = map[int]string{0: "Undeclared", 1: "Ground", 2: "Airborne", 3: "Emergency", 4: "RemoteIDSystemFailure"}

func expectedColumns(t *testing.T, msgs []map[string]json.RawMessage) odidColumns {
	t.Helper()
	var c odidColumns
	for _, raw := range msgs {
		// Only the members the row has columns for; the rest are core's
		// own vector test's.
		var m vecOdidMsg
		b, _ := json.Marshal(raw)
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		switch m.Type {
		case "basic_id":
			if c.idType == nil {
				c.idType = m.IDType
			}
			if *m.IDType == 1 && *m.UAID != "" {
				c.serial, c.idType = m.UAID, m.IDType
			}
		case "operator_id":
			if *m.OperatorID != "" {
				c.operator = m.OperatorID
			}
		case "location":
			c.lat, c.lon, c.hae, c.baro, c.height = m.LatDeg, m.LonDeg, m.AltHAEM, m.AltBaroM, m.HeightM
			c.speed, c.dir, c.vs = m.SpeedHorizontalMS, m.DirectionDeg, m.SpeedVerticalMS
			if m.HeightM != nil {
				ref := map[int]string{0: "TakeoffLocation", 1: "GroundLevel"}[*m.HeightReference]
				c.heightRef = &ref
			}
			if name, ok := vecStatusNames[*m.Status]; ok {
				c.status = &name
			}
		}
	}
	return c
}

func eqIntPtr(t *testing.T, field string, got, want *int) {
	t.Helper()
	if (got == nil) != (want == nil) || (got != nil && *got != *want) {
		t.Errorf("%s: got %v, want %v", field, deref(got), deref(want))
	}
}

func TestVectorsOdidDecodeIntoTheRowColumns(t *testing.T) {
	f := vectors.Load(t, "odid_decode.json")
	latTol, _ := f.FloatTolerance("lat_deg/lon_deg")
	tol, _ := f.FloatTolerance("other floats")
	accepted, refused := 0, 0
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in vecOdidInput
		var exp vecOdidExpected
		c.Decode(t, &in, &exp)
		payload, err := hex.DecodeString(in.Hex)
		if err != nil {
			t.Fatalf("input.hex: %v", err)
		}
		p, _ := pipe(DefaultSettings(), Deps{})
		heard := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
		b := batchOf("rx-1", heard, false, rxRow("rx-1", "TEST-TX", payload, at(heard)))
		observe(t, p, b)
		r := b.Rows[0]
		if r.CapturedAt == nil || r.TimeSource == nil {
			t.Fatal("row not placed")
		}
		if exp.Error != nil {
			refused++
			if r.DecodeError == nil || !strings.Contains(*r.DecodeError, *exp.Error) || !strings.Contains(*r.DecodeError, exp.ErrorContains) {
				t.Fatalf("decode_error %v, want the phrase %q", deref(r.DecodeError), *exp.Error)
			}
			if p.Counters().Get(CounterDecodeRefused) != 1 {
				t.Errorf("decode_refused %d", p.Counters().Get(CounterDecodeRefused))
			}
			if r.Serial != nil || r.IDType != nil || r.LatDeg != nil || r.Status != nil || r.OperatorReg != nil {
				t.Errorf("a refused frame left decoded columns: %+v", r)
			}
			return
		}
		accepted++
		if r.DecodeError != nil {
			t.Fatalf("decode_error %q on an accepted frame", *r.DecodeError)
		}
		want := expectedColumns(t, exp.Messages)
		vectors.EqualStrPtr(t, "serial", r.Serial, want.serial)
		eqIntPtr(t, "id_type", r.IDType, want.idType)
		vectors.EqualStrPtr(t, "operator_reg", r.OperatorReg, want.operator)
		vectors.NearPtr(t, "lat_deg", r.LatDeg, want.lat, latTol)
		vectors.NearPtr(t, "lon_deg", r.LonDeg, want.lon, latTol)
		vectors.NearPtr(t, "alt_wgs84_m", r.AltWGS84M, want.hae, tol)
		vectors.NearPtr(t, "alt_pressure_m", r.AltPressureM, want.baro, tol)
		vectors.NearPtr(t, "height_m", r.HeightM, want.height, tol)
		vectors.EqualStrPtr(t, "height_ref", r.HeightRef, want.heightRef)
		vectors.NearPtr(t, "speed_ms", r.SpeedMS, want.speed, tol)
		vectors.NearPtr(t, "track_deg", r.TrackDeg, want.dir, tol)
		vectors.NearPtr(t, "vspeed_ms", r.VSpeedMS, want.vs, tol)
		vectors.EqualStrPtr(t, "status", r.Status, want.status)
		if len(exp.Messages) == 0 && p.Counters().Get(CounterFramesSkipped) != 1 {
			t.Errorf("a frame of skipped messages only is not counted")
		}
	})
	t.Logf("odid_decode.json through the row adapter: %d accepted, %d refused", accepted, refused)
}

// --- rid_time.json: observation -> captured_at, time_source ----------

type vecTimeInput struct {
	TimestampTenths *uint16   `json:"timestamp_tenths"`
	TSAccuracyCode  *uint8    `json:"ts_accuracy_code"`
	ReceivedAt      time.Time `json:"received_at"`
	TimeToleranceS  float64   `json:"time_tolerance_s"`
	MaxLatencyS     float64   `json:"max_latency_s"`
	// Network cases (dp-poller's adapter, WP-14).
	StateTimestamp    *time.Time `json:"state_timestamp"`
	ResponseTimestamp *time.Time `json:"response_timestamp"`
	MaxAgeS           *float64   `json:"max_age_s"`
}

type vecTimeExpected struct {
	TS         time.Time `json:"ts"`
	CapturedAt time.Time `json:"captured_at"`
	TimeSource string    `json:"time_source"`
	Fallback   *string   `json:"fallback"`
}

func TestVectorsRidTimeBroadcastThroughTheIngest(t *testing.T) {
	f := vectors.Load(t, "rid_time.json")
	build := func(s float64, acc uint8) []byte {
		l := loc(baseLatDeg, baseLonDeg)
		l.SecondsAfterHour, l.TSAccuracy = &s, acc
		return frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTTIME01"}, l)
	}
	off := tsOffset(t, func(s float64) []byte { return build(s, 0) })
	ran, network := 0, 0
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in vecTimeInput
		c.Decode(t, &in, nil)
		if in.TimestampTenths == nil {
			network++
			t.Skip("network placement (timeplace.PlaceNetwork) is dp-poller's adapter, WP-14")
		}
		var exp vecTimeExpected
		c.Decode(t, nil, &exp)
		ran++
		s := DefaultSettings()
		s.Broadcast = timeplace.BroadcastPolicy{ToleranceS: in.TimeToleranceS, MaxLatencyS: in.MaxLatencyS}
		p, rec := pipe(s, Deps{})
		payload := build(0, *in.TSAccuracyCode)
		binary.LittleEndian.PutUint16(payload[off:], *in.TimestampTenths)
		b := batchOf("rx-1", in.ReceivedAt, false, rxRow("rx-1", "TEST-TX", payload, at(in.ReceivedAt)))
		observe(t, p, b)
		r := b.Rows[0]
		if r.DecodeError != nil {
			t.Fatal(*r.DecodeError)
		}
		vectors.EqualTime(t, "captured_at", *r.CapturedAt, exp.CapturedAt)
		if *r.TimeSource != exp.TimeSource {
			t.Errorf("time_source %s, want %s", *r.TimeSource, exp.TimeSource)
		}
		noTime := exp.Fallback != nil && (*exp.Fallback == string(timeplace.FallbackUnknown) || *exp.Fallback == string(timeplace.FallbackInvalid))
		if noTime {
			if r.TSBroadcast != nil {
				t.Errorf("ts_broadcast %v for a %s timestamp", *r.TSBroadcast, *exp.Fallback)
			}
		} else {
			vectors.EqualTimePtr(t, "ts_broadcast", r.TSBroadcast, &exp.TS)
		}
		counter := CounterPlacedBroadcast
		if exp.Fallback != nil {
			counter = CounterTimeFallback + *exp.Fallback
		}
		if p.Counters().Get(counter) != 1 {
			t.Errorf("%s not counted: %v", counter, p.Counters().Snapshot())
		}
		tracks := rec.tracks(t)
		if len(tracks) != 1 {
			t.Fatalf("%d tracks published", len(tracks))
		}
		m := tracks[0]
		if m.CapturedAt != bus.Stamp(exp.CapturedAt) || string(m.TimeSource) != exp.TimeSource || m.RxTS != bus.Stamp(in.ReceivedAt) {
			t.Errorf("envelope captured_at %s time_source %s rx_ts %s", m.CapturedAt, m.TimeSource, m.RxTS)
		}
		switch {
		case noTime && m.TS != nil:
			t.Errorf("envelope ts %s for a %s timestamp (T-12: not ordered within the source)", *m.TS, *exp.Fallback)
		case !noTime && (m.TS == nil || *m.TS != bus.Stamp(exp.TS)):
			t.Errorf("envelope ts %v, want %s", deref(m.TS), bus.Stamp(exp.TS))
		}
	})
	if ran != 18 {
		t.Errorf("ran %d broadcast cases, want 18", ran)
	}
	t.Logf("rid_time.json: %d broadcast cases through the ingest, %d network cases skipped (WP-14)", ran, network)
}

// --- rid_identity.json: frame sequences -> published tracks, counters

type vecIdentitySettings struct {
	IdentityTTLS    *float64 `json:"identity_ttl_s"`
	MaxGapS         *float64 `json:"max_gap_s"`
	IdentifyWithinS *float64 `json:"identify_within_s"`
}

type vecIdentityMessage struct {
	Type       string   `json:"type"`
	IDType     *uint8   `json:"id_type"`
	UAID       *string  `json:"ua_id"`
	LatDeg     *float64 `json:"lat_deg"`
	OperatorID *string  `json:"operator_id"`
}

type vecIdentityStep struct {
	NowS        float64              `json:"now_s"`
	Messages    []vecIdentityMessage `json:"messages"`
	Receiver    *string              `json:"receiver"`
	Transmitter *string              `json:"transmitter"`
}

type vecIdentityObservation struct {
	DroneID    string    `json:"drone_id"`
	Label      string    `json:"label"`
	Identified bool      `json:"identified"`
	UAID       string    `json:"ua_id"`
	IDType     uint8     `json:"id_type"`
	OperatorID *string   `json:"operator_id"`
	LatDeg     float64   `json:"lat_deg"`
	RxTS       time.Time `json:"rx_ts"`
}

// identityEpoch is the vectors' time origin (rx_ts of now_s 0).
var identityEpoch = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func TestVectorsRidIdentityThroughTheIngest(t *testing.T) {
	f := vectors.Load(t, "rid_identity.json")
	latTol, _ := f.FloatTolerance("lat_deg")
	var defaults struct {
		Receiver    string `json:"receiver"`
		Transmitter string `json:"transmitter"`
	}
	f.Header(t, "defaults", &defaults)
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in struct {
			Settings vecIdentitySettings `json:"settings"`
			Steps    []vecIdentityStep   `json:"steps"`
		}
		var exp struct {
			PerStep  []*vecIdentityObservation `json:"per_step"`
			Counters map[string]uint64         `json:"counters"`
		}
		c.Decode(t, &in, &exp)
		s := DefaultSettings()
		if v := in.Settings.IdentityTTLS; v != nil {
			s.Tracker.IdentityTTLS = *v
		}
		if v := in.Settings.MaxGapS; v != nil {
			s.Tracker.MaxGapS = *v
		}
		if v := in.Settings.IdentifyWithinS; v != nil {
			s.Tracker.IdentifyWithinS = *v
			if *v == 0 {
				s.Tracker.IdentifyWithinS = rid.IdentifyAtOnceS
			}
		}
		p, rec := pipe(s, Deps{})
		for i, step := range in.Steps {
			rx, tx := defaults.Receiver, defaults.Transmitter
			if step.Receiver != nil {
				rx = *step.Receiver
			}
			if step.Transmitter != nil {
				tx = *step.Transmitter
			}
			var msgs []odid.Message
			for _, m := range step.Messages {
				switch m.Type {
				case "basic_id":
					msgs = append(msgs, odid.BasicID{IDType: odid.IDType(*m.IDType), UAID: *m.UAID})
				case "location":
					lat := baseLatDeg
					if m.LatDeg != nil {
						lat = *m.LatDeg
					}
					msgs = append(msgs, odid.Location{Status: odid.StatusAirborne, LatDeg: &lat, LonDeg: f64(baseLonDeg)})
				case "operator_id":
					msgs = append(msgs, odid.OperatorID{OperatorID: *m.OperatorID})
				default:
					t.Fatalf("message type %q", m.Type)
				}
			}
			heard := identityEpoch.Add(time.Duration(step.NowS * float64(time.Second)))
			rec.reset()
			observe(t, p, batchOf(rx, heard, false, rxRow(rx, tx, frame(t, msgs...), at(heard))))
			got := rec.tracks(t)
			want := exp.PerStep[i]
			field := fmt.Sprintf("per_step[%d]", i)
			switch {
			case want == nil && len(got) == 0:
				continue
			case want == nil:
				t.Errorf("%s: published %s, want nothing", field, got[0].Body.TrackID)
				continue
			case len(got) != 1:
				t.Errorf("%s: published %d tracks, want %s", field, len(got), want.Label)
				continue
			}
			m := got[0]
			if m.Body.TrackID != want.DroneID {
				t.Errorf("%s: track_id %s, want %s", field, m.Body.TrackID, want.DroneID)
			}
			vectors.NearPtr(t, field+".lat_deg", &m.Body.Position.Lat, &want.LatDeg, latTol)
			if m.RxTS != bus.Stamp(want.RxTS) {
				t.Errorf("%s: rx_ts %s, want %s", field, m.RxTS, bus.Stamp(want.RxTS))
			}
			id := m.Body.Identification
			vectors.EqualStrPtr(t, field+".operator_reg", id.OperatorReg, want.OperatorID)
			switch {
			case !want.Identified && id.Status != core.IdentUnidentified:
				t.Errorf("%s: unidentified observation resolved %s/%s", field, id.Status, id.Reason)
			case want.Identified && want.IDType == uint8(odid.IDTypeSerial):
				vectors.EqualStrPtr(t, field+".serial", id.Serial, &want.UAID)
			case want.Identified && id.Reason != core.ReasonNotASerial:
				t.Errorf("%s: identity of type %d resolved %s", field, want.IDType, id.Reason)
			}
		}
		live, _ := p.TrackerCounters()
		for name, want := range exp.Counters {
			if got := live.Get(name); got != want {
				t.Errorf("counters.%s: got %d, want %d", name, got, want)
			}
		}
	})
}

// --- pressure_altitude.json: -> alt_amsl_m, alt_pressure_m, alt_source

type vecAltStep struct {
	NowS             float64  `json:"now_s"`
	VertAccuracyCode uint8    `json:"vert_accuracy_code"`
	AltPressureM     *float64 `json:"alt_pressure_m"`
}

type vecAltResult struct {
	AltAMSLM  *float64 `json:"alt_amsl_m"`
	AltSource *string  `json:"alt_source"`
}

// altTrack runs one Location of the given altitudes through p at now
// and returns the published track's altitude fields.
func altTrack(t *testing.T, p *Pipeline, rec *recorder, now time.Time, hae, baro *float64, code uint8) (amsl, pressure *float64, src core.AltSource) {
	t.Helper()
	l := loc(baseLatDeg, baseLonDeg)
	l.AltHAEM, l.AltBaroM, l.VertAccuracy = hae, baro, code
	rec.reset()
	observe(t, p, batchOf("rx-1", now, false,
		rxRow("rx-1", "TEST-ALT", frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTALT001"}, l), at(now))))
	got := rec.tracks(t)
	if len(got) != 1 {
		t.Fatalf("%d tracks published", len(got))
	}
	b := got[0].Body
	return b.AltAMSLM, b.AltPressureM, b.AltSource
}

// compareAlt maps the vector's result onto the track (R-08): a geodetic
// altitude is alt_amsl_m; a pressure altitude is alt_pressure_m with
// alt_source pressure and alt_amsl_m null; none is null with source none.
func compareAlt(t *testing.T, field string, amsl, pressure *float64, src core.AltSource, want vecAltResult, tol float64) {
	t.Helper()
	wantSrc := core.AltNone
	if want.AltSource != nil {
		wantSrc = core.AltSource(*want.AltSource)
	}
	if src != wantSrc {
		t.Errorf("%s.alt_source %s, want %s", field, src, wantSrc)
	}
	switch wantSrc {
	case core.AltGeodetic:
		vectors.NearPtr(t, field+".alt_amsl_m", amsl, want.AltAMSLM, tol)
	case core.AltPressure:
		if amsl != nil {
			t.Errorf("%s: a pressure altitude in alt_amsl_m (%v): R-08", field, *amsl)
		}
		vectors.NearPtr(t, field+".alt_pressure_m", pressure, want.AltAMSLM, tol)
	case core.AltNone, core.AltNetwork:
		if amsl != nil {
			t.Errorf("%s.alt_amsl_m %v, want null", field, *amsl)
		}
	}
}

func TestVectorsPressureAltitudeOnThePublishedTrack(t *testing.T) {
	f := vectors.Load(t, "pressure_altitude.json")
	tol, _ := f.FloatTolerance("alt_amsl_m")
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in struct {
			AltHAEM             *float64     `json:"alt_hae_m"`
			AltPressureM        *float64     `json:"alt_pressure_m"`
			VertAccuracyCode    *uint8       `json:"vert_accuracy_code"`
			GeoidUndulationM    *float64     `json:"geoid_undulation_m"`
			MinVerticalAccuracy *uint8       `json:"min_vertical_accuracy"`
			HoldPressure        *bool        `json:"hold_pressure"`
			PressureHoldS       *float64     `json:"pressure_hold_s"`
			Steps               []vecAltStep `json:"steps"`
		}
		var exp struct {
			AltAMSLM  *float64       `json:"alt_amsl_m"`
			AltSource *string        `json:"alt_source"`
			PerStep   []vecAltResult `json:"per_step"`
		}
		c.Decode(t, &in, &exp)
		s := DefaultSettings()
		var d Deps
		if in.GeoidUndulationM != nil {
			d.Geoid = constGeoid{*in.GeoidUndulationM}
		}
		t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
		if in.Steps == nil {
			s.Altitude.MinVerticalAccuracy = *in.MinVerticalAccuracy
			p, rec := pipe(s, d)
			now := t0
			if *in.HoldPressure {
				// "The hold is in force for this message": a poor fix one
				// second before puts the track's hold in force, as a
				// running track would have it (AltitudeSelector).
				altTrack(t, p, rec, now, in.AltHAEM, f64(507.5), 1)
				now = now.Add(time.Second)
			}
			amsl, pressure, src := altTrack(t, p, rec, now, in.AltHAEM, in.AltPressureM, *in.VertAccuracyCode)
			compareAlt(t, "result", amsl, pressure, src, vecAltResult{AltAMSLM: exp.AltAMSLM, AltSource: exp.AltSource}, tol)
			return
		}
		s.Altitude.PressureHoldS = *in.PressureHoldS
		p, rec := pipe(s, d)
		for i, st := range in.Steps {
			now := t0.Add(time.Duration(st.NowS * float64(time.Second)))
			amsl, pressure, src := altTrack(t, p, rec, now, in.AltHAEM, st.AltPressureM, st.VertAccuracyCode)
			compareAlt(t, fmt.Sprintf("per_step[%d]", i), amsl, pressure, src, exp.PerStep[i], tol)
		}
	})
}

// --- identification_status.json: -> the track's identification -------

type vecRegistry struct {
	Operators []struct {
		OperatorID         string `json:"operator_id"`
		RegistrationNumber string `json:"registration_number"`
		Status             string `json:"status"`
	} `json:"operators"`
	UAS []struct {
		DroneID            string  `json:"drone_id"`
		Label              string  `json:"label"`
		Serial             string  `json:"serial"`
		RegistrationStatus string  `json:"registration_status"`
		UASOperatorID      *string `json:"uas_operator_id"`
		InRegistry         bool    `json:"in_registry"`
	} `json:"uas"`
	Notes []string `json:"notes"`
}

// lookup is the vector's registry as WP-3's projection reader holds it
// after a read.
func (r vecRegistry) lookup(t *testing.T) func() identify.Lookup {
	t.Helper()
	ops := make([]identify.OperatorFacts, 0, len(r.Operators))
	for _, o := range r.Operators {
		ops = append(ops, identify.OperatorFacts{OperatorID: o.OperatorID, RegistrationNumber: o.RegistrationNumber, Status: o.Status})
	}
	uas := make([]identify.UASFacts, 0, len(r.UAS))
	for _, u := range r.UAS {
		uas = append(uas, identify.UASFacts{DroneID: u.DroneID, Label: u.Label, Serial: u.Serial,
			RegistrationStatus: u.RegistrationStatus, OperatorID: u.UASOperatorID, InRegistry: u.InRegistry})
	}
	return loadedRegistry(t, ops, uas)
}

func TestVectorsIdentificationStatusOnThePublishedTrack(t *testing.T) {
	f := vectors.Load(t, "identification_status.json")
	var fx struct {
		Registry vecRegistry `json:"registry"`
	}
	vectors.Unmarshal(t, f.Fixtures, &fx)
	ran := map[string]int{}
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in struct {
			Kind             string       `json:"kind"`
			Serial           *string      `json:"serial"`
			OperatorReg      *string      `json:"operator_reg"`
			RegistryOverride *vecRegistry `json:"registry_override"`
			RemoteID         *struct {
				Identified bool    `json:"identified"`
				UAID       string  `json:"ua_id"`
				IDType     uint8   `json:"id_type"`
				OperatorID *string `json:"operator_id"`
			} `json:"remote_id"`
			DroneID *string `json:"drone_id"`
		}
		var exp struct {
			Status                string  `json:"status"`
			Reason                string  `json:"reason"`
			Serial                *string `json:"serial"`
			OperatorReg           *string `json:"operator_reg"`
			Mismatch              bool    `json:"mismatch"`
			RegisteredOperatorReg *string `json:"registered_operator_reg"`
			DroneID               *string `json:"drone_id"`
		}
		c.Decode(t, &in, &exp)
		// The frames a transmitter would send for the case's identity.
		var msgs []odid.Message
		var op *string
		switch in.Kind {
		case "broadcast":
			if in.Serial != nil {
				msgs = append(msgs, odid.BasicID{IDType: odid.IDTypeSerial, UAID: *in.Serial})
			}
			op = in.OperatorReg
		case "remote_id_block":
			if in.RemoteID.Identified {
				msgs = append(msgs, odid.BasicID{IDType: odid.IDType(in.RemoteID.IDType), UAID: in.RemoteID.UAID})
			}
			op = in.RemoteID.OperatorID
		case "bound":
			ran["bound (skipped)"]++
			t.Skip("an authenticated session binding is the USSP's; the authority holds none (D6)")
		case "serial_conflict":
			ran["serial_conflict (skipped)"]++
			t.Skip("serial_conflict needs authenticated telemetry the authority does not hold (D6, doc.go)")
		default:
			t.Fatalf("kind %q", in.Kind)
		}
		ran[in.Kind]++
		msgs = append(msgs, loc(baseLatDeg, baseLonDeg))
		if op != nil {
			msgs = append(msgs, odid.OperatorID{OperatorID: *op})
		}
		reg := fx.Registry
		if in.RegistryOverride != nil {
			reg = *in.RegistryOverride
		}
		s := DefaultSettings()
		s.Tracker.IdentifyWithinS = rid.IdentifyAtOnceS
		p, rec := pipe(s, Deps{Registry: reg.lookup(t)})
		now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
		observe(t, p, batchOf("rx-1", now, false, rxRow("rx-1", "TEST-ID", frame(t, msgs...), at(now))))
		got := rec.tracks(t)
		if len(got) != 1 {
			t.Fatalf("%d tracks published", len(got))
		}
		id := got[0].Body.Identification
		if string(id.Status) != exp.Status || string(id.Reason) != exp.Reason {
			t.Errorf("%s/%s, want %s/%s", id.Status, id.Reason, exp.Status, exp.Reason)
		}
		vectors.EqualStrPtr(t, "serial", id.Serial, exp.Serial)
		vectors.EqualStrPtr(t, "operator_reg", id.OperatorReg, exp.OperatorReg)
		vectors.EqualStrPtr(t, "registered_operator_reg", id.RegisteredOperatorReg, exp.RegisteredOperatorReg)
		vectors.EqualStrPtr(t, "drone_id", id.RegistryUASID, exp.DroneID)
		if id.Mismatch != exp.Mismatch {
			t.Errorf("mismatch %v, want %v", id.Mismatch, exp.Mismatch)
		}
		if id.Basis != core.BasisAsBroadcast || got[0].Body.Trust != core.TrustBroadcast {
			t.Errorf("basis %s trust %s: a broadcast is never authenticated (R-05)", id.Basis, got[0].Body.Trust)
		}
	})
	if ran["broadcast"] != 29 || ran["remote_id_block"] != 6 {
		t.Errorf("ran %v, want 29 broadcast and 6 remote_id_block", ran)
	}
	t.Logf("identification_status.json through the ingest: %v", ran)
}
