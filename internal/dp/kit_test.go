package dp

import (
	"time"

	"github.com/rootxkit/uspace-core/f3411"
)

// The fixtures use TEST serials (CLAUDE.md rule 11): TESTA0000000001 is
// a CTA-2063-A serial (manufacturer code TEST, length code A = 10).
const (
	spBase     = "https://sp.example.test"
	ctaSerial  = "TESTA0000000001"
	baseLatDeg = 41.7151
	baseLonDeg = 44.8271
)

func f32(v float32) *float32 { return &v }
func f64(v float64) *float64 { return &v }
func str(v string) *string   { return &v }

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// state is a current state at ts and the position.
func state(ts time.Time, lat, lon float64) *f3411.RIDAircraftState {
	st := f3411.Airborne
	return &f3411.RIDAircraftState{
		Timestamp:         f3411.Time{Format: f3411.RFC3339, Value: ts},
		TimestampAccuracy: 0.1,
		Position:          f3411.RIDAircraftPosition{Lat: f64(lat), Lng: f64(lon), Alt: f32(600)},
		Speed:             f32(5), Track: f32(90), VerticalSpeed: f32(0.5), SpeedAccuracy: f3411.SA1mps,
		OperationalStatus: &st,
	}
}

// flight is a RIDFlight with a current state.
func flight(id string, st *f3411.RIDAircraftState) f3411.RIDFlight {
	return f3411.RIDFlight{Id: id, AircraftType: f3411.Helicopter, CurrentState: st}
}

// details are a flight's details with a serial and an operator id.
func details(id, sn, operator string) *f3411.RIDFlightDetails {
	d := &f3411.RIDFlightDetails{Id: id, UasId: &f3411.UASID{SerialNumber: str(sn)}}
	if operator != "" {
		d.OperatorId = str(operator)
	}
	return d
}

// box2km is a box of about 1.4 km diagonal around the base, box7km one
// of about 5.5 km (above the details diagonal, under the display one).
var (
	box2km = Box{MinLat: baseLatDeg - 0.005, MinLon: baseLonDeg - 0.006, MaxLat: baseLatDeg + 0.005, MaxLon: baseLonDeg + 0.006}
	box7km = Box{MinLat: baseLatDeg - 0.02, MinLon: baseLonDeg - 0.025, MaxLat: baseLatDeg + 0.02, MaxLon: baseLonDeg + 0.025}
)

// isa is an ISA of owner at base, in force around t0.
func isa(id, owner, base string) f3411.IdentificationServiceArea {
	return f3411.IdentificationServiceArea{
		Id: id, Owner: owner, UssBaseUrl: base, Version: "v1",
		TimeStart: f3411.Time{Format: f3411.RFC3339, Value: t0.Add(-time.Hour)},
		TimeEnd:   f3411.Time{Format: f3411.RFC3339, Value: t0.Add(time.Hour)},
	}
}
