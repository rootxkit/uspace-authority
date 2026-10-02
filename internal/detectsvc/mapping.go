package detectsvc

import (
	"math"
	"time"

	"github.com/rootxkit/uspace-core/alerting"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/track"
)

// Counters of the mapping (E-09).
const (
	// CounterStatusAbsent counts tracks without an operational status,
	// mapped as Undeclared: uspace-core f3411 counts Undeclared as
	// airborne, so an aircraft that says nothing is judged, never held as
	// "flying unknown" for ever.
	CounterStatusAbsent = "status_absent_as_undeclared"
	// CounterPressureAltitude counts tracks judged on their pressure
	// altitude (alt_source pressure): uspace-core zones widens the zone
	// limits by the pressure margin and flags vertical_known false (R-09).
	CounterPressureAltitude = "pressure_altitude_judged"
)

// EnvSource resolves the ground and the geoid at a position
// (internal/ground.Service).
type EnvSource interface {
	Env(p core.LatLon) zones.Env
}

// seconds is t as seconds since the Unix epoch, the monitor's time base.
func seconds(t time.Time) float64 {
	return float64(t.UnixNano()) / 1e9
}

// parseStamp reads an envelope time (RFC 3339 UTC); the error names the
// field.
func parseStamp(field, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, core.Fieldf(field, "%q is not a time", s)
	}
	return t, nil
}

// Times are a track message's three clocks.
type Times struct {
	CapturedAt, RxTS time.Time
	TS               *time.Time
}

// TimesOf parses m's envelope times.
func TimesOf(m *track.Message) (Times, error) {
	var t Times
	var err error
	if t.CapturedAt, err = parseStamp("captured_at", m.CapturedAt); err != nil {
		return t, err
	}
	if t.RxTS, err = parseStamp("rx_ts", m.RxTS); err != nil {
		return t, err
	}
	if m.TS != nil {
		ts, err := parseStamp("ts", *m.TS)
		if err != nil {
			return t, err
		}
		t.TS = &ts
	}
	return t, nil
}

// ToTrack maps a validated track message onto the monitor's input, with
// env resolved at its position. Nothing is judged here:
//
//   - ID is the track id (one id, one aircraft: direct and network
//     Remote ID of one serial share it, plan D6).
//   - The altitude: alt_amsl_m with its source (geodetic or network);
//     for alt_source pressure the pressure altitude, which uspace-core
//     judges as indicated and widened by the pressure margin, flagged
//     vertical_known false (R-09); with none, no altitude.
//   - Flying is the operational status through uspace-core f3411
//     (Ground is not flying; Undeclared, Airborne, Emergency and
//     RemoteIDSystemFailure are); a status the source did not give is
//     Undeclared (counted).
//   - Times: CapturedAtS and RxAtS are the envelope's, SourceTS the
//     source's own ts (T-01, T-03); Backlog the envelope's (T-04).
//   - Source and Station are the source type and the instance the
//     ingest authenticated (receiver or USSP), as source control names
//     them (B-11).
//   - Identification is the block the ingest resolved (I-08); Identified
//     says whether it names anyone.
//   - The velocity north, east and down from speed, track and vertical
//     speed (0 when unknown): conflicts are not judged here (plan D5,
//     Config.SkipConflicts), so it is carried for completeness only.
func ToTrack(m *track.Message, t Times, env zones.Env, counters *core.Counters) alerting.Track {
	b := &m.Body
	tr := alerting.Track{
		ID:          b.TrackID,
		Pos:         core.LatLon{LatDeg: b.Position.Lat, LonDeg: b.Position.Lng},
		AltSource:   b.AltSource,
		CapturedAtS: seconds(t.CapturedAt),
		RxAtS:       seconds(t.RxTS),
		Backlog:     m.Backlog,
		Source:      string(b.Source),
		Station:     b.SourceInstance,
		Env:         env,
	}
	switch b.AltSource {
	case core.AltPressure:
		if b.AltPressureM != nil {
			v := *b.AltPressureM
			tr.AltAMSLM = &v
			counters.Inc(CounterPressureAltitude)
		}
	case core.AltNone:
	case core.AltGeodetic, core.AltNetwork:
		if b.AltAMSLM != nil {
			v := *b.AltAMSLM
			tr.AltAMSLM = &v
		}
	}
	status := f3411.Undeclared
	if b.Status != nil {
		status = *b.Status
	} else {
		counters.Inc(CounterStatusAbsent)
	}
	flying := status.Airborne()
	tr.Flying = &flying
	if t.TS != nil {
		ts := seconds(*t.TS)
		tr.SourceTS = &ts
	}
	ident := b.Identification
	tr.Identification = &ident
	identified := ident.Status != core.IdentUnidentified
	tr.Identified = &identified
	if b.SpeedMS != nil && b.TrackDeg != nil {
		rad := *b.TrackDeg * math.Pi / 180
		tr.VNMS = *b.SpeedMS * math.Cos(rad)
		tr.VEMS = *b.SpeedMS * math.Sin(rad)
	}
	if b.VSpeedMS != nil {
		tr.VDMS = -*b.VSpeedMS
	}
	return tr
}
