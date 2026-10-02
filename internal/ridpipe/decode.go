package ridpipe

import (
	"errors"
	"math"
	"strings"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/timeplace"
)

// statusName is the F3411 name of an ODID operational status (04 §3.1:
// the uas_standards RIDOperationalStatus spelling); nil for a value the
// frozen odid types do not name.
func statusName(s odid.Status) *f3411.RIDOperationalStatus {
	var v f3411.RIDOperationalStatus
	switch s {
	case odid.StatusUndeclared:
		v = f3411.Undeclared
	case odid.StatusGround:
		v = f3411.Ground
	case odid.StatusAirborne:
		v = f3411.Airborne
	case odid.StatusEmergency:
		v = f3411.Emergency
	case odid.StatusRemoteIDSystemFailure:
		v = f3411.RemoteIDSystemFailure
	default:
		return nil
	}
	return &v
}

// heightRef is the F3411 name of a height reference (R-12).
func heightRef(r odid.HeightReference) *f3411.RIDHeightReference {
	var v f3411.RIDHeightReference
	switch r {
	case odid.HeightOverTakeoff:
		v = f3411.TakeoffLocation
	case odid.HeightOverGround:
		v = f3411.GroundLevel
	default:
		return nil
	}
	return &v
}

// timestampTenths is the wire form of a Location's broadcast time that
// timeplace.PlaceBroadcast takes: odid decodes the tenths after the hour
// to seconds (SecondsAfterHour = tenths / 10) and the unknown 0xFFFF to
// nil; this is the inverse, exact for every 16-bit value.
func timestampTenths(loc *odid.Location) uint16 {
	if loc.SecondsAfterHour == nil {
		return timeplace.TimestampUnknown
	}
	t := math.Round(*loc.SecondsAfterHour * 10)
	if t < 0 || t >= float64(timeplace.TimestampUnknown) {
		return timeplace.TimestampUnknown
	}
	return uint16(t)
}

// decoded is what one row's frame said.
type decoded struct {
	messages []odid.Message
	location *odid.Location
}

// decodeFrame decodes a row's payload with uspace-core odid (R-01..R-04:
// Self-ID, Authentication and undefined types are dropped by the
// decoder; a malformed pack is refused whole) and fills the row's
// decoded columns from what it holds.
func decodeFrame(r *Row) (decoded, error) {
	msgs, err := odid.Decode(r.Payload, odid.DecodeOptions{})
	if err != nil {
		return decoded{}, err
	}
	d := decoded{messages: msgs}
	var firstType *int
	for _, m := range msgs {
		switch v := m.(type) {
		case odid.BasicID:
			t := int(v.IDType)
			if firstType == nil {
				firstType = &t
			}
			if v.IDType == odid.IDTypeSerial && v.UAID != "" {
				ua := v.UAID
				r.Serial, r.IDType = &ua, &t
			}
		case odid.OperatorID:
			op := v.OperatorID
			if op != "" {
				r.OperatorReg = &op
			}
		case odid.Location:
			loc := v
			d.location = &loc
			r.LatDeg, r.LonDeg = loc.LatDeg, loc.LonDeg
			r.AltWGS84M, r.AltPressureM = loc.AltHAEM, loc.AltBaroM
			r.HeightM = loc.HeightM
			if loc.HeightM != nil {
				if ref := heightRef(loc.HeightReference); ref != nil {
					s := string(*ref)
					r.HeightRef = &s
				}
			}
			r.SpeedMS, r.TrackDeg, r.VSpeedMS = loc.SpeedHorizontalMS, loc.DirectionDeg, loc.SpeedVerticalMS
			if st := statusName(loc.Status); st != nil {
				s := string(*st)
				r.Status = &s
			}
		}
	}
	if r.IDType == nil {
		r.IDType = firstType
	}
	return d, nil
}

// maxRefusalKinds bounds the per-phrase refusal counters (E-10): a
// phrase past it is counted under decode_refused_other.
const maxRefusalKinds = 64

// refusalKey is the stable form of a decoder refusal: its field and
// reason with every number replaced by "n", so "pack of 12 messages"
// and "pack of 10 messages" are one kind, as snake case.
func refusalKey(err error) string {
	phrase := err.Error()
	var fe *core.FieldError
	if errors.As(err, &fe) {
		phrase = fe.Field + " " + fe.Reason
	}
	var b strings.Builder
	digits := false
	underscore := true
	for _, r := range strings.ToLower(phrase) {
		switch {
		case r >= '0' && r <= '9':
			if !digits {
				if !underscore {
					b.WriteByte('_')
				}
				b.WriteByte('n')
				underscore = false
			}
			digits = true
			continue
		case r >= 'a' && r <= 'z':
			if digits {
				b.WriteByte('_')
			}
			b.WriteRune(r)
			underscore = false
		default:
			if !underscore {
				b.WriteByte('_')
				underscore = true
			}
		}
		digits = false
	}
	s := strings.Trim(b.String(), "_")
	const maxLen = 64
	if len(s) > maxLen {
		s = strings.TrimRight(s[:maxLen], "_")
	}
	return s
}
