package dp

import (
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"
	"github.com/rootxkit/uspace-core/serial"
	"github.com/rootxkit/uspace-core/timeplace"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// Producer names dp-poller in every envelope (04 §2).
const Producer = "authority/dp-poller"

// Outcomes of Map that publish nothing, each a counter (E-09).
const (
	CounterStateAbsent  = "flight_without_current_state"
	CounterNoPosition   = "flight_without_position"
	CounterStateTooOld  = "state_older_than_max_age" // timeplace shown=false (T-02)
	CounterTrackInvalid = "track_invalid"
)

// Counters of a published state's placement and altitude.
const (
	CounterPlacedOwnTime    = "placed_at_state_time"
	CounterPlacedAtReceipt  = "placed_at_receipt_" // plus the timeplace.NetworkNote
	CounterAltGeodetic      = "alt_geodetic"
	CounterAltPressure      = "alt_pressure"
	CounterAltNone          = "alt_none"
	CounterAltNoGeoid       = "alt_amsl_unavailable_no_geoid"
	CounterGeoidFailed      = "geoid_failed"
	CounterRegistryNotReady = "identification_registry_unavailable"
	CounterSerialNotCTA     = "serial_not_cta"
)

// Input is one flight as a Service Provider served it, with what the
// Display Provider knows of where it came from.
type Input struct {
	// USSID is the Service Provider's id: the owner of the ISA that
	// named its uss_base_url (the client id the DSS knows it by).
	USSID string
	// ISAID is that ISA.
	ISAID string
	// Flight is the flight as received (validated by core's reader).
	Flight *f3411.RIDFlight
	// Details are the flight's details when fetched, nil otherwise.
	Details *f3411.RIDFlightDetails
	// ResponseTS is the response's timestamp (nil when absent), RxTS when
	// the response was received on this system's clock.
	ResponseTS *time.Time
	RxTS       time.Time
}

// Mapped is a flight state ready to publish.
type Mapped struct {
	Message *Message
	Times   core.Times
	// Airborne is the state's operational status read by core's rule
	// (R-11).
	Airborne bool
}

// MapDeps are what Map judges with.
type MapDeps struct {
	// Registry is the registry projection (nil before it loads, read as
	// registry_unavailable).
	Registry identify.Lookup
	// Geoid converts HAE to AMSL; nil means none (R-07).
	Geoid geoid.Undulator
	// Network is timeplace.NetworkPolicy (MaxAgeS 60).
	Network timeplace.NetworkPolicy
	// Counters receive Map's counters.
	Counters *core.Counters
}

// TrackID is the flight's track id (D6, I-05, I-06): rid.AircraftID of
// the serial, ID type 1, when the details carry a serial number that is
// a CTA-2063-A serial, so the network flight and the direct broadcast of
// the same serial are one track (SC-06 row 3); otherwise
// rid.UnidentifiedID of the F3411 flight id.
func TrackID(flightID string, d *f3411.RIDFlightDetails) (string, bool) {
	if sn := SerialOf(d); sn != nil && serial.ValidateCTA2063A(*sn) == nil {
		return rid.AircraftID(odid.IDTypeSerial, *sn), true
	}
	return rid.UnidentifiedID(flightID), false
}

// SerialOf is the details' uas_id.serial_number, trimmed; nil when
// absent or blank.
func SerialOf(d *f3411.RIDFlightDetails) *string {
	if d == nil || d.UasId == nil || d.UasId.SerialNumber == nil {
		return nil
	}
	s := strings.TrimSpace(*d.UasId.SerialNumber)
	if s == "" {
		return nil
	}
	return &s
}

// OperatorIDOf is the details' operator_id, trimmed; nil when absent or
// blank.
func OperatorIDOf(d *f3411.RIDFlightDetails) *string {
	if d == nil || d.OperatorId == nil {
		return nil
	}
	s := strings.TrimSpace(*d.OperatorId)
	if s == "" {
		return nil
	}
	return &s
}

// Identify resolves the details against the registry on the provider
// basis: identify.ResolveBroadcast over the serial and the operator id
// (G-01, G-02, G-05), the basis set to core.BasisProvider (Q-A8: a
// provider's claim, neither authenticated nor heard by a receiver).
func Identify(reg identify.Lookup, d *f3411.RIDFlightDetails) core.Identification {
	id := identify.ResolveBroadcast(reg, SerialOf(d), OperatorIDOf(d))
	id.Basis = core.BasisProvider
	return id
}

// Place is the state's placement on this system's clock
// (timeplace.PlaceNetwork against the response timestamp, T-02): shown
// is false for a state older than MaxAgeS, which is not published.
func Place(st *f3411.RIDAircraftState, in *Input, pol timeplace.NetworkPolicy) (timeplace.Placement, timeplace.NetworkNote, bool) {
	return timeplace.PlaceNetwork(st.Timestamp.Value, in.ResponseTS, in.RxTS, pol)
}

// Map maps one flight onto track/telemetry/v1 (04 §3.1): trust provider,
// source network_rid, source_instance the Service Provider, the special
// values as null (core's accessors), AMSL from HAE through the geoid
// (rid.SelectAltitude), the pressure altitude kept apart, the height
// with its reference, the identification on the provider basis and the
// operator position as received (shown to the console realm only,
// WP-13). It returns false, counted, for a flight without a current
// state or a position and for a state older than MaxAgeS.
func Map(in *Input, d MapDeps) (*Mapped, bool) {
	cnt := d.Counters
	if cnt == nil {
		cnt = &core.Counters{}
	}
	f := in.Flight
	if f == nil || f.CurrentState == nil {
		cnt.Inc(CounterStateAbsent)
		return nil, false
	}
	st := f.CurrentState
	pos := st.Position.LatLon()
	if !pos.Valid() {
		cnt.Inc(CounterNoPosition)
		return nil, false
	}
	pl, note, shown := Place(st, in, d.Network)
	if !shown {
		cnt.Inc(CounterStateTooOld)
		return nil, false
	}
	if note == timeplace.NoteNone {
		cnt.Inc(CounterPlacedOwnTime)
	} else {
		cnt.Inc(CounterPlacedAtReceipt + string(note))
	}
	times := timeplace.Times(pl, in.RxTS, false)

	trackID, ctaSerial := TrackID(f.Id, in.Details)
	if SerialOf(in.Details) != nil && !ctaSerial {
		cnt.Inc(CounterSerialNotCTA)
	}
	body := track.Body{
		TrackID: trackID, Trust: core.TrustProvider, Source: track.SourceNetworkRID, SourceInstance: in.USSID,
		Position: track.Position{Lat: pos.LatDeg, Lng: pos.LonDeg}, AltWGS84M: st.Position.AltHAEM(),
		AltPressureM: st.Position.PressureAltM(), SpeedMS: st.SpeedMS(), TrackDeg: st.TrackDeg(),
		VSpeedMS: st.VerticalSpeedMS(), FlightID: strPtr(f.Id),
	}
	if h := st.Position.Height; h != nil {
		if v := h.DistanceM(); v != nil && h.Reference.Valid() {
			ref := h.Reference
			body.HeightM, body.HeightRef = v, &ref
		}
	}
	if s := st.OperationalStatus; s != nil && s.Valid() {
		status := *s
		body.Status = &status
		body.Emergency = status == f3411.Emergency
	}
	altitude(&body, pos, d, cnt)
	body.Identification = Identify(d.Registry, in.Details)
	if body.Identification.Reason == core.ReasonRegistryUnavailable {
		cnt.Inc(CounterRegistryNotReady)
	}
	m, err := track.New(Producer, times, body)
	if err != nil {
		cnt.Inc(CounterTrackInvalid)
		return nil, false
	}
	out := &Message{Message: *m}
	if dd := in.Details; dd != nil && dd.OperatorLocation != nil {
		p := dd.OperatorLocation.Position.LatLon()
		out.OperatorPosition = &track.Position{Lat: p.LatDeg, Lng: p.LonDeg}
	}
	if err := out.Validate(); err != nil {
		cnt.Inc(CounterTrackInvalid)
		return nil, false
	}
	return &Mapped{Message: out, Times: times, Airborne: st.Airborne()}, true
}

// altitude fills the AMSL altitude through core's rule (R-07, R-08): the
// geodetic altitude is HAE minus the undulation; with no usable geodetic
// altitude the pressure altitude stands in as alt_source pressure and is
// never written to alt_amsl_m; without a geoid there is no AMSL
// altitude. The F3411 vertical accuracy is not mapped to an ODID code
// (no table in uspace-core; E-03): it is unknown, which SelectAltitude
// reads as usable.
func altitude(b *track.Body, pos core.LatLon, d MapDeps, cnt *core.Counters) {
	in := rid.AltInput{AltHAEM: b.AltWGS84M, AltPressureM: b.AltPressureM}
	if d.Geoid != nil {
		n, err := d.Geoid.UndulationM(pos)
		if err != nil {
			cnt.Inc(CounterGeoidFailed)
		} else {
			in.UndulationM = &n
		}
	}
	res := rid.SelectAltitude(in, rid.DefaultAltPolicy())
	b.AltSource = res.Source
	switch res.Source {
	case core.AltGeodetic:
		cnt.Inc(CounterAltGeodetic)
		b.AltAMSLM = res.AltAMSLM
	case core.AltPressure:
		cnt.Inc(CounterAltPressure)
	case core.AltNone, core.AltNetwork:
		cnt.Inc(CounterAltNone)
		if d.Geoid == nil && b.AltWGS84M != nil {
			cnt.Inc(CounterAltNoGeoid)
		}
	}
}

func strPtr(s string) *string { return &s }

// Message is track/telemetry/v1 as dp-poller publishes it: the lab's
// members (track.Message) and the one member a producer may add, the
// remote pilot or operator position of a Display Provider flight
// (F3411 operator_location), personal data that picture-ws shows to the
// console realm only (WP-13, 06 §5).
type Message struct {
	track.Message
	OperatorPosition *track.Position `json:"-"`
}

// wireBody is the body on the wire: track.Body and operator_position.
type wireBody struct {
	track.Body
	OperatorPosition *track.Position `json:"operator_position,omitempty"`
}

type wireMessage struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	Producer   string          `json:"producer"`
	TS         *string         `json:"ts"`
	RxTS       string          `json:"rx_ts"`
	CapturedAt string          `json:"captured_at"`
	TimeSource core.TimeSource `json:"time_source"`
	Backlog    bool            `json:"backlog"`
	Body       wireBody        `json:"body"`
}

// Validate is track's schema check plus the operator position's range.
func (m *Message) Validate() error {
	if err := m.Message.Validate(); err != nil {
		return err
	}
	if op := m.OperatorPosition; op != nil {
		if math.IsNaN(op.Lat) || op.Lat < -90 || op.Lat > 90 || math.IsNaN(op.Lng) || op.Lng < -180 || op.Lng > 180 {
			return &core.FieldError{Field: "body.operator_position", Reason: "outside WGS84"}
		}
	}
	return nil
}

// Marshal is the message's wire form.
func (m *Message) Marshal() ([]byte, error) {
	t := m.Message
	return json.Marshal(wireMessage{
		Schema: t.Schema, MsgID: t.MsgID, Producer: t.Producer, TS: t.TS, RxTS: t.RxTS, CapturedAt: t.CapturedAt,
		TimeSource: t.TimeSource, Backlog: t.Backlog, Body: wireBody{Body: t.Body, OperatorPosition: m.OperatorPosition},
	})
}

// Publish validates m and sends it on trk.v1.<cell3>.<cell5>.<track_id>.
func (m *Message) Publish(p bus.Publisher) error {
	if err := m.Validate(); err != nil {
		return err
	}
	subject, err := track.SubjectOf(&m.Message)
	if err != nil {
		return err
	}
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	return p.Publish(subject, data)
}
