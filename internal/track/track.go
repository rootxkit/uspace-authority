package track

import (
	"encoding/json"
	"math"
	"regexp"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
)

// Schema is the envelope's schema name of a track message.
const Schema = "track/telemetry/v1"

// Source is the adapter type of a track (04 §2, the envelope's closed
// enumeration).
type Source string

// Sources (04 §2).
const (
	SourceOperatorWS Source = "operator_ws"
	SourceNetworkRID Source = "network_rid"
	SourceDirectRID  Source = "direct_rid"
	SourceANSPFeed   Source = "ansp_feed"
	SourceADSBRx     Source = "adsb_rx"
	// SourceSITL is lab only; Validate refuses it (spec 06 T11).
	SourceSITL Source = "sitl"
)

// Position is WGS84 decimal degrees (02 §1); the member names are the
// schema's.
type Position struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

// Body is the track/telemetry/v1 body (04 §3.1). Every pointer is null
// when the source did not give the value (R-01, R-10); nothing unknown
// is written as a number.
type Body struct {
	TrackID        string     `json:"track_id"`
	Trust          core.Trust `json:"trust"`
	Source         Source     `json:"source"`
	SourceInstance string     `json:"source_instance"`
	Position       Position   `json:"position"`
	// AltWGS84M is the geodetic altitude above the WGS84 ellipsoid (HAE)
	// as the source gave it.
	AltWGS84M *float64 `json:"alt_wgs84_m"`
	// AltAMSLM is the orthometric altitude: HAE minus the geoid
	// undulation (alt_source geodetic) or, for network Remote ID, the
	// provider's (network). Never a pressure altitude (R-08).
	AltAMSLM  *float64       `json:"alt_amsl_m"`
	AltSource core.AltSource `json:"alt_source"`
	// AltPressureM is the pressure altitude, ISA 1013.25 hPa, as
	// broadcast; not AMSL (R-08).
	AltPressureM *float64 `json:"alt_pressure_m"`
	HeightM      *float64 `json:"height_m"`
	// HeightRef is set exactly when HeightM is (R-12).
	HeightRef *f3411.RIDHeightReference `json:"height_ref"`
	SpeedMS   *float64                  `json:"speed_ms"`
	TrackDeg  *float64                  `json:"track_deg"`
	// VSpeedMS is positive up.
	VSpeedMS       *float64                    `json:"vspeed_ms"`
	AccuracyHM     *float64                    `json:"accuracy_h_m"`
	AccuracyVM     *float64                    `json:"accuracy_v_m"`
	Status         *f3411.RIDOperationalStatus `json:"status"`
	Emergency      bool                        `json:"emergency"`
	Identification core.Identification         `json:"identification"`
	FlightID       *string                     `json:"flight_id"`
	IntentID       *string                     `json:"intent_id"`
	// Cell is the c5 cell name (c5:<lat_idx>:<lon_idx>) of the position.
	Cell string `json:"cell,omitempty"`
}

// Message is a track with the 04 §2 envelope. TS is null when the source
// carried no time of its own (T-12).
type Message struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	Producer   string          `json:"producer"`
	TS         *string         `json:"ts"`
	RxTS       string          `json:"rx_ts"`
	CapturedAt string          `json:"captured_at"`
	TimeSource core.TimeSource `json:"time_source"`
	Backlog    bool            `json:"backlog"`
	Body       Body            `json:"body"`
}

// New wraps body in the envelope for producer at the times t: msg_id is
// a new ULID stamped with t.RxTS, and the cell is filled from the
// position when it is empty.
func New(producer string, t core.Times, body Body) (*Message, error) {
	m := &Message{
		Schema: Schema, MsgID: bus.NewULID(t.RxTS), Producer: producer, RxTS: bus.Stamp(t.RxTS),
		CapturedAt: bus.Stamp(t.CapturedAt), TimeSource: t.Source, Backlog: t.Backlog, Body: body,
	}
	if t.TS != nil {
		s := bus.Stamp(*t.TS)
		m.TS = &s
	}
	if m.Body.Cell == "" {
		c5, err := cell.Of(core.LatLon{LatDeg: body.Position.Lat, LonDeg: body.Position.Lng}, cell.Level5)
		if err != nil {
			return nil, err
		}
		m.Body.Cell = c5.String()
	}
	return m, nil
}

// Marshal is the message's wire form.
func (m *Message) Marshal() ([]byte, error) { return json.Marshal(m) }

// Patterns of the envelope (uspace-lab envelope/v1).
var (
	ulidPattern     = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	producerPattern = regexp.MustCompile(`^(authority|cisp|ussp|ansp|lab)(/[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*|-[0-9]+/[a-z][a-z0-9]*(-[a-z][a-z0-9]*)*-[0-9]+)$`)
	stampPattern    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
	cellPattern     = regexp.MustCompile(`^c5:(0|[1-9][0-9]{0,2}|1[0-7][0-9]{2}):(0|[1-9][0-9]{0,2}|[12][0-9]{3}|3[0-5][0-9]{2})$`)
)

func stamp(field, s string) error {
	if !stampPattern.MatchString(s) {
		return core.Fieldf(field, "%q is not RFC 3339 UTC with milliseconds and Z", s)
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
		return core.Fieldf(field, "%q is not a time", s)
	}
	return nil
}

func finite(field string, v *float64) error {
	if v != nil && (math.IsNaN(*v) || math.IsInf(*v, 0)) {
		return &core.FieldError{Field: field, Reason: "not a finite number"}
	}
	return nil
}

func nonNegative(field string, v *float64) error {
	if err := finite(field, v); err != nil {
		return err
	}
	if v != nil && *v < 0 {
		return &core.FieldError{Field: field, Reason: "negative"}
	}
	return nil
}

// Validate refuses a message the schema refuses, naming the first field
// at fault, and refuses trust "simulated" and source "sitl" (spec 06
// T11: production ingest never accepts them).
func (m *Message) Validate() error {
	switch {
	case m.Schema != Schema:
		return core.Fieldf("schema", "%q, want %s", m.Schema, Schema)
	case !ulidPattern.MatchString(m.MsgID):
		return core.Fieldf("msg_id", "%q is not a ULID", m.MsgID)
	case !producerPattern.MatchString(m.Producer):
		return core.Fieldf("producer", "%q is not <system>/<process>", m.Producer)
	}
	if m.TS != nil {
		if err := stamp("ts", *m.TS); err != nil {
			return err
		}
	}
	if err := stamp("rx_ts", m.RxTS); err != nil {
		return err
	}
	if err := stamp("captured_at", m.CapturedAt); err != nil {
		return err
	}
	switch m.TimeSource {
	case core.TimeSourceClock, core.TimeBroadcast, core.TimeReceiver, core.TimeProvider, core.TimeSystem:
	default:
		return core.Fieldf("time_source", "%q is not a time source", m.TimeSource)
	}
	return m.Body.validate()
}

func (b *Body) validate() error {
	switch {
	case b.TrackID == "":
		return &core.FieldError{Field: "body.track_id", Reason: "required"}
	case b.SourceInstance == "":
		return &core.FieldError{Field: "body.source_instance", Reason: "required"}
	}
	switch b.Trust {
	case core.TrustAuthenticated, core.TrustProvider, core.TrustSurveillance, core.TrustBroadcast, core.TrustSensor:
	case core.TrustSimulated:
		return &core.FieldError{Field: "body.trust", Reason: "simulated is lab only and refused in production (06 T11)"}
	default:
		return core.Fieldf("body.trust", "%q is not a trust class", b.Trust)
	}
	switch b.Source {
	case SourceOperatorWS, SourceNetworkRID, SourceDirectRID, SourceANSPFeed, SourceADSBRx:
	case SourceSITL:
		return &core.FieldError{Field: "body.source", Reason: "sitl is lab only and refused in production (06 T11)"}
	default:
		return core.Fieldf("body.source", "%q is not a source", b.Source)
	}
	p := b.Position
	if math.IsNaN(p.Lat) || p.Lat < -90 || p.Lat > 90 {
		return &core.FieldError{Field: "body.position.lat", Reason: "outside [-90, 90]"}
	}
	if math.IsNaN(p.Lng) || p.Lng < -180 || p.Lng > 180 {
		return &core.FieldError{Field: "body.position.lng", Reason: "outside [-180, 180]"}
	}
	for _, f := range []struct {
		name string
		v    *float64
	}{{"body.alt_wgs84_m", b.AltWGS84M}, {"body.alt_amsl_m", b.AltAMSLM}, {"body.alt_pressure_m", b.AltPressureM},
		{"body.height_m", b.HeightM}, {"body.vspeed_ms", b.VSpeedMS}} {
		if err := finite(f.name, f.v); err != nil {
			return err
		}
	}
	for _, f := range []struct {
		name string
		v    *float64
	}{{"body.speed_ms", b.SpeedMS}, {"body.accuracy_h_m", b.AccuracyHM}, {"body.accuracy_v_m", b.AccuracyVM}} {
		if err := nonNegative(f.name, f.v); err != nil {
			return err
		}
	}
	switch b.AltSource {
	case core.AltGeodetic, core.AltPressure, core.AltNetwork, core.AltNone:
	default:
		return core.Fieldf("body.alt_source", "%q is not an altitude source", b.AltSource)
	}
	if b.HeightRef != nil && !b.HeightRef.Valid() {
		return core.Fieldf("body.height_ref", "%q is not a height reference", *b.HeightRef)
	}
	if b.HeightM != nil && b.HeightRef == nil {
		return &core.FieldError{Field: "body.height_ref", Reason: "required with height_m (R-12)"}
	}
	if b.TrackDeg != nil && (math.IsNaN(*b.TrackDeg) || *b.TrackDeg < 0 || *b.TrackDeg >= 360) {
		return &core.FieldError{Field: "body.track_deg", Reason: "outside [0, 360)"}
	}
	if b.Status != nil && !b.Status.Valid() {
		return core.Fieldf("body.status", "%q is not an operational status", *b.Status)
	}
	if b.Cell != "" && !cellPattern.MatchString(b.Cell) {
		return core.Fieldf("body.cell", "%q is not a c5 cell name", b.Cell)
	}
	return validateIdentification("body.identification", &b.Identification)
}

func validateIdentification(at string, id *core.Identification) error {
	switch id.Status {
	case core.IdentRegistered, core.IdentSuspended, core.IdentUnknownOperator, core.IdentUnidentified:
	default:
		return core.Fieldf(at+".status", "%q is not an identification status", id.Status)
	}
	switch id.Reason {
	case core.ReasonMatched, core.ReasonSessionBinding, core.ReasonUASSuspended, core.ReasonUASRevoked,
		core.ReasonOperatorSuspended, core.ReasonOperatorRevoked, core.ReasonSerialUnknown, core.ReasonNotASerial,
		core.ReasonOperatorAbsent, core.ReasonOperatorMismatch, core.ReasonOwnerUnknown, core.ReasonNotInRegistry,
		core.ReasonSerialConflict, core.ReasonNoSerial, core.ReasonRegistryUnavailable:
	default:
		return core.Fieldf(at+".reason", "%q is not an identification reason", id.Reason)
	}
	switch id.Basis {
	case core.BasisAuthenticated, core.BasisAsBroadcast, core.BasisProvider:
	default:
		return core.Fieldf(at+".basis", "%q is not an identification basis", id.Basis)
	}
	if id.Reason == core.ReasonSerialConflict && !id.Mismatch {
		return &core.FieldError{Field: at + ".mismatch", Reason: "must be true for serial_conflict (04 §3.2)"}
	}
	return nil
}

// Subject is trk.v1.<cell3>.<cell5>.<track_id>; the cells are subject
// tokens (internal/cell.Token).
func Subject(cell3, cell5, trackID string) (string, error) {
	return bus.Subjects.Trk(cell3, cell5, trackID)
}

// SubjectOf is the subject of m, from its position.
func SubjectOf(m *Message) (string, error) {
	c3, c5, err := cell.Tokens(core.LatLon{LatDeg: m.Body.Position.Lat, LonDeg: m.Body.Position.Lng})
	if err != nil {
		return "", err
	}
	return Subject(c3, c5, m.Body.TrackID)
}

// Publish validates m and sends it on its subject over core NATS. A
// message that does not validate is not sent; the error names the field.
func Publish(p bus.Publisher, m *Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	subject, err := SubjectOf(m)
	if err != nil {
		return err
	}
	data, err := m.Marshal()
	if err != nil {
		return err
	}
	return p.Publish(subject, data)
}
