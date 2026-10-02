package picture

import (
	"encoding/json"
	"math"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// trackBody is a track/telemetry/v1 body as it arrives on trk.v1: the
// lab's members (track.Body) and the one member a producer may add that
// the picture shows by realm.
type trackBody struct {
	track.Body
	// OperatorPosition is the remote pilot or operator position a
	// Display Provider flight carries (F3411 operator_location; WP-14
	// produces it). It is shown to the console realm only and omitted
	// for every other realm and any public subset (06 §5).
	OperatorPosition *track.Position `json:"operator_position,omitempty"`
}

// trackIn is a track message as it arrives.
type trackIn struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	Producer   string          `json:"producer"`
	TS         *string         `json:"ts"`
	RxTS       string          `json:"rx_ts"`
	CapturedAt string          `json:"captured_at"`
	TimeSource core.TimeSource `json:"time_source"`
	Backlog    bool            `json:"backlog"`
	Body       trackBody       `json:"body"`
}

// trackOutBody is the body of a track frame: the track as it arrived,
// the operator position by realm, and what the server knows at sending:
// age_s (now - captured_at on this system's clock) and source_state (the
// state of the track's source instance, source/status/v1's).
type trackOutBody struct {
	trackBody
	AgeS        float64 `json:"age_s"`
	SourceState string  `json:"source_state"`
}

type trackOut struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	Producer   string          `json:"producer"`
	TS         *string         `json:"ts"`
	RxTS       string          `json:"rx_ts"`
	CapturedAt string          `json:"captured_at"`
	TimeSource core.TimeSource `json:"time_source"`
	Backlog    bool            `json:"backlog"`
	Body       trackOutBody    `json:"body"`
}

// maxMessageBytes bounds one message taken from the bus; a larger one is
// refused and counted.
const maxMessageBytes = 256 << 10

// decodeTrack reads and validates one trk.v1 message (track.Validate:
// the lab's schema rules and the T11 refusals) and returns it with its
// captured_at and c5 cell. A malformed message is a *core.FieldError and
// never a panic.
func decodeTrack(raw []byte) (*trackIn, time.Time, cell.ID, error) {
	if len(raw) > maxMessageBytes {
		return nil, time.Time{}, cell.ID{}, core.Fieldf("message", "%d bytes, more than %d", len(raw), maxMessageBytes)
	}
	var m trackIn
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, time.Time{}, cell.ID{}, &core.FieldError{Field: "message", Reason: "not a track/telemetry/v1 message"}
	}
	tm := track.Message{
		Schema: m.Schema, MsgID: m.MsgID, Producer: m.Producer, TS: m.TS, RxTS: m.RxTS, CapturedAt: m.CapturedAt,
		TimeSource: m.TimeSource, Backlog: m.Backlog, Body: m.Body.Body,
	}
	if err := tm.Validate(); err != nil {
		return nil, time.Time{}, cell.ID{}, err
	}
	if op := m.Body.OperatorPosition; op != nil {
		if math.IsNaN(op.Lat) || op.Lat < -90 || op.Lat > 90 || math.IsNaN(op.Lng) || op.Lng < -180 || op.Lng > 180 {
			return nil, time.Time{}, cell.ID{}, &core.FieldError{Field: "body.operator_position", Reason: "outside WGS84"}
		}
	}
	captured, err := time.Parse(time.RFC3339Nano, m.CapturedAt)
	if err != nil {
		return nil, time.Time{}, cell.ID{}, &core.FieldError{Field: "captured_at", Reason: "not a time"}
	}
	c5, err := cell.Of(core.LatLon{LatDeg: m.Body.Position.Lat, LonDeg: m.Body.Position.Lng}, cell.Level5)
	if err != nil {
		return nil, time.Time{}, cell.ID{}, &core.FieldError{Field: "body.position", Reason: err.Error()}
	}
	return &m, captured, c5, nil
}

// ageS is now - captured, never negative (a sample from a clock slightly
// ahead is age 0, not a negative age).
func ageS(now, captured time.Time) float64 {
	return math.Max(0, now.Sub(captured).Seconds())
}

// encodeTrack is the frame of m at now: the realm rule applied (the
// operator position for the console realm only), age_s and source_state
// added.
func encodeTrack(m *trackIn, captured, now time.Time, sourceState string, console bool) ([]byte, error) {
	out := trackOut{
		Schema: m.Schema, MsgID: m.MsgID, Producer: m.Producer, TS: m.TS, RxTS: m.RxTS, CapturedAt: m.CapturedAt,
		TimeSource: m.TimeSource, Backlog: m.Backlog,
		Body: trackOutBody{trackBody: m.Body, AgeS: math.Round(ageS(now, captured)*1000) / 1000, SourceState: sourceState},
	}
	if !console {
		out.Body.OperatorPosition = nil
	}
	return json.Marshal(out)
}

// mannedIn is what the picture reads of a track/manned/v1 message: the
// envelope only. The body is the ANSP's schema and is forwarded as
// received (manned-ingest, WP-15, validates it against the ANSP's
// mirror); its cell and icao24 come from the subject
// man.v1.<cell3>.<cell5>.<icao24>.
type mannedIn struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	CapturedAt string          `json:"captured_at"`
	Backlog    bool            `json:"backlog"`
	Body       json.RawMessage `json:"body"`
}

// decodeManned reads one man.v1 message and its subject.
func decodeManned(subject string, raw []byte) (icao24 string, c5 cell.ID, captured time.Time, backlog bool, err error) {
	if len(raw) > maxMessageBytes {
		return "", cell.ID{}, time.Time{}, false, core.Fieldf("message", "%d bytes, more than %d", len(raw), maxMessageBytes)
	}
	parts := strings.Split(subject, ".")
	if len(parts) != 5 || parts[0] != "man" || parts[1] != "v1" {
		return "", cell.ID{}, time.Time{}, false, core.Fieldf("subject", "%q is not man.v1.<cell3>.<cell5>.<icao24>", subject)
	}
	c5, err = cell.ParseToken(parts[3])
	if err != nil || c5.Level != cell.Level5 {
		return "", cell.ID{}, time.Time{}, false, core.Fieldf("subject", "%q is not a c5 cell token", parts[3])
	}
	if _, err := bus.Token("icao24", parts[4]); err != nil {
		return "", cell.ID{}, time.Time{}, false, err
	}
	var m mannedIn
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", cell.ID{}, time.Time{}, false, &core.FieldError{Field: "message", Reason: "not an enveloped message"}
	}
	if m.Schema != SchemaManned {
		return "", cell.ID{}, time.Time{}, false, core.Fieldf("schema", "%q, want %s", m.Schema, SchemaManned)
	}
	if len(m.Body) == 0 || m.Body[0] != '{' {
		return "", cell.ID{}, time.Time{}, false, &core.FieldError{Field: "body", Reason: "not an object"}
	}
	captured, err = time.Parse(time.RFC3339Nano, m.CapturedAt)
	if err != nil {
		return "", cell.ID{}, time.Time{}, false, &core.FieldError{Field: "captured_at", Reason: "not a time"}
	}
	return parts[4], c5, captured, m.Backlog, nil
}
