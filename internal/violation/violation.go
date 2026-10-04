package violation

import (
	"encoding/json"
	"regexp"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// Schema is the envelope's schema name of a violation
// (schemas/violation/v1.json, this repository's: spec 04 §3.3, M14).
const Schema = "violation/v1"

// Producer names detect in the envelope.
const Producer = "authority/detect"

// Kind is a violation kind (spec 04 §3.3). rid_absent is a later
// detector (plan D5, Q-A6).
type Kind string

// The kinds this detector raises (plan D5; no_authorisation WP-26, Q-A5).
const (
	KindHeight120m             Kind = "height_120m"
	KindZoneIncursion          Kind = "zone_incursion"
	KindUnregistered           Kind = "unregistered"
	KindIdentificationMismatch Kind = "identification_mismatch"
	KindNoAuthorisation        Kind = "no_authorisation"
)

// Kinds are the kinds this detector raises.
var Kinds = []Kind{KindHeight120m, KindZoneIncursion, KindUnregistered, KindIdentificationMismatch, KindNoAuthorisation}

// State is where a violation is in its life.
type State string

// The states (spec 04 §3.3 alert/v1 states, which violation/v1 shares).
const (
	StateRaised  State = "raised"
	StateUpdated State = "updated"
	StateCleared State = "cleared"
)

// ClearReasonReconfigured clears a violation the monitor no longer holds
// after it was rebuilt for a new zone set or policy, because the last
// sample of the aircraft, judged under the new configuration, did not
// raise it again (a zone withdrawn, a limit raised). It is not
// "resolved": no hysteresis was observed. The other reasons are
// uspace-core alerting.ClearReason values. A spec gap: 04 §3.3 lists no
// reason for it (WP-12 pull request).
const ClearReasonReconfigured = "reconfigured"

// ClearReasonAuthorised clears a height_120m violation when the aircraft,
// inside a U-space airspace, is matched to an operational intent and the
// policy says height_limit_in_uspace skip_when_authorised (WP-26; spec
// 01 §7: there the authorised volume caps the height, and the USSP's
// conformance monitoring covers it). It is not "resolved": the aircraft
// may still be over 120 m. A spec gap like reconfigured: 04 §3.3 lists
// no reason for it (WP-26 pull request).
const ClearReasonAuthorised = "authorised"

// Peak is the number a violation rested on, at its worst (03 §1
// violations.peak_value): height_agl_m for height_120m.
type Peak struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

// TerrainSource is the DEM the height over the ground was taken from
// (D-05: every AGL number shows its dataset and spacing).
type TerrainSource struct {
	Dataset     string  `json:"dataset"`
	SpacingM    float64 `json:"spacing_m"`
	Attribution string  `json:"attribution"`
}

// EvidenceRef names one piece of evidence: a track, the receiver or
// USSP it came through, or the zone version judged.
type EvidenceRef struct {
	Type    string `json:"type"`
	ID      string `json:"id"`
	Version *int64 `json:"version"`
}

// Evidence reference types.
const (
	RefTrack    = "track"
	RefReceiver = "receiver"
	RefUSSP     = "ussp"
	RefZone     = "zone"
)

// Body is the violation/v1 body. A pointer is null when it does not
// apply to the kind or is not known; nothing unknown is written as a
// number.
type Body struct {
	ViolationID string        `json:"violation_id"`
	Kind        Kind          `json:"kind"`
	State       State         `json:"state"`
	Severity    core.Severity `json:"severity"`
	// AlertKey is the monitor's key of the condition (uspace-core
	// alerting.Alert.Key): one violation per raise of a key.
	AlertKey string `json:"alert_key"`
	// TrackRef is the aircraft's track id (rid.AircraftID).
	TrackRef      string  `json:"track_ref"`
	Serial        *string `json:"serial"`
	OperatorReg   *string `json:"operator_reg"`
	RegistryUASID *string `json:"registry_uas_id"`
	// ZoneID is country/identifier of the zone judged; ZoneVersion its
	// version in force (null for a dynamic restriction).
	ZoneID      *string `json:"zone_id"`
	ZoneVersion *int64  `json:"zone_version"`
	ZoneType    *string `json:"zone_type"`
	// CapturedAt is the triggering sample's placement (02 §1).
	CapturedAt string `json:"captured_at"`
	// OpenedAt is when the condition was first raised and ClosedAt when
	// it cleared, both on the placed clock.
	OpenedAt    string  `json:"opened_at"`
	ClosedAt    *string `json:"closed_at"`
	ClearReason *string `json:"clear_reason"`
	// PolicyVersion is the authority_policy version judged with; 0 is
	// the documented defaults before any policy reached detect.
	PolicyVersion int64 `json:"policy_version"`
	Peak          *Peak `json:"peak"`
	// Detail is the judgement's numbers and flags as uspace-core gave
	// them (vertical_known, limit_not_judged, not_judged, within_band,
	// height_agl_m, max_height_agl_m, restriction, status, ...), at full
	// precision; on a clear, the last numbers that showed it true (C-14).
	Detail map[string]any `json:"detail"`
	// ClearingDetail is the judgement that cleared it, when one did.
	ClearingDetail map[string]any `json:"clearing_detail"`
	TerrainSource  *TerrainSource `json:"terrain_source"`
	// InUSpace is true while the aircraft is inside a U-space airspace
	// (a USPACE zone), whatever height_limit_in_uspace says.
	InUSpace bool `json:"in_uspace"`
	// EvidenceTrust is the trust class of the evidence: broadcast for
	// direct Remote ID (never escalated without a note, 06 §2 T1),
	// provider for network Remote ID.
	EvidenceTrust core.Trust    `json:"evidence_trust"`
	EvidenceRefs  []EvidenceRef `json:"evidence_refs"`
	// EvidenceExcerpt is the track samples copied at detection (the last
	// window before the raise) and, on an update, those since the last
	// publication: the Display Provider cache is gone in 24 h (03 §1).
	EvidenceExcerpt []Sample `json:"evidence_excerpt"`
	// Cell5 is the c5 cell of the triggering sample.
	Cell5 string `json:"cell5"`
}

// Message is a violation with the 04 §2 envelope.
type Message = bus.Envelope[Body]

var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// Validate refuses a message the schema refuses, naming the field.
func Validate(m *Message) error {
	switch {
	case m.Schema != Schema:
		return core.Fieldf("schema", "%q, want %s", m.Schema, Schema)
	case !ulidPattern.MatchString(m.MsgID):
		return core.Fieldf("msg_id", "%q is not a ULID", m.MsgID)
	case !ulidPattern.MatchString(m.Body.ViolationID):
		return core.Fieldf("body.violation_id", "%q is not a ULID", m.Body.ViolationID)
	case m.Body.TrackRef == "":
		return &core.FieldError{Field: "body.track_ref", Reason: "required"}
	case m.Body.AlertKey == "":
		return &core.FieldError{Field: "body.alert_key", Reason: "required"}
	case m.Body.PolicyVersion < 0:
		return &core.FieldError{Field: "body.policy_version", Reason: "negative"}
	}
	known := false
	for _, k := range Kinds {
		known = known || m.Body.Kind == k
	}
	if !known {
		return core.Fieldf("body.kind", "%q is not a violation kind of this detector", m.Body.Kind)
	}
	switch m.Body.State {
	case StateRaised, StateUpdated:
		if m.Body.ClearReason != nil || m.Body.ClosedAt != nil {
			return &core.FieldError{Field: "body.clear_reason", Reason: "only a cleared violation has one"}
		}
	case StateCleared:
		if m.Body.ClearReason == nil || *m.Body.ClearReason == "" || m.Body.ClosedAt == nil {
			return &core.FieldError{Field: "body.clear_reason", Reason: "required when cleared (C-14)"}
		}
	default:
		return core.Fieldf("body.state", "%q is not raised, updated or cleared", m.Body.State)
	}
	switch m.Body.Severity {
	case core.SeverityInfo, core.SeverityWarning, core.SeverityCritical:
	default:
		return core.Fieldf("body.severity", "%q is not a severity", m.Body.Severity)
	}
	return nil
}

// Decode reads a violation message and validates it.
func Decode(raw []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, &core.FieldError{Field: "body", Reason: "not a violation/v1 message"}
	}
	if err := Validate(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Subject is alrt.v1.<kind>.<cell5>.<violation_id>, the cell in its
// subject-token form.
func Subject(b *Body) (string, error) {
	c5, err := cell.Parse(b.Cell5)
	if err != nil {
		return "", &core.FieldError{Field: "body.cell5", Reason: err.Error()}
	}
	return bus.Subjects.Alrt(string(b.Kind), cell.Token(c5), b.ViolationID)
}

// Sample is one track sample as a violation keeps it (evidence_excerpt):
// the times, the position and altitude with their sources, the motion,
// who heard it and the identification it carried. A value the source
// did not give is null.
type Sample struct {
	MsgID          string              `json:"msg_id"`
	CapturedAt     string              `json:"captured_at"`
	RxTS           string              `json:"rx_ts"`
	TS             *string             `json:"ts"`
	TimeSource     core.TimeSource     `json:"time_source"`
	Lat            float64             `json:"lat"`
	Lng            float64             `json:"lng"`
	AltAMSLM       *float64            `json:"alt_amsl_m"`
	AltWGS84M      *float64            `json:"alt_wgs84_m"`
	AltPressureM   *float64            `json:"alt_pressure_m"`
	AltSource      core.AltSource      `json:"alt_source"`
	SpeedMS        *float64            `json:"speed_ms"`
	TrackDeg       *float64            `json:"track_deg"`
	VSpeedMS       *float64            `json:"vspeed_ms"`
	Status         *string             `json:"status"`
	Source         track.Source        `json:"source"`
	SourceInstance string              `json:"source_instance"`
	Trust          core.Trust          `json:"trust"`
	Identification core.Identification `json:"identification"`
}

// SampleOf is m as a violation keeps it.
func SampleOf(m *track.Message) Sample {
	b := &m.Body
	s := Sample{
		MsgID: m.MsgID, CapturedAt: m.CapturedAt, RxTS: m.RxTS, TS: m.TS, TimeSource: m.TimeSource,
		Lat: b.Position.Lat, Lng: b.Position.Lng, AltAMSLM: b.AltAMSLM, AltWGS84M: b.AltWGS84M,
		AltPressureM: b.AltPressureM, AltSource: b.AltSource, SpeedMS: b.SpeedMS, TrackDeg: b.TrackDeg,
		VSpeedMS: b.VSpeedMS, Source: b.Source, SourceInstance: b.SourceInstance, Trust: b.Trust,
		Identification: b.Identification,
	}
	if b.Status != nil {
		st := string(*b.Status)
		s.Status = &st
	}
	return s
}
