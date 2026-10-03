package manned

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/rootxkit/uspace-core/core"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-authority/api/clients"
)

// The schemas of the frames the ANSP's stream carries (its
// api/openapi.yaml MannedStreamFrame, M12, M29) and of what this
// process publishes.
const (
	SchemaTrack    = "track/manned/v1"
	SchemaStatus   = "console/status/v1"
	SchemaSnapshot = "console/snapshot/v1"
	// SchemaSource is the status this process publishes on src.v1.
	SchemaSource = "source/status/v1"
	// Producer names this process in every envelope it writes.
	Producer = "authority/manned-ingest"
	// SourceType is the adapter type (04 §2) and the source-control type
	// of the feed and of every ANSP adapter (WP-10).
	SourceType = "ansp_feed"
	// Scope is the ecosystem scope of the stream and the snapshot (WP-2
	// table B, 06 §3).
	Scope = "ansp.traffic"
)

// The paths of the ANSP's api/openapi.yaml this process calls.
const (
	PathStream   = "/v1/manned-traffic/stream"
	PathSnapshot = "/v1/manned-traffic/snapshot"
)

// The states of a manned aircraft (track/manned/v1 body.state).
const (
	StateLive           = "live"
	StateStale          = "stale"
	StateSourceDisabled = "source_disabled"
)

// stateRank orders the states an aircraft ages through: a sample only
// ages forward (live, stale, source_disabled); a newer sample starts
// again from its own state.
func stateRank(s string) int {
	switch s {
	case StateLive:
		return 0
	case StateStale:
		return 1
	case StateSourceDisabled:
		return 2
	}
	return -1
}

// Position is body.position (WGS84 decimal degrees).
type Position struct {
	Lat float64 `json:"lat"`
	Lng float64 `json:"lng"`
}

// Body is the body of track/manned/v1, member for member the ANSP's
// schema (uspace-ansp schemas/track/manned/v1.json, pinned in
// api/clients/ansp-schemas; TestBodyMembersAreTheSchemas holds them
// equal). alt_pressure_m is pressure altitude (ISA 1013.25 hPa), never
// AMSL; alt_wgs84_m is the geometric altitude above the ellipsoid when
// the source gave one (D-03). Optional members the ANSP left out stay
// out.
type Body struct {
	ICAO24         string          `json:"icao24"`
	Callsign       *string         `json:"callsign"`
	Position       Position        `json:"position"`
	AltPressureM   *float64        `json:"alt_pressure_m"`
	AltWGS84M      *float64        `json:"alt_wgs84_m"`
	GSMS           *float64        `json:"gs_ms"`
	TrackDeg       *float64        `json:"track_deg"`
	VRateMS        *float64        `json:"vrate_ms"`
	Emergency      *bool           `json:"emergency,omitempty"`
	SPI            *bool           `json:"spi,omitempty"`
	Squawk         *string         `json:"squawk,omitempty"`
	SourceClass    string          `json:"source_class"`
	Quality        json.RawMessage `json:"quality,omitempty"`
	Trust          string          `json:"trust"`
	Source         string          `json:"source"`
	SourceInstance string          `json:"source_instance"`
	State          string          `json:"state"`
	Relevant       *bool           `json:"relevant,omitempty"`
	PolicyVersion  *string         `json:"policy_version,omitempty"`
	AgeS           *float64        `json:"age_s,omitempty"`
}

// envelopeIn is the 04 §2 envelope of a frame as received. Every time is
// optional here: a frame without rx_ts is placed at arrival and counted
// (T-12), never refused for it; the body is validated on its own.
type envelopeIn struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	Producer   string          `json:"producer"`
	TS         *string         `json:"ts"`
	RxTS       *string         `json:"rx_ts"`
	CapturedAt *string         `json:"captured_at"`
	TimeSource string          `json:"time_source"`
	Backlog    bool            `json:"backlog"`
	Body       json.RawMessage `json:"body"`
}

// Message is a track/manned/v1 message as this process publishes it on
// man.v1 (the envelope with this system's times: rx_ts its arrival,
// captured_at its placement; ts the source's time as carried, null when
// none).
type Message struct {
	Schema     string  `json:"schema"`
	MsgID      string  `json:"msg_id"`
	Producer   string  `json:"producer"`
	TS         *string `json:"ts"`
	RxTS       string  `json:"rx_ts"`
	CapturedAt string  `json:"captured_at"`
	TimeSource string  `json:"time_source"`
	Backlog    bool    `json:"backlog"`
	Body       Body    `json:"body"`
}

// AdapterState is one ANSP adapter as the ANSP's snapshot and status
// frame say it (its api/openapi.yaml AdapterState).
type AdapterState struct {
	ID          string   `json:"id"`
	State       string   `json:"state"`
	Enabled     bool     `json:"enabled"`
	LastFrameAt *string  `json:"last_frame_at"`
	AgeS        *float64 `json:"age_s"`
}

// statusIn is the part of the ANSP's console/status/v1 body this
// process reads (uspace-lab console/status/v1 with the ANSP's extras
// adapters[] and dropped_frames).
type statusIn struct {
	Degraded      []string          `json:"degraded"`
	Sources       []json.RawMessage `json:"sources"`
	Adapters      []AdapterState    `json:"adapters"`
	DroppedFrames *int64            `json:"dropped_frames"`
}

// snapshotIn is console/snapshot/v1 (a stream frame's body) and the
// answer of GET /v1/manned-traffic/snapshot (MannedSnapshot: the same
// body plus degraded, adapters and generated_at).
type snapshotIn struct {
	Manned      []json.RawMessage `json:"manned"`
	Degraded    []string          `json:"degraded"`
	Adapters    []AdapterState    `json:"adapters"`
	GeneratedAt *string           `json:"generated_at"`
}

// Validator checks a track/manned/v1 body against the ANSP's pinned
// schema (#/$defs/body of schemas/track/manned/v1.json).
type Validator struct {
	body *jsonschema.Schema
}

// The pinned files the validator compiles.
const (
	schemaFile   = "ansp-schemas/track/manned/v1.json"
	envelopeFile = "ansp-schemas/common/envelope/v1/schema.json"
)

// NewValidator compiles the pinned schema embedded from api/clients.
// Formats are asserted and nothing is loaded from the network: the
// envelope the schema references is added as a resource first.
func NewValidator() (*Validator, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	var trackID string
	for _, f := range []string{envelopeFile, schemaFile} {
		raw, err := fs.ReadFile(clients.ANSPSchemas, f)
		if err != nil {
			return nil, fmt.Errorf("pinned schema %s: %w", f, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("pinned schema %s: %w", f, err)
		}
		m, _ := doc.(map[string]any)
		id, _ := m["$id"].(string)
		if id == "" {
			return nil, fmt.Errorf("pinned schema %s has no $id", f)
		}
		if err := c.AddResource(id, doc); err != nil {
			return nil, fmt.Errorf("pinned schema %s: %w", f, err)
		}
		if f == schemaFile {
			trackID = id
		}
	}
	body, err := c.Compile(trackID + "#/$defs/body")
	if err != nil {
		return nil, fmt.Errorf("pinned schema %s does not compile: %w", schemaFile, err)
	}
	return &Validator{body: body}, nil
}

// Body validates raw as a track/manned/v1 body and decodes it. The
// error names the first failing member.
func (v *Validator) Body(raw json.RawMessage) (Body, error) {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return Body{}, &core.FieldError{Field: "body", Reason: "not JSON"}
	}
	if err := v.body.Validate(inst); err != nil {
		return Body{}, schemaError(err)
	}
	var b Body
	if err := json.Unmarshal(raw, &b); err != nil {
		return Body{}, core.Fieldf("body", "does not decode: %s", truncate(err.Error(), 120))
	}
	return b, nil
}

// schemaError is the first leaf of a validation error as a field error.
func schemaError(err error) error {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return core.Fieldf("body", "%s", truncate(err.Error(), 200))
	}
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	field := "body"
	if len(ve.InstanceLocation) > 0 {
		field += "." + strings.Join(ve.InstanceLocation, ".")
	}
	reason := "does not match the ANSP's schema"
	if u := ve.BasicOutput(); u != nil && u.Error != nil {
		reason = u.Error.String()
	}
	return &core.FieldError{Field: field, Reason: truncate(reason, 200)}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// decodeEnvelope reads the envelope of one frame of at most maxBytes.
func decodeEnvelope(data []byte, maxBytes int) (envelopeIn, error) {
	if maxBytes > 0 && len(data) > maxBytes {
		return envelopeIn{}, core.Fieldf("frame", "%d bytes, more than %d", len(data), maxBytes)
	}
	var e envelopeIn
	if err := json.Unmarshal(data, &e); err != nil {
		return envelopeIn{}, &core.FieldError{Field: "frame", Reason: "not an enveloped JSON object"}
	}
	if e.Schema == "" {
		return envelopeIn{}, &core.FieldError{Field: "schema", Reason: "required"}
	}
	if len(e.Body) == 0 || e.Body[0] != '{' {
		return envelopeIn{}, &core.FieldError{Field: "body", Reason: "not an object"}
	}
	return e, nil
}
