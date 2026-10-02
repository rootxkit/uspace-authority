package picture

import (
	"encoding/json"
	"time"

	"github.com/coder/websocket"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// Producer is the envelope's producer of every frame picture-ws makes
// (status, snapshot); a track, a manned track and a violation keep the
// envelope of the process that produced them, so each keeps its own
// times (04 §2, console/snapshot/v1).
const Producer = "authority/picture-ws"

// The schemas of the common console frame (M29; uspace-lab
// schemas/common/), and the two message schemas forwarded as received.
const (
	SchemaStatus    = "console/status/v1"
	SchemaSnapshot  = "console/snapshot/v1"
	SchemaSubscribe = "console/subscribe/v1"
	SchemaSource    = "source/status/v1"
	SchemaTrack     = "track/telemetry/v1"
	SchemaManned    = "track/manned/v1"
	SchemaViolation = "violation/v1"
)

// The layers of console/subscribe/v1.
const (
	LayerTracks = "tracks"
	LayerManned = "manned"
	LayerAlerts = "alerts"
	LayerZones  = "zones"
)

// Close codes picture-ws sends.
const (
	// CloseRelogin (4401): no session, a refused one, or one that has
	// ended (logout, revocation, expiry); the console signs in again
	// (M22).
	CloseRelogin websocket.StatusCode = 4401
	// CloseTryAgainLater (1013): the session could not be checked (api
	// unreachable); the console reconnects later.
	CloseTryAgainLater = websocket.StatusTryAgainLater
	// CloseGoingAway (1001): the instance stops.
	CloseGoingAway = websocket.StatusGoingAway
	// CloseInvalid (1007): a frame from the console that is not a
	// console/subscribe/v1.
	CloseInvalid = websocket.StatusInvalidFramePayloadData
	// CloseTooBig (1009): a frame larger than PICTURE_SUBSCRIBE_MAX_BYTES.
	CloseTooBig = websocket.StatusMessageTooBig
)

// SourceState is one source as the console sees it: the body of
// source/status/v1 (uspace-lab schemas/common/source/status/v1) built
// from the adapter's last src.v1 status and the source-control state,
// plus the adapters' lagging and lag_s.
type SourceState struct {
	Source         string            `json:"source"`
	SourceInstance *string           `json:"source_instance"`
	State          string            `json:"state"`
	Since          string            `json:"since"`
	AgeS           *float64          `json:"age_s"`
	DisabledBy     *string           `json:"disabled_by"`
	DisabledByWho  *string           `json:"disabled_by_who"`
	Counters       map[string]uint64 `json:"counters"`
	Lagging        bool              `json:"lagging"`
	LagS           *float64          `json:"lag_s"`
}

// StatusBody is the console/status/v1 body (the lab's members) with this
// system's extras (schemas/picture/status/v1.json): projection_age_s,
// cis_version, cis_age_s, dp_state and nats from the lab's catalogue of
// extras, and nats_since and degraded_since, which say since when.
type StatusBody struct {
	ConnectionID  string        `json:"connection_id"`
	ServerTS      string        `json:"server_ts"`
	PolicyVersion string        `json:"policy_version"`
	StaleAfterS   float64       `json:"stale_after_s"`
	LiveMaxAgeS   float64       `json:"live_max_age_s"`
	DroppedFrames uint64        `json:"dropped_frames"`
	Degraded      []string      `json:"degraded"`
	Sources       []SourceState `json:"sources"`

	ProjectionAgeS *float64          `json:"projection_age_s,omitempty"`
	CISVersion     *string           `json:"cis_version,omitempty"`
	CISAgeS        *float64          `json:"cis_age_s,omitempty"`
	DPState        string            `json:"dp_state"`
	NATS           string            `json:"nats"`
	NATSSince      *string           `json:"nats_since,omitempty"`
	DegradedSince  map[string]string `json:"degraded_since"`
}

// SnapshotBody is the console/snapshot/v1 body: each item a complete
// message with its own envelope.
type SnapshotBody struct {
	Tracks       []json.RawMessage `json:"tracks"`
	Alerts       []json.RawMessage `json:"alerts"`
	Manned       []json.RawMessage `json:"manned"`
	ZonesVersion *string           `json:"zones_version"`
	// Truncated says items were left out at PICTURE_SNAPSHOT_MAX_BYTES
	// (schemas/picture/snapshot/v1.json).
	Truncated bool `json:"truncated"`
}

// systemFrame is body in the 04 §2 envelope as picture-ws produces it at
// now: time_source system, never backlog.
func systemFrame[B any](schema string, now time.Time, body B) ([]byte, error) {
	return json.Marshal(bus.SystemEnvelope(schema, Producer, now, body))
}

// stamp is the envelope's timestamp form.
func stamp(t time.Time) string { return bus.Stamp(t) }

func ptr[T any](v T) *T { return &v }
