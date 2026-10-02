package track

import (
	"encoding/json"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// IdentSchema is the schema of an identification change
// (schemas/ident/change/v1.json, this repository's).
const IdentSchema = "ident/change/v1"

// IdentBody is an identification change: the block now carried by the
// track, and the one it replaces (null for the track's first).
type IdentBody struct {
	TrackID        string               `json:"track_id"`
	Trust          core.Trust           `json:"trust"`
	Source         Source               `json:"source"`
	SourceInstance string               `json:"source_instance"`
	Identification core.Identification  `json:"identification"`
	Previous       *core.Identification `json:"previous"`
}

// IdentChange is ident/change/v1 with the 04 §2 envelope; its times are
// those of the track message that carried the change.
type IdentChange struct {
	Schema     string          `json:"schema"`
	MsgID      string          `json:"msg_id"`
	Producer   string          `json:"producer"`
	TS         *string         `json:"ts"`
	RxTS       string          `json:"rx_ts"`
	CapturedAt string          `json:"captured_at"`
	TimeSource core.TimeSource `json:"time_source"`
	Backlog    bool            `json:"backlog"`
	Body       IdentBody       `json:"body"`
}

// IdentChanged reports whether next differs from prev in what ident.v1
// announces: the status, the reason or the mismatch flag (04 §3.2). A
// nil prev is a change: the track's first identification.
func IdentChanged(prev *core.Identification, next core.Identification) bool {
	return prev == nil || prev.Status != next.Status || prev.Reason != next.Reason || prev.Mismatch != next.Mismatch
}

// NewIdentChange is the change m carries over prev; at stamps its
// msg_id.
func NewIdentChange(m *Message, prev *core.Identification, at time.Time) *IdentChange {
	var before *core.Identification
	if prev != nil {
		p := *prev
		before = &p
	}
	return &IdentChange{
		Schema: IdentSchema, MsgID: bus.NewULID(at), Producer: m.Producer, TS: m.TS, RxTS: m.RxTS,
		CapturedAt: m.CapturedAt, TimeSource: m.TimeSource, Backlog: m.Backlog,
		Body: IdentBody{
			TrackID: m.Body.TrackID, Trust: m.Body.Trust, Source: m.Body.Source, SourceInstance: m.Body.SourceInstance,
			Identification: m.Body.Identification, Previous: before,
		},
	}
}

// IdentSubject is ident.v1.<track_id>.
func IdentSubject(trackID string) (string, error) { return bus.Subjects.Ident(trackID) }

// Validate refuses a change the schema refuses.
func (c *IdentChange) Validate() error {
	switch {
	case c.Schema != IdentSchema:
		return core.Fieldf("schema", "%q, want %s", c.Schema, IdentSchema)
	case !ulidPattern.MatchString(c.MsgID):
		return core.Fieldf("msg_id", "%q is not a ULID", c.MsgID)
	case c.Body.TrackID == "":
		return &core.FieldError{Field: "body.track_id", Reason: "required"}
	}
	if err := validateIdentification("body.identification", &c.Body.Identification); err != nil {
		return err
	}
	if c.Body.Previous != nil {
		return validateIdentification("body.previous", c.Body.Previous)
	}
	return nil
}

// PublishIdent validates c and sends it on ident.v1.<track_id> (the
// IDENT stream holds the subject, 24 h).
func PublishIdent(p bus.Publisher, c *IdentChange) error {
	if err := c.Validate(); err != nil {
		return err
	}
	subject, err := IdentSubject(c.Body.TrackID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return p.Publish(subject, data)
}
