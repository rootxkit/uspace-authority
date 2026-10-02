package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// Schema names the document's body (schemas/source/control/v1.json).
const Schema = "source/control/v1"

// Producer names api in the envelope.
const Producer = "authority/api"

// StateKey is the document's key in the bucket.
const StateKey = "state"

// The source types of this system (04 §2 source): one per adapter
// process (B-16).
const (
	TypeDirectRID  = "direct_rid"  // rid-ingest, per receiver
	TypeNetworkRID = "network_rid" // dp-poller, per USSP
	TypeANSPFeed   = "ansp_feed"   // manned-ingest, per feed
)

// Types are the source types a switch may name.
var Types = []string{TypeDirectRID, TypeNetworkRID, TypeANSPFeed}

// Control is one switch as it travels: core's Control plus who, why,
// when and the version of the change.
type Control struct {
	SourceType string    `json:"source_type"`
	InstanceID *string   `json:"instance_id"`
	Enabled    bool      `json:"enabled"`
	Reason     string    `json:"reason"`
	Actor      string    `json:"actor"`
	ChangedAt  time.Time `json:"changed_at"`
	Version    uint64    `json:"version"`
}

// Document is the source-control state as it travels (the envelope's
// body).
type Document struct {
	Epoch       string    `json:"epoch"`
	Version     uint64    `json:"version"`
	DefaultDeny bool      `json:"default_deny"`
	Controls    []Control `json:"controls"`
}

// State is d as core judges it.
func (d Document) State() coresources.State {
	st := coresources.State{DefaultDeny: d.DefaultDeny, Version: d.Version, Epoch: d.Epoch}
	for _, c := range d.Controls {
		st.Controls = append(st.Controls, coresources.Control{SourceType: c.SourceType, InstanceID: c.InstanceID, Enabled: c.Enabled})
	}
	return st
}

// Same reports whether d and o carry the same state: epoch, version,
// default and every control.
func (d Document) Same(o Document) bool {
	if d.Epoch != o.Epoch || d.Version != o.Version || d.DefaultDeny != o.DefaultDeny || len(d.Controls) != len(o.Controls) {
		return false
	}
	return slices.EqualFunc(d.Controls, o.Controls, func(a, b Control) bool {
		return a.SourceType == b.SourceType && eqPtr(a.InstanceID, b.InstanceID) && a.Enabled == b.Enabled &&
			a.Reason == b.Reason && a.Actor == b.Actor && a.ChangedAt.Equal(b.ChangedAt) && a.Version == b.Version
	})
}

// SameContent is Same without the epoch and the version: whether the
// switches themselves differ.
func (d Document) SameContent(o Document) bool {
	o.Epoch, o.Version = d.Epoch, d.Version
	return d.Same(o)
}

func eqPtr(a, b *string) bool { return (a == nil && b == nil) || (a != nil && b != nil && *a == *b) }

// Encode is d in its envelope at now.
func Encode(d Document, now time.Time) ([]byte, error) {
	if d.Controls == nil {
		d.Controls = []Control{}
	}
	return json.Marshal(bus.SystemEnvelope(Schema, Producer, now, d))
}

// ErrMalformed is a value that is not a source/control/v1 document.
var ErrMalformed = errors.New("source-control document malformed")

// Decode reads a document from its envelope. A value that is not one
// (wrong schema, no epoch, a control without a type) is ErrMalformed: a
// follower keeps what it holds and counts it.
func Decode(raw []byte) (Document, error) {
	var env bus.Envelope[Document]
	if err := json.Unmarshal(raw, &env); err != nil {
		return Document{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if env.Schema != Schema {
		return Document{}, fmt.Errorf("%w: schema %q, want %q", ErrMalformed, env.Schema, Schema)
	}
	d := env.Body
	if d.Epoch == "" {
		return Document{}, fmt.Errorf("%w: no epoch", ErrMalformed)
	}
	for i, c := range d.Controls {
		if c.SourceType == "" {
			return Document{}, fmt.Errorf("%w: controls[%d] has no source_type", ErrMalformed, i)
		}
	}
	return d, nil
}
