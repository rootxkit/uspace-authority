package audit

import (
	"errors"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// ActorType is who acted (spec 03 §1 events.actor_type).
type ActorType string

// The actor types the table admits.
const (
	ActorUser     ActorType = "user"
	ActorClient   ActorType = "client"
	ActorReceiver ActorType = "receiver"
	ActorSystem   ActorType = "system"
)

var actorTypes = []ActorType{ActorUser, ActorClient, ActorReceiver, ActorSystem}

// Realms of a console session (docs/PLAN.md §7).
const (
	RealmConsole = "console"
	RealmPolice  = "police"
)

// Actor is who an event is attributed to.
type Actor struct {
	Type ActorType
	ID   string
	// Realm is the session realm; empty for machines and the system.
	Realm string
}

// SystemActor is the actor of an act the system takes on its own (a
// job, a migration seed).
func SystemActor(id string) Actor { return Actor{Type: ActorSystem, ID: id} }

// Event is one row to record.
type Event struct {
	// TS is when the act happened; zero means now. Set only by imports
	// and tests: a handler never back-dates an event.
	TS    time.Time
	Actor Actor
	// Purpose is why: required on every event type tagged PIIView
	// (CLAUDE.md rule 6), optional elsewhere.
	Purpose    string
	EntityType string
	EntityID   string
	EventType  string
	// Payload is marshalled to a JSON object; nil records {}.
	Payload any
}

// Kind describes one event type.
type Kind struct {
	// PIIView tags a read of personal data: the event is refused
	// without a purpose.
	PIIView bool
}

// Catalogue is every event type the writer accepts. A type outside it
// is refused, so a misspelt type cannot slip into the log unnoticed.
type Catalogue map[string]Kind

// Event types of WP-1. Later work packages add theirs to
// DefaultCatalogue.
const (
	EventPolicyCreated     = "policy_created"
	EventPolicyActivated   = "policy_activated"
	EventAuditEventsViewed = "audit_events_viewed"
)

// Event types of WP-2's token service (internal/tokens): every issuance
// and every refusal (06 §3), the client registry and the signing keys.
const (
	EventTokenIssued          = "token_issued"
	EventTokenRefused         = "token_refused"
	EventOAuthClientCreated   = "oauth_client_created"
	EventOAuthClientUpdated   = "oauth_client_updated"
	EventSigningKeyRegistered = "signing_key_registered"
	EventSigningKeyActivated  = "signing_key_activated"
	EventKeyRotationRequested = "key_rotation_requested"
	EventKeyRotationRefused   = "key_rotation_refused"
)

// DefaultCatalogue is the catalogue of this build.
func DefaultCatalogue() Catalogue {
	return Catalogue{
		EventPolicyCreated:     {},
		EventPolicyActivated:   {},
		EventAuditEventsViewed: {},

		EventTokenIssued:          {},
		EventTokenRefused:         {},
		EventOAuthClientCreated:   {},
		EventOAuthClientUpdated:   {},
		EventSigningKeyRegistered: {},
		EventSigningKeyActivated:  {},
		EventKeyRotationRequested: {},
		EventKeyRotationRefused:   {},
	}
}

// Validate refuses an event the log must not hold, naming every field
// at fault.
func (c Catalogue) Validate(ev Event) error {
	var errs []error
	if !slices.Contains(actorTypes, ev.Actor.Type) {
		errs = append(errs, core.Fieldf("actor_type", "must be one of user, client, receiver, system"))
	}
	if ev.Actor.ID == "" {
		errs = append(errs, &core.FieldError{Field: "actor_id", Reason: "required"})
	}
	if ev.Actor.Realm != "" && ev.Actor.Realm != RealmConsole && ev.Actor.Realm != RealmPolice {
		errs = append(errs, core.Fieldf("realm", "must be console or police"))
	}
	if ev.EntityType == "" {
		errs = append(errs, &core.FieldError{Field: "entity_type", Reason: "required"})
	}
	kind, known := c[ev.EventType]
	switch {
	case ev.EventType == "":
		errs = append(errs, &core.FieldError{Field: "event_type", Reason: "required"})
	case !known:
		errs = append(errs, core.Fieldf("event_type", "%q is not in the audit catalogue", ev.EventType))
	case kind.PIIView && ev.Purpose == "":
		errs = append(errs, core.Fieldf("purpose", "required: %s is a PII read (pii_view)", ev.EventType))
	}
	return errors.Join(errs...)
}
