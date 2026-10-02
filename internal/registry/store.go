package registry

import (
	"context"
	"errors"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// ErrNotFound is a missing registry entry.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is a registration whose key is held already (the
// database's unique constraint, behind the service's own check).
var ErrDuplicate = errors.New("registered already")

// SealedOperator holds an operator's personal columns as sealed bytes
// (internal/pii); nil is a NULL column.
type SealedOperator struct {
	KeyID                     string
	FullName                  []byte
	LegalName                 []byte
	DateOfBirth               []byte
	LegalIdentificationNumber []byte
	PostalAddress             []byte
	ContactEmail              []byte
	ContactPhone              []byte
	InsurancePolicyNumber     []byte
}

// OperatorRecord is a stored operator.
type OperatorRecord struct {
	Operator
	// Key is the compare key (regnum.CompareKey), unique.
	Key        string
	SecretSalt []byte
	SecretHash string
	Sealed     SealedOperator
}

// PilotRecord is a stored pilot.
type PilotRecord struct {
	Pilot
	PersonRefHash  string
	PersonRefLast4 string
	KeyID          string
	NameSealed     []byte
}

// StatusUpdate is one status transition to store.
type StatusUpdate struct {
	ID      string
	Status  Status
	Reason  string
	Version int64
	At      time.Time
	By      string
}

// Change is one entry of the F8 change feed.
type Change struct {
	Seq        int64
	EntityType string
	EntityID   string
	PublicKey  string
	Status     Status
	At         time.Time
}

// ProjectedOperator is one operator as the projection holds it
// (identify.OperatorFacts plus the version).
type ProjectedOperator struct {
	OperatorID         string
	RegistrationNumber string
	Status             string
	Version            int64
}

// ProjectedUAS is one aircraft as the projection holds it
// (identify.UASFacts plus the version; every row written here is in
// the registry).
type ProjectedUAS struct {
	UASID      string
	Label      string
	Serial     string
	SerialFold string
	Status     string
	OperatorID string
	Version    int64
}

// Facts is what a full re-projection writes.
type Facts struct {
	Operators []ProjectedOperator
	UAS       []ProjectedUAS
}

// Page selects one page in id order.
type Page struct {
	After string
	Limit int
}

// OperatorFilter selects operators; empty fields do not filter.
type OperatorFilter struct {
	Key    string
	Status Status
	Page
}

// UASFilter selects aircraft; empty fields do not filter.
type UASFilter struct {
	SerialFold string
	OperatorID string
	Status     Status
	Page
}

// PilotFilter selects pilots; empty fields do not filter.
type PilotFilter struct {
	OperatorID string
	Status     Status
	Page
}

// Store is the registry's view of the relational database. The
// production implementation is PG; tests use an in-memory one.
type Store interface {
	// InTx runs fn in one transaction: everything fn writes, events
	// included, commits together or not at all.
	InTx(ctx context.Context, fn func(Tx) error) error
	Operator(ctx context.Context, id string) (OperatorRecord, error)
	OperatorByKey(ctx context.Context, key string) (OperatorRecord, error)
	Operators(ctx context.Context, f OperatorFilter) ([]OperatorRecord, error)
	UAS(ctx context.Context, id string) (UAS, error)
	UASByFold(ctx context.Context, fold string) ([]UAS, error)
	UASList(ctx context.Context, f UASFilter) ([]UAS, error)
	// Pilot reads a pilot with its competencies.
	Pilot(ctx context.Context, id string) (PilotRecord, error)
	Pilots(ctx context.Context, f PilotFilter) ([]PilotRecord, error)
	Changes(ctx context.Context, since int64, limit int) ([]Change, error)
}

// Tx is the work inside one transaction.
type Tx interface {
	// Lock takes a transaction-scoped advisory lock on name, waiting.
	Lock(ctx context.Context, name string) error
	// TryLock takes it without waiting; false when another holds it.
	TryLock(ctx context.Context, name string) (bool, error)
	// Record writes an events row in this transaction.
	Record(ctx context.Context, ev audit.Event) error
	// NextVersion numbers this change (registry_version_seq).
	NextVersion(ctx context.Context) (int64, error)

	InsertOperator(ctx context.Context, r OperatorRecord) (OperatorRecord, error)
	OperatorForUpdate(ctx context.Context, id string) (OperatorRecord, error)
	OperatorByKey(ctx context.Context, key string) (OperatorRecord, error)
	UpdateOperator(ctx context.Context, r OperatorRecord) (OperatorRecord, error)
	SetOperatorStatus(ctx context.Context, u StatusUpdate) (OperatorRecord, error)
	ExpiredOperatorIDs(ctx context.Context, now time.Time, limit int) ([]string, error)

	InsertUAS(ctx context.Context, u UAS) (UAS, error)
	UASForUpdate(ctx context.Context, id string) (UAS, error)
	UASByFold(ctx context.Context, fold string) ([]UAS, error)
	UpdateUAS(ctx context.Context, u UAS) (UAS, error)
	SetUASStatus(ctx context.Context, u StatusUpdate) (UAS, error)

	InsertPilot(ctx context.Context, r PilotRecord) (PilotRecord, error)
	PilotForUpdate(ctx context.Context, id string) (PilotRecord, error)
	PilotByPersonRef(ctx context.Context, hash string) (PilotRecord, error)
	UpdatePilot(ctx context.Context, r PilotRecord) (PilotRecord, error)
	SetPilotStatus(ctx context.Context, u StatusUpdate) (PilotRecord, error)
	UpsertCompetency(ctx context.Context, pilotID string, c Competency) error

	InsertChange(ctx context.Context, c Change) (int64, error)
	// Facts reads every operator and aircraft for a re-projection.
	Facts(ctx context.Context) (Facts, error)
}
