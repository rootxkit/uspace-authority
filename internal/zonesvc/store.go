package zonesvc

import (
	"context"
	"errors"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// ErrNotFound is a missing identifier or version.
var ErrNotFound = errors.New("not found")

// ErrDuplicate is a version whose (identifier, zone_version) is taken:
// another change to the identifier committed first.
var ErrDuplicate = errors.New("version taken")

// ListFilter selects the newest version of each identifier of a
// dataset, in identifier order after After.
type ListFilter struct {
	Dataset Dataset
	State   State
	After   string
	Limit   int
}

// Store is the zone service's view of the relational database. The
// production implementation is PG; unit tests use an in-memory one.
type Store interface {
	// InTx runs fn in one transaction: everything fn writes, events
	// included, commits together or not at all.
	InTx(ctx context.Context, fn func(Tx) error) error
	// Now is the database clock.
	Now(ctx context.Context) (time.Time, error)
	Latest(ctx context.Context, identifier string) (Version, error)
	Version(ctx context.Context, identifier string, zoneVersion int) (Version, error)
	// Versions is an identifier's history below before, newest first.
	Versions(ctx context.Context, identifier string, before, limit int) ([]Version, error)
	List(ctx context.Context, f ListFilter) ([]Version, error)
	// InForce is, per identifier of ds, the newest published version
	// whose period holds at at.
	InForce(ctx context.Context, ds Dataset, at time.Time) ([]Version, error)
}

// Tx is the work inside one transaction.
type Tx interface {
	// Lock takes a transaction-scoped advisory lock on name, waiting.
	Lock(ctx context.Context, name string) error
	// TryLock takes it without waiting; false when another holds it.
	TryLock(ctx context.Context, name string) (bool, error)
	// Record writes an events row in this transaction.
	Record(ctx context.Context, ev audit.Event) error
	// Now is the database clock (the transaction's start).
	Now(ctx context.Context) (time.Time, error)
	// NextZonesVersion numbers one publication.
	NextZonesVersion(ctx context.Context) (int64, error)
	// LatestForUpdate is the newest version of identifier, locked.
	LatestForUpdate(ctx context.Context, identifier string) (Version, error)
	// Insert stores d as version zoneVersion, a draft, by actor.
	Insert(ctx context.Context, d *Draft, zoneVersion int, by string) (Version, error)
	// SupersedeUnpublished marks the identifier's drafts and approved
	// versions superseded.
	SupersedeUnpublished(ctx context.Context, identifier string) error
	// Approve moves a draft to approved.
	Approve(ctx context.Context, identifier string, zoneVersion int, by string) (Version, error)
	// PublishApproved publishes every approved version of ds under
	// version.
	PublishApproved(ctx context.Context, ds Dataset, version int64, by string) ([]Version, error)
	// SupersedeOlderPublished marks the identifier's published versions
	// below zoneVersion superseded.
	SupersedeOlderPublished(ctx context.Context, identifier string, zoneVersion int) error
	InForce(ctx context.Context, ds Dataset, at time.Time) ([]Version, error)
	// Projectable is every published version of both datasets whose
	// period has not ended at at.
	Projectable(ctx context.Context, at time.Time) ([]Version, error)
	// MaxPublishedVersion is the newest zones version published.
	MaxPublishedVersion(ctx context.Context) (int64, error)
	// EnqueuePublication writes the F1 outbox row (pending, unsigned),
	// superseding the dataset's older pending row.
	EnqueuePublication(ctx context.Context, p PublicationInput) (Publication, error)
}

// PublicationInput is one outbox row to write.
type PublicationInput struct {
	Dataset      Dataset
	Version      int64
	Payload      []byte
	PayloadHash  string
	FeatureCount int
	By           string
}
