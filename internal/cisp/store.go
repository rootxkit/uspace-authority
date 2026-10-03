package cisp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// Outbox states (migration 00014_cisp).
const (
	StatePending      = "pending"
	StateSent         = "sent"
	StateAcknowledged = "acknowledged"
	StateFailed       = "failed"
	StateConflict     = "conflict"
	StateSuperseded   = "superseded"
)

// DueRow is the first unfinished row of a dataset.
type DueRow struct {
	ID           int64
	Dataset      Dataset
	Version      int64
	Payload      []byte
	PayloadHash  string
	FeatureCount int
	ContentType  string
	State        string
	Attempts     int
	NextRetryAt  *time.Time
	CreatedAt    time.Time
}

// Outcome is how one attempt ended, as the outbox records it.
type Outcome struct {
	// Status is the CISP's HTTP status; 0 for a network error.
	Status int
	// Reason is the error text (empty on success).
	Reason string
}

// OutboxView is one row as the console sees it.
type OutboxView struct {
	ID              int64
	Dataset         Dataset
	Version         int64
	PayloadHash     string
	FeatureCount    int
	ContentType     string
	SignatureKID    *string
	SignedAt        *time.Time
	State           string
	Attempts        int
	NextRetryAt     *time.Time
	CISPVersion     *int64
	ConflictVersion *int64
	LastAttemptAt   *time.Time
	LastStatus      *int
	LastError       *string
	AcknowledgedAt  *time.Time
	CreatedAt       time.Time
	CreatedBy       string
	StateChangedAt  time.Time
	AgeS            float64
}

// ListFilter selects outbox rows.
type ListFilter struct {
	Dataset Dataset
	State   string
	Limit   int
}

// OutboxStore is the relational side of the outbox. Every state change
// writes its events row in the same transaction.
type OutboxStore interface {
	// Enqueue writes p pending as version (0: the dataset's next) in a
	// transaction of its own, superseding the pending row.
	Enqueue(ctx context.Context, p Prepared, version int64, actor audit.Actor) (Row, error)
	// Due returns the first unfinished row of every dataset.
	Due(ctx context.Context) ([]DueRow, error)
	// IfMatch is the CISP version the row id is sent against: that of
	// the newest earlier row of ds the CISP acknowledged or showed in a
	// 412; ok is false before the first.
	IfMatch(ctx context.Context, ds Dataset, before int64) (version int64, ok bool, err error)
	// MarkSending records an attempt (pending or sent -> sent) and its
	// fresh signature; false when the row is no longer due.
	MarkSending(ctx context.Context, r *DueRow, sig, kid string, signedAt time.Time) (bool, error)
	MarkAcknowledged(ctx context.Context, r *DueRow, cispVersion int64, o Outcome) error
	MarkRetry(ctx context.Context, r *DueRow, next time.Time, o Outcome) error
	MarkFailed(ctx context.Context, r *DueRow, o Outcome) error
	MarkConflict(ctx context.Context, r *DueRow, current *int64, o Outcome) error
	List(ctx context.Context, f ListFilter) ([]OutboxView, error)
}

// Cached is one dataset version held by the subscriber.
type Cached struct {
	Dataset      Dataset
	Version      int64
	ETag         string
	UpdatedAt    *time.Time
	FetchedAt    time.Time
	CheckedAt    time.Time
	FeatureCount int
	PublisherKID string
	Payload      json.RawMessage
	// AgeS is the age on the database clock when loaded (warm start).
	AgeS float64
}

// CacheStore is the relational side of the subscriber.
type CacheStore interface {
	Load(ctx context.Context) ([]Cached, error)
	// Save stores c; an older version never replaces a newer one.
	Save(ctx context.Context, c *Cached) error
	// Touch records that the CISP confirmed version.
	Touch(ctx context.Context, ds Dataset, version int64) error
	// RememberJTI records a verified delivery id for ttl, at most maxLive
	// live ids per issuer. fresh is false for a replay; full is true when
	// maxLive ids of the issuer are live and nothing was recorded.
	RememberJTI(ctx context.Context, issuer, jti string, ttl time.Duration, maxLive int64) (fresh, full bool, err error)
	// SweepJTIs deletes the expired delivery ids.
	SweepJTIs(ctx context.Context) (int64, error)
}
