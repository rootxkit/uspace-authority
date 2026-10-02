package cisp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Problem slugs of the outbox.
const (
	SlugPublicationKeyMissing = "publication_key_missing"
	SlugPublicationRefused    = "publication_refused"
)

// MaxPayloadBytes bounds a publication: what the outbox column holds and
// what the CISP's ED-318 parser accepts by default (4 MiB).
const MaxPayloadBytes = 4 << 20

// Signer signs a publication's exact bytes as a detached JWS in the
// CISP's format (core's auth.KeyRing: RFC 7515 Appendix F, RFC 7797 b64
// false, crit ["b64"], RS256, kid, iat; M26).
type Signer interface {
	SignDetached(payload []byte, now time.Time) (string, error)
	ActiveKID() string
}

// Prepared is a publication that passed the CISP's checks and is signed:
// what the outbox row holds.
type Prepared struct {
	Dataset      Dataset
	Payload      []byte
	PayloadHash  string
	FeatureCount int
	ContentType  string
	Signature    string
	KID          string
	SignedAt     time.Time
}

// Row is one outbox row as written.
type Row struct {
	ID           int64
	Dataset      Dataset
	Version      int64
	PayloadHash  string
	FeatureCount int
	Signature    *string
	State        string
	CreatedAt    time.Time
}

// Outbox prepares publications (validation against the pinned CISP
// schemas, then the detached signature) and writes them pending; the
// Sender delivers them.
type Outbox struct {
	Schemas *Schemas
	// Signer is nil when PUBLICATION_KEY_FILE is not configured: every
	// publication is refused (503 publication_key_missing), never
	// queued unsigned.
	Signer   Signer
	Store    OutboxStore
	Counters *core.Counters
	Now      func() time.Time

	wake chan struct{}
}

// NewOutbox builds an outbox.
func NewOutbox(schemas *Schemas, signer Signer, store OutboxStore, counters *core.Counters) *Outbox {
	if counters == nil {
		counters = &core.Counters{}
	}
	return &Outbox{Schemas: schemas, Signer: signer, Store: store, Counters: counters, Now: time.Now, wake: make(chan struct{}, 1)}
}

// Prepare holds payload to the CISP's checks for ds (CheckPublication),
// refusing it whole with every problem by path (400
// publication_refused, before anything is signed), and signs it.
func (o *Outbox) Prepare(ds Dataset, payload []byte) (Prepared, error) {
	if len(payload) > MaxPayloadBytes {
		o.count(CounterPublicationsRefused)
		return Prepared{}, httpx.Refuse(http.StatusConflict, SlugPublicationRefused, "the dataset is too large to publish",
			core.Fieldf("payload", "%d bytes; a publication is at most %d", len(payload), MaxPayloadBytes))
	}
	checked, probs, more := o.Schemas.CheckPublication(ds, payload)
	if len(probs) > 0 {
		o.count(CounterPublicationsRefused)
		p := httpx.NewProblem(http.StatusBadRequest, SlugPublicationRefused, "Publication refused",
			"the "+string(ds)+" dataset does not pass the CISP's checks; nothing was signed or queued", probs...)
		if more > 0 {
			p.Truncated = true
		}
		return Prepared{}, &httpx.ProblemError{Problem: p}
	}
	if o.Signer == nil {
		o.count(CounterPublicationsUnsigned)
		return Prepared{}, httpx.Refuse(http.StatusServiceUnavailable, SlugPublicationKeyMissing,
			"no publication key is configured (PUBLICATION_KEY_FILE); nothing was queued")
	}
	now := o.now()
	sig, err := o.Signer.SignDetached(payload, now)
	if err != nil {
		o.count(CounterPublicationsUnsigned)
		return Prepared{}, httpx.Refuse(http.StatusServiceUnavailable, SlugPublicationKeyMissing,
			"the publication could not be signed; nothing was queued")
	}
	sum := sha256.Sum256(payload)
	return Prepared{
		Dataset: ds, Payload: payload, PayloadHash: hex.EncodeToString(sum[:]), FeatureCount: checked.FeatureCount,
		ContentType: ds.ContentType(), Signature: sig, KID: o.Signer.ActiveKID(), SignedAt: now.UTC(),
	}, nil
}

// Enqueue prepares payload and writes it pending in a transaction of its
// own, superseding the dataset's pending row, then wakes the sender. It
// is the outbox of publications that are not written inside another
// transaction (the USSP list, WP-16); zones and U-space airspaces are
// written by their publication's transaction through EnqueueTx.
func (o *Outbox) Enqueue(ctx context.Context, ds Dataset, payload []byte, actor audit.Actor) (Row, error) {
	p, err := o.Prepare(ds, payload)
	if err != nil {
		return Row{}, err
	}
	row, err := o.Store.Enqueue(ctx, p, 0, actor)
	if err != nil {
		return Row{}, err
	}
	o.count(CounterPublicationsQueued)
	o.Wake()
	return row, nil
}

// Wake tells the sender a row was written; it never blocks.
func (o *Outbox) Wake() {
	if o.wake == nil {
		return
	}
	select {
	case o.wake <- struct{}{}:
	default:
	}
}

// Woken is the sender's wake-up channel.
func (o *Outbox) Woken() <-chan struct{} { return o.wake }

func (o *Outbox) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

func (o *Outbox) count(name string) {
	if o.Counters != nil {
		o.Counters.Inc(name)
	}
}
