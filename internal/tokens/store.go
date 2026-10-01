package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Client statuses (oauth_clients.status).
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusRevoked   = "revoked"
)

// Client authentication methods (oauth_clients.auth_method).
const (
	MethodSecretPost    = "client_secret_post"
	MethodPrivateKeyJWT = "private_key_jwt"
)

// Client is a row of oauth_clients.
type Client struct {
	ID            string
	System        string
	Scopes        []string
	Audiences     []string
	AuthMethod    string
	SecretHash    string
	JWKS          json.RawMessage
	MTLSSubject   string
	CertificateID string
	Status        string
	Note          string
	CreatedAt     time.Time
	CreatedBy     string
	UpdatedAt     time.Time
	UpdatedBy     string
}

// ErrNotFound is a missing client.
var ErrNotFound = errors.New("not found")

// Store is the token service's view of the relational database. The
// production implementation is PG; tests use an in-memory one.
type Store interface {
	// InTx runs fn in one transaction: everything fn writes, events
	// included, commits together or not at all.
	InTx(ctx context.Context, fn func(Tx) error) error
	Client(ctx context.Context, id string) (Client, error)
	Clients(ctx context.Context) ([]Client, error)
	SigningKeys(ctx context.Context) ([]KeyRow, error)
}

// Tx is the work inside one transaction.
type Tx interface {
	// Lock takes a transaction-scoped advisory lock on name.
	Lock(ctx context.Context, name string) error
	// Record writes an events row in this transaction.
	Record(ctx context.Context, ev audit.Event) error
	Client(ctx context.Context, id string) (Client, error)
	InsertClient(ctx context.Context, c Client) (Client, error)
	UpdateClient(ctx context.Context, c Client) (Client, error)
	SigningKeys(ctx context.Context) ([]KeyRow, error)
	InsertSigningKey(ctx context.Context, r KeyRow) error
	SetSigningKeyRef(ctx context.Context, kid, ref string) error
	ActivateSigningKey(ctx context.Context, kid string, at time.Time) error
	RetireSigningKey(ctx context.Context, kid string, at time.Time) error
	RequestKeyRotation(ctx context.Context, kid, by string, at time.Time) error
}

// PG is Store on the relational database, recording events through the
// audit writer in the same transaction.
type PG struct {
	DB    *pg.DB
	Audit *audit.Writer
}

var _ Store = PG{}

// InTx runs fn in a pg transaction.
func (p PG) InTx(ctx context.Context, fn func(Tx) error) error {
	return p.DB.WithTx(ctx, func(q *gen.Queries) error { return fn(pgTx{q: q, audit: p.Audit}) })
}

// Client reads one client.
func (p PG) Client(ctx context.Context, id string) (Client, error) {
	return clientByID(ctx, p.DB.Queries(), id)
}

// Clients lists every client.
func (p PG) Clients(ctx context.Context) ([]Client, error) {
	rows, err := p.DB.Queries().ListOAuthClients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Client, 0, len(rows))
	for i := range rows {
		out = append(out, clientFromRow(&rows[i]))
	}
	return out, nil
}

// SigningKeys lists signing_keys.
func (p PG) SigningKeys(ctx context.Context) ([]KeyRow, error) {
	return signingKeys(ctx, p.DB.Queries())
}

type pgTx struct {
	q     *gen.Queries
	audit *audit.Writer
}

// Lock implements Tx.
func (t pgTx) Lock(ctx context.Context, name string) error {
	return t.q.AdvisoryXactLock(ctx, pg.LockKey(name))
}

// Record implements Tx.
func (t pgTx) Record(ctx context.Context, ev audit.Event) error {
	_, err := t.audit.Record(ctx, t.q, ev)
	return err
}

// Client implements Tx.
func (t pgTx) Client(ctx context.Context, id string) (Client, error) { return clientByID(ctx, t.q, id) }

// InsertClient implements Tx.
func (t pgTx) InsertClient(ctx context.Context, c Client) (Client, error) {
	r, err := t.q.InsertOAuthClient(ctx, gen.InsertOAuthClientParams{
		ClientID: c.ID, System: c.System, Scopes: c.Scopes, Audiences: nonNil(c.Audiences),
		AuthMethod: c.AuthMethod, SecretHash: optional(c.SecretHash), Jwks: optionalJSON(c.JWKS),
		MtlsSubject: optional(c.MTLSSubject), CertificateID: optional(c.CertificateID),
		Status: c.Status, Note: c.Note, CreatedAt: c.CreatedAt, CreatedBy: c.CreatedBy,
	})
	if err != nil {
		return Client{}, err
	}
	return clientFromRow(&r), nil
}

// UpdateClient implements Tx.
func (t pgTx) UpdateClient(ctx context.Context, c Client) (Client, error) {
	r, err := t.q.UpdateOAuthClient(ctx, gen.UpdateOAuthClientParams{
		ClientID: c.ID, Scopes: c.Scopes, Audiences: nonNil(c.Audiences), Status: c.Status, Note: c.Note,
		UpdatedAt: c.UpdatedAt, UpdatedBy: c.UpdatedBy,
	})
	if store.IsNoRows(err) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	return clientFromRow(&r), nil
}

// SigningKeys implements Tx.
func (t pgTx) SigningKeys(ctx context.Context) ([]KeyRow, error) { return signingKeys(ctx, t.q) }

// InsertSigningKey implements Tx.
func (t pgTx) InsertSigningKey(ctx context.Context, r KeyRow) error {
	return t.q.InsertSigningKey(ctx, gen.InsertSigningKeyParams{
		Kid: r.KID, Purpose: r.Purpose, PublicJwk: r.PublicJWK, PrivateRef: r.PrivateRef, RegisteredAt: r.RegisteredAt,
	})
}

// SetSigningKeyRef implements Tx.
func (t pgTx) SetSigningKeyRef(ctx context.Context, kid, ref string) error {
	return t.q.SetSigningKeyRef(ctx, gen.SetSigningKeyRefParams{Kid: kid, PrivateRef: ref})
}

// ActivateSigningKey implements Tx.
func (t pgTx) ActivateSigningKey(ctx context.Context, kid string, at time.Time) error {
	return t.q.ActivateSigningKey(ctx, gen.ActivateSigningKeyParams{Kid: kid, At: &at})
}

// RetireSigningKey implements Tx.
func (t pgTx) RetireSigningKey(ctx context.Context, kid string, at time.Time) error {
	return t.q.RetireSigningKey(ctx, gen.RetireSigningKeyParams{Kid: kid, At: &at})
}

// RequestKeyRotation implements Tx.
func (t pgTx) RequestKeyRotation(ctx context.Context, kid, by string, at time.Time) error {
	return t.q.RequestKeyRotation(ctx, gen.RequestKeyRotationParams{Kid: kid, RequestedBy: &by, RequestedAt: &at})
}

func clientByID(ctx context.Context, q *gen.Queries, id string) (Client, error) {
	r, err := q.OAuthClient(ctx, id)
	if store.IsNoRows(err) {
		return Client{}, ErrNotFound
	}
	if err != nil {
		return Client{}, err
	}
	return clientFromRow(&r), nil
}

func signingKeys(ctx context.Context, q *gen.Queries) ([]KeyRow, error) {
	rows, err := q.SigningKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]KeyRow, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, KeyRow{
			KID: r.Kid, Purpose: r.Purpose, PublicJWK: r.PublicJwk, PrivateRef: r.PrivateRef,
			RegisteredAt: r.RegisteredAt, ActiveFrom: r.ActiveFrom, RetiredAt: r.RetiredAt,
			RequestedBy: deref(r.RequestedBy), RequestedAt: r.RequestedAt,
		})
	}
	return out, nil
}

func clientFromRow(r *gen.OauthClient) Client {
	return Client{
		ID: r.ClientID, System: r.System, Scopes: slices.Clone(r.Scopes), Audiences: slices.Clone(r.Audiences),
		AuthMethod: r.AuthMethod, SecretHash: deref(r.SecretHash), JWKS: r.Jwks,
		MTLSSubject: deref(r.MtlsSubject), CertificateID: deref(r.CertificateID), Status: r.Status, Note: r.Note,
		CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
	}
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optionalJSON(b json.RawMessage) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
