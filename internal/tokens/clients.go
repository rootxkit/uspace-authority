package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/passhash"
)

// Bounds of a client registration (E-10).
const (
	MaxAudiences       = 32
	MaxClientJWKSBytes = 16 << 10
	MaxClientJWKSKeys  = 8
	MaxNoteLen         = 1000
	MaxMTLSSubjectLen  = 512
	MaxCertificateID   = 64
	// SecretBytes is the entropy of a generated client secret (256 bits).
	SecretBytes = 32
)

// NewClient is a registration request.
type NewClient struct {
	ID            string
	Scopes        []string
	Audiences     []string
	AuthMethod    string
	JWKS          json.RawMessage
	MTLSSubject   string
	CertificateID string
	Note          string
}

// ClientPatch changes a client; nil fields stay.
type ClientPatch struct {
	Status    *string
	Scopes    *[]string
	Audiences *[]string
	Note      *string
}

// Registry is the client registry (oauth_clients).
type Registry struct {
	Store  Store
	Hasher *passhash.Hasher
	Now    func() time.Time
}

func (g *Registry) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// validateScopes checks a client's scope list: not empty, bounded,
// distinct, every scope grantable to clientID.
func validateScopes(clientID string, scopes []string) []error {
	var errs []error
	if len(scopes) == 0 {
		errs = append(errs, core.Fieldf("scopes", "at least one scope (least privilege, 06 §3)"))
	}
	if len(scopes) > MaxScopes {
		errs = append(errs, core.Fieldf("scopes", "more than %d scopes", MaxScopes))
		return errs
	}
	for i, s := range scopes {
		if err := CheckGrantable(s, clientID); err != nil {
			errs = append(errs, core.Fieldf("scopes["+strconv.Itoa(i)+"]", "%v", err))
		}
		if slices.Index(scopes, s) != i {
			errs = append(errs, core.Fieldf("scopes["+strconv.Itoa(i)+"]", "%s appears twice", quote(s)))
		}
	}
	return errs
}

// validateAudiences checks hosts in their normal form.
func validateAudiences(auds []string) []error {
	var errs []error
	if len(auds) > MaxAudiences {
		return []error{core.Fieldf("audiences", "more than %d audiences", MaxAudiences)}
	}
	for i, a := range auds {
		h, err := NormalizeAudience(a)
		switch {
		case err != nil:
			errs = append(errs, core.Fieldf("audiences["+strconv.Itoa(i)+"]", "%s is not a host name", quote(a)))
		case h != a:
			errs = append(errs, core.Fieldf("audiences["+strconv.Itoa(i)+"]", "write the host as %s", quote(h)))
		case slices.Index(auds, a) != i:
			errs = append(errs, core.Fieldf("audiences["+strconv.Itoa(i)+"]", "%s appears twice", quote(a)))
		}
	}
	return errs
}

// ValidateClientJWKS checks a private_key_jwt client's key set: a JSON
// JWKS of at most MaxClientJWKSKeys RSA public keys of at least
// auth.MinRSABits, each with a distinct kid, none carrying private key
// material, none for another algorithm or use. It returns the set.
func ValidateClientJWKS(raw json.RawMessage) (jwk.Set, error) {
	if len(raw) == 0 {
		return nil, core.Fieldf("jwks", "required for private_key_jwt")
	}
	if len(raw) > MaxClientJWKSBytes {
		return nil, core.Fieldf("jwks", "larger than %d bytes", MaxClientJWKSBytes)
	}
	set, err := jwk.Parse(raw)
	if err != nil {
		return nil, core.Fieldf("jwks", "not a JWK set")
	}
	if set.Len() == 0 || set.Len() > MaxClientJWKSKeys {
		return nil, core.Fieldf("jwks", "%d keys; between 1 and %d", set.Len(), MaxClientJWKSKeys)
	}
	seen := map[string]bool{}
	for i := range set.Len() {
		field := "jwks.keys[" + strconv.Itoa(i) + "]"
		k, _ := set.Key(i)
		kid, ok := k.KeyID()
		if !ok || kid == "" {
			return nil, core.Fieldf(field+".kid", "required")
		}
		if seen[kid] {
			return nil, core.Fieldf(field+".kid", "%s appears twice", quote(kid))
		}
		seen[kid] = true
		if _, isPriv := k.(jwk.RSAPrivateKey); isPriv {
			return nil, core.Fieldf(field, "carries private key material; register the public key only")
		}
		pub, isPub := k.(jwk.RSAPublicKey)
		if !isPub {
			return nil, core.Fieldf(field+".kty", "an RSA public key is required (RS256 only)")
		}
		if alg, ok := k.Algorithm(); ok && alg.String() != "RS256" {
			return nil, core.Fieldf(field+".alg", "%s; RS256 only", quote(alg.String()))
		}
		if use, ok := k.KeyUsage(); ok && use != "sig" {
			return nil, core.Fieldf(field+".use", "%s; sig only", quote(use))
		}
		n, ok := pub.N()
		if !ok || new(big.Int).SetBytes(n).BitLen() < auth.MinRSABits {
			return nil, core.Fieldf(field+".n", "shorter than %d bits", auth.MinRSABits)
		}
	}
	return set, nil
}

// validateClient checks a whole client row before it is written.
func validateClient(c *Client) error {
	var errs []error
	sys, err := SystemOf(c.ID)
	if err != nil {
		errs = append(errs, err)
	} else {
		c.System = sys
	}
	errs = append(errs, validateScopes(c.ID, c.Scopes)...)
	errs = append(errs, validateAudiences(c.Audiences)...)
	if !slices.Contains([]string{StatusActive, StatusSuspended, StatusRevoked}, c.Status) {
		errs = append(errs, core.Fieldf("status", "must be active, suspended or revoked"))
	}
	if len(c.Note) > MaxNoteLen {
		errs = append(errs, core.Fieldf("note", "longer than %d bytes", MaxNoteLen))
	}
	if len(c.MTLSSubject) > MaxMTLSSubjectLen {
		errs = append(errs, core.Fieldf("mtls_subject", "longer than %d bytes", MaxMTLSSubjectLen))
	}
	if len(c.CertificateID) > MaxCertificateID {
		errs = append(errs, core.Fieldf("certificate_id", "longer than %d bytes", MaxCertificateID))
	}
	return errors.Join(errs...)
}

// Create registers a client. For client_secret_post it generates the
// secret, stores its argon2id hash and returns the secret once.
func (g *Registry) Create(ctx context.Context, in NewClient, actor audit.Actor) (Client, string, error) {
	now := g.now()
	c := Client{
		ID: in.ID, Scopes: slices.Clone(in.Scopes), Audiences: slices.Clone(in.Audiences), AuthMethod: in.AuthMethod,
		MTLSSubject: in.MTLSSubject, CertificateID: in.CertificateID, Status: StatusActive, Note: in.Note,
		CreatedAt: now, CreatedBy: actor.ID, UpdatedAt: now, UpdatedBy: actor.ID,
	}
	if c.Audiences == nil {
		c.Audiences = []string{}
	}
	errs := []error{validateClient(&c)}
	var secret string
	switch in.AuthMethod {
	case MethodSecretPost:
		if len(in.JWKS) > 0 {
			errs = append(errs, core.Fieldf("jwks", "only for private_key_jwt"))
		}
		var b [SecretBytes]byte
		if _, err := rand.Read(b[:]); err != nil {
			return Client{}, "", err
		}
		secret = base64.RawURLEncoding.EncodeToString(b[:])
	case MethodPrivateKeyJWT:
		if _, err := ValidateClientJWKS(in.JWKS); err != nil {
			errs = append(errs, err)
		}
		c.JWKS = in.JWKS
	default:
		errs = append(errs, core.Fieldf("auth_method", "must be client_secret_post or private_key_jwt"))
	}
	if err := errors.Join(errs...); err != nil {
		return Client{}, "", err
	}
	if secret != "" {
		h, err := g.Hasher.Hash(secret)
		if err != nil {
			return Client{}, "", err
		}
		c.SecretHash = h
	}
	var out Client
	err := g.Store.InTx(ctx, func(tx Tx) error {
		if _, err := tx.Client(ctx, c.ID); err == nil {
			return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "the client exists",
				core.Fieldf("client_id", "%s is registered already", quote(c.ID)))
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		var err error
		if out, err = tx.InsertClient(ctx, c); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "oauth_client", EntityID: c.ID, EventType: audit.EventOAuthClientCreated,
			Payload: map[string]any{
				"client_id": c.ID, "system": c.System, "scopes": c.Scopes, "audiences": c.Audiences,
				"auth_method": c.AuthMethod, "certificate_id": c.CertificateID, "mtls_subject": c.MTLSSubject,
			},
		})
	})
	if err != nil {
		return Client{}, "", err
	}
	return out, secret, nil
}

// Update applies p. A status change takes effect on the next token
// request; issued tokens run to their exp.
func (g *Registry) Update(ctx context.Context, id string, p ClientPatch, actor audit.Actor) (Client, error) {
	var out Client
	err := g.Store.InTx(ctx, func(tx Tx) error {
		c, err := tx.Client(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return notFound(id)
		}
		if err != nil {
			return err
		}
		before := c
		if p.Status != nil {
			c.Status = *p.Status
		}
		if p.Scopes != nil {
			c.Scopes = slices.Clone(*p.Scopes)
		}
		if p.Audiences != nil {
			c.Audiences = slices.Clone(*p.Audiences)
			if c.Audiences == nil {
				c.Audiences = []string{}
			}
		}
		if p.Note != nil {
			c.Note = *p.Note
		}
		if err := validateClient(&c); err != nil {
			return err
		}
		c.UpdatedAt, c.UpdatedBy = g.now(), actor.ID
		if out, err = tx.UpdateClient(ctx, c); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "oauth_client", EntityID: id, EventType: audit.EventOAuthClientUpdated,
			Payload: map[string]any{
				"client_id": id,
				"before":    map[string]any{"status": before.Status, "scopes": before.Scopes, "audiences": before.Audiences},
				"after":     map[string]any{"status": c.Status, "scopes": c.Scopes, "audiences": c.Audiences},
			},
		})
	})
	if err != nil {
		return Client{}, err
	}
	return out, nil
}

// Get reads one client.
func (g *Registry) Get(ctx context.Context, id string) (Client, error) {
	c, err := g.Store.Client(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Client{}, notFound(id)
	}
	return c, err
}

// List reads every client.
func (g *Registry) List(ctx context.Context) ([]Client, error) { return g.Store.Clients(ctx) }

func notFound(id string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such client",
		core.Fieldf("client_id", "%s is not registered", quote(id)))
}

// String renders a client for logs without its secret hash or keys.
func (c Client) String() string {
	return fmt.Sprintf("client %s (%s, %s, %s)", c.ID, c.System, c.AuthMethod, c.Status)
}
