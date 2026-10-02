package tokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// Key purposes (signing_keys.purpose).
const (
	PurposeToken       = "token"
	PurposePublication = "publication"
)

// MaxKeyFileBytes bounds a PEM file read at start.
const MaxKeyFileBytes = 64 << 10

// KeyFile is one RSA private key loaded from a PEM file. The private key
// lives in memory only: never in the database, never in a log.
type KeyFile struct {
	// Ref is the reference as configured (the file path).
	Ref string
	// KID is the RFC 7638 SHA-256 thumbprint of the public key,
	// base64url: the same key always has the same kid, on every replica.
	KID string
	Key *rsa.PrivateKey
	// PublicJWK is the JWK the JWKS publishes (kty, n, e, kid, alg RS256,
	// use sig), as core's KeyRing renders it.
	PublicJWK json.RawMessage
}

// LoadKeyFile reads ref, a PEM file holding one RSA private key
// (PKCS #1 "RSA PRIVATE KEY" or PKCS #8 "PRIVATE KEY"), and checks it as
// core's issuer checks a signing key (at least 2048 bits, valid). field
// names the configuration variable in errors. A kms: reference is
// refused: this build has no KMS client (the reference is accepted in
// signing_keys.private_ref so a later build can add one).
func LoadKeyFile(field, ref string) (KeyFile, error) {
	if strings.HasPrefix(ref, "kms:") {
		return KeyFile{}, core.Fieldf(field, "%s is a KMS reference; this build loads PEM files only", quote(ref))
	}
	f, err := os.Open(ref) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return KeyFile{}, core.Fieldf(field, "%s cannot be read: %v", quote(ref), errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, MaxKeyFileBytes+1))
	if err != nil {
		return KeyFile{}, core.Fieldf(field, "%s cannot be read", quote(ref))
	}
	if len(raw) > MaxKeyFileBytes {
		return KeyFile{}, core.Fieldf(field, "%s is larger than %d bytes", quote(ref), MaxKeyFileBytes)
	}
	key, err := ParsePrivateKeyPEM(raw)
	if err != nil {
		return KeyFile{}, core.Fieldf(field, "%s: %v", quote(ref), err)
	}
	kf, err := NewKeyFile(ref, key)
	if err != nil {
		return KeyFile{}, core.Fieldf(field, "%s: %v", quote(ref), err)
	}
	return kf, nil
}

// ParsePrivateKeyPEM parses exactly one PEM block holding an RSA private
// key. Encrypted PEM (a Proc-Type header) is refused.
func ParsePrivateKeyPEM(raw []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("more than one PEM block")
	}
	if _, enc := block.Headers["Proc-Type"]; enc {
		return nil, errors.New("encrypted PEM is not supported; decrypt it into a file readable by api only")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a PKCS #1 RSA private key")
		}
		return k, nil
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a PKCS #8 private key")
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("a %T, not an RSA key (RS256 only)", k)
		}
		return rk, nil
	default:
		return nil, fmt.Errorf("PEM block %s is not a private key", quote(block.Type))
	}
}

// NewKeyFile derives the kid and the public JWK of key, checking it
// through core's KeyRing (at least auth.MinRSABits, rsa Validate).
func NewKeyFile(ref string, key *rsa.PrivateKey) (KeyFile, error) {
	if key == nil {
		return KeyFile{}, errors.New("no key")
	}
	kid, err := Thumbprint(&key.PublicKey)
	if err != nil {
		return KeyFile{}, err
	}
	ring, err := auth.NewKeyRing(auth.SigningKey{KID: kid, Key: key})
	if err != nil {
		return KeyFile{}, err
	}
	set := ring.JWKS()
	pub, ok := set.Key(0)
	if !ok {
		return KeyFile{}, errors.New("the key ring published no key")
	}
	b, err := json.Marshal(pub)
	if err != nil {
		return KeyFile{}, err
	}
	return KeyFile{Ref: ref, KID: kid, Key: key, PublicJWK: b}, nil
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint of pub, base64url.
func Thumbprint(pub *rsa.PublicKey) (string, error) {
	k, err := jwk.Import(pub)
	if err != nil {
		return "", err
	}
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// KeyRow is a row of signing_keys.
type KeyRow struct {
	KID          string
	Purpose      string
	PublicJWK    json.RawMessage
	PrivateRef   string
	RegisteredAt time.Time
	ActiveFrom   *time.Time
	RetiredAt    *time.Time
	RequestedBy  string
	RequestedAt  *time.Time
}

// Active reports whether the key signs (activated, not retired).
func (r KeyRow) Active() bool { return r.ActiveFrom != nil && r.RetiredAt == nil }

// Published reports whether the JWKS lists the key at now: active, or
// retired less than grace ago.
func (r KeyRow) Published(now time.Time, grace time.Duration) bool {
	if r.ActiveFrom == nil {
		return false
	}
	return r.RetiredAt == nil || now.Before(r.RetiredAt.Add(grace))
}

// State names the row's state at now for the admin listing.
func (r KeyRow) State(now time.Time, grace time.Duration) string {
	switch {
	case r.Active():
		return "active"
	case r.ActiveFrom != nil && r.Published(now, grace):
		return "retiring"
	case r.ActiveFrom != nil:
		return "retired"
	case r.RequestedAt != nil:
		return "requested"
	default:
		return "candidate"
	}
}

// Issued is a signed machine token with the claims the audit needs.
type Issued struct {
	Token     string
	JTI       string
	KID       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionClaims are table A's console session claims (M20).
type SessionClaims struct {
	Subject   string
	Audience  string
	Roles     []string
	Realm     string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SessionScope is the scope claim of every session token.
const SessionScope = "session"

// Keys is the signing state of this issuer: the token-signing key files
// configured, the publication key, and the signing_keys rows last read.
// It signs with the active token key and renders the JWKS. Safe for
// concurrent use; Apply swaps the state atomically.
type Keys struct {
	issuer string
	grace  time.Duration
	files  map[string]KeyFile // token keys by kid
	order  []string           // kids in SIGNING_KEY_FILES order
	pub    *KeyFile           // publication key, optional
	pubJWK jwk.Key            // its public JWK

	mu     sync.RWMutex
	rows   []KeyRow
	active *activeKey

	// Counters counts stored keys left out of the JWKS
	// (signing_key_rejected); nil counts nothing.
	Counters *core.Counters
}

// CounterKeyRejected counts a signing_keys row left out of the JWKS
// because its public JWK does not parse or is not the key its kid names.
const CounterKeyRejected = "signing_key_rejected"

// PublicJWK is the JWK to publish for a stored row: the public part
// only (jwk.PublicKeyOf drops any private member a tampered or mistaken
// row carries), RSA, with alg RS256 and use sig set here, and only when
// kid is the RFC 7638 thumbprint of that public key, so a row cannot
// publish one key under another key's kid.
func PublicJWK(raw []byte, kid string) (jwk.Key, error) {
	stored, err := jwk.ParseKey(raw)
	if err != nil {
		return nil, fmt.Errorf("the stored public JWK does not parse: %w", err)
	}
	pub, err := jwk.PublicKeyOf(stored)
	if err != nil {
		return nil, fmt.Errorf("the stored JWK has no public key: %w", err)
	}
	if _, ok := pub.(jwk.RSAPublicKey); !ok {
		return nil, errors.New("the stored JWK is not an RSA key")
	}
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(tp) != kid {
		return nil, errors.New("the kid is not the thumbprint of the stored key")
	}
	for name, v := range map[string]any{jwk.KeyIDKey: kid, jwk.AlgorithmKey: jwa.RS256(), jwk.KeyUsageKey: "sig"} {
		if err := pub.Set(name, v); err != nil {
			return nil, err
		}
	}
	return pub, nil
}

type activeKey struct {
	file   KeyFile
	priv   jwk.Key
	issuer *auth.Issuer
}

// NewKeys holds the configured key files. tokenFiles must not be empty
// and must not repeat a key; pub may be nil. A key may serve one purpose
// only.
func NewKeys(issuer string, grace time.Duration, tokenFiles []KeyFile, pub *KeyFile) (*Keys, error) {
	if issuer == "" {
		return nil, core.Fieldf("ISSUER_URL", "empty")
	}
	if len(tokenFiles) == 0 {
		return nil, core.Fieldf("SIGNING_KEY_FILES", "required: the issuer cannot sign without a key")
	}
	k := &Keys{issuer: issuer, grace: grace, files: map[string]KeyFile{}}
	for _, f := range tokenFiles {
		if _, dup := k.files[f.KID]; dup {
			return nil, core.Fieldf("SIGNING_KEY_FILES", "%s holds the same key as an earlier file", quote(f.Ref))
		}
		k.files[f.KID] = f
		k.order = append(k.order, f.KID)
	}
	if pub != nil {
		if _, dup := k.files[pub.KID]; dup {
			return nil, core.Fieldf("PUBLICATION_KEY_FILE", "is also a token-signing key; a key serves one purpose")
		}
		pk, err := jwk.ParseKey(pub.PublicJWK)
		if err != nil {
			return nil, core.Fieldf("PUBLICATION_KEY_FILE", "%v", err)
		}
		p := *pub
		k.pub, k.pubJWK = &p, pk
	}
	return k, nil
}

// Issuer is the iss of every token.
func (k *Keys) Issuer() string { return k.issuer }

// Grace is how long a retired key stays published.
func (k *Keys) Grace() time.Duration { return k.grace }

// Files returns the token key files in configured order.
func (k *Keys) Files() []KeyFile {
	out := make([]KeyFile, 0, len(k.order))
	for _, kid := range k.order {
		out = append(out, k.files[kid])
	}
	return out
}

// Publication returns the publication key, if configured.
func (k *Keys) Publication() *KeyFile { return k.pub }

// PublicationRing returns a core KeyRing holding the publication key, for
// SignDetached (WP-6), or nil when none is configured.
func (k *Keys) PublicationRing() (*auth.KeyRing, error) {
	if k.pub == nil {
		return nil, nil
	}
	return auth.NewKeyRing(auth.SigningKey{KID: k.pub.KID, Key: k.pub.Key})
}

// ErrNoActiveKey is the state without an active token key whose file is
// configured.
var ErrNoActiveKey = errors.New("no active token-signing key with its file configured")

// Apply installs rows (signing_keys as read) as the current state. The
// active token key must be one of the configured files; otherwise the
// previous state is kept and ErrNoActiveKey returned (a replica that
// lacks the key another replica rotated to keeps signing with what it
// has, and says so).
func (k *Keys) Apply(rows []KeyRow) error {
	var act *KeyRow
	for i := range rows {
		if rows[i].Purpose == PurposeToken && rows[i].Active() {
			act = &rows[i]
			break
		}
	}
	if act == nil {
		return fmt.Errorf("%w: no token key is active in signing_keys", ErrNoActiveKey)
	}
	f, ok := k.files[act.KID]
	if !ok {
		return fmt.Errorf("%w: the active kid %s is not in SIGNING_KEY_FILES", ErrNoActiveKey, act.KID)
	}
	k.mu.RLock()
	same := k.active != nil && k.active.file.KID == f.KID
	k.mu.RUnlock()
	var ak *activeKey
	if !same {
		priv, err := jwk.Import(f.Key)
		if err != nil {
			return err
		}
		if err := priv.Set(jwk.KeyIDKey, f.KID); err != nil {
			return err
		}
		iss, err := auth.NewIssuer(k.issuer, f.Key, f.KID)
		if err != nil {
			return err
		}
		ak = &activeKey{file: f, priv: priv, issuer: iss}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.rows = slices.Clone(rows)
	if ak != nil {
		k.active = ak
	}
	return nil
}

// Rows returns the signing_keys rows last applied.
func (k *Keys) Rows() []KeyRow {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return slices.Clone(k.rows)
}

// ActiveKID is the kid that signs, or "" before Apply.
func (k *Keys) ActiveKID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return ""
	}
	return k.active.file.KID
}

func (k *Keys) current() (*activeKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == nil {
		return nil, ErrNoActiveKey
	}
	return k.active, nil
}

// Issue signs an ecosystem machine token (table A) through core's
// Issuer: iss, sub, aud, scope, iat, exp, a random jti and kid.
func (k *Keys) Issue(sub, aud string, scopes []string, ttl time.Duration, now time.Time) (Issued, error) {
	a, err := k.current()
	if err != nil {
		return Issued{}, err
	}
	tok, err := a.issuer.Issue(sub, aud, scopes, ttl, now)
	if err != nil {
		return Issued{}, err
	}
	// Read back the jti and times core chose, for the audit row: the
	// token is this process's own output, so its payload is decoded, not
	// verified.
	var cl struct {
		JTI string `json:"jti"`
		IAT int64  `json:"iat"`
		EXP int64  `json:"exp"`
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Issued{}, errors.New("issuer returned a token that is not three parts")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(raw, &cl) != nil || cl.JTI == "" {
		return Issued{}, errors.New("issuer returned a token without a readable jti")
	}
	return Issued{Token: tok, JTI: cl.JTI, KID: a.file.KID, IssuedAt: time.Unix(cl.IAT, 0).UTC(), ExpiresAt: time.Unix(cl.EXP, 0).UTC()}, nil
}

// sessionPayload is table A's session row, exactly: iss, aud, sub,
// scope = "session", roles, realm, iat, exp, jti (kid in the header).
type sessionPayload struct {
	Issuer    string   `json:"iss"`
	Audience  string   `json:"aud"`
	Subject   string   `json:"sub"`
	Scope     string   `json:"scope"`
	Roles     []string `json:"roles"`
	Realm     string   `json:"realm"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
	JTI       string   `json:"jti"`
}

// SignSession signs a console session token (table A, M20) with the
// active token key. Core's Issuer has no roles or realm, so the payload
// is marshalled here and signed by jwx with RS256 and the kid header,
// the same form core's Issuer and SignCompact produce; core's Verifier
// with StrictSessionClaims verifies it.
func (k *Keys) SignSession(c SessionClaims) (string, error) {
	switch {
	case c.Subject == "":
		return "", core.Fieldf("sub", "empty")
	case c.Audience == "":
		return "", core.Fieldf("aud", "empty")
	case c.JTI == "":
		return "", core.Fieldf("jti", "empty")
	case c.Realm == "":
		return "", core.Fieldf("realm", "empty")
	case !c.ExpiresAt.After(c.IssuedAt):
		return "", core.Fieldf("exp", "not after iat")
	}
	a, err := k.current()
	if err != nil {
		return "", err
	}
	roles := c.Roles
	if roles == nil {
		roles = []string{}
	}
	payload, err := json.Marshal(sessionPayload{
		Issuer: k.issuer, Audience: c.Audience, Subject: c.Subject, Scope: SessionScope,
		Roles: roles, Realm: c.Realm, IssuedAt: c.IssuedAt.Unix(), ExpiresAt: c.ExpiresAt.Unix(), JTI: c.JTI,
	})
	if err != nil {
		return "", err
	}
	hdr := jws.NewHeaders()
	if err := hdr.Set(jws.KeyIDKey, a.file.KID); err != nil {
		return "", err
	}
	if err := hdr.Set(jws.TypeKey, "JWT"); err != nil {
		return "", err
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), a.priv, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// JWKS is the set this issuer publishes at now: token keys that are
// active or retired less than the grace ago, then the publication key.
func (k *Keys) JWKS(now time.Time) (jwk.Set, error) {
	set, err := k.TokenKeys(now)
	if err != nil {
		return nil, err
	}
	if k.pubJWK != nil {
		c, err := k.pubJWK.Clone()
		if err != nil {
			return nil, err
		}
		if err := set.AddKey(c); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// TokenKeys is the set a verifier of this issuer's tokens uses at now:
// the token keys of JWKS without the publication key, which signs
// publications and never a token.
func (k *Keys) TokenKeys(now time.Time) (jwk.Set, error) {
	set := jwk.NewSet()
	rowsCopy := k.Rows()
	for ri := range rowsCopy {
		r := &rowsCopy[ri]
		if r.Purpose != PurposeToken || !r.Published(now, k.grace) {
			continue
		}
		key, err := PublicJWK(r.PublicJWK, r.KID)
		if err != nil {
			// One bad row never takes the whole JWKS down: it is left
			// out and counted.
			if k.Counters != nil {
				k.Counters.Inc(CounterKeyRejected)
			}
			continue
		}
		if err := set.AddKey(key); err != nil {
			return nil, err
		}
	}
	return set, nil
}

// NextCandidate is the first configured token key never activated: the
// key a rotation activates.
func NextCandidate(order []string, rows []KeyRow) (KeyRow, bool) {
	for _, kid := range order {
		for ri := range rows {
			r := &rows[ri]
			if r.KID == kid && r.Purpose == PurposeToken && r.ActiveFrom == nil {
				return *r, true
			}
		}
	}
	return KeyRow{}, false
}

// NewID is 128 random bits in hex: account ids, session ids.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
