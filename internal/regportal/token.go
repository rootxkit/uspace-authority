package regportal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// KeyBytes is the length of the portal key.
const KeyBytes = 32

// MaxTokenBytes bounds a link token (the contract's maxLength).
const MaxTokenBytes = 512

// Token purposes: what a link may do. A token of one purpose is never
// accepted for another.
const (
	PurposeApplication = "application"   // the applicant's link: verify, then read the state
	PurposeOperator    = "operator_link" // an operator's single-use occurrence-report link
)

// tokenVersion prefixes every token, so a later format is told apart.
const tokenVersion = "v1"

// Claims is what a link token says. Exp is Unix seconds; the caller
// compares it with the database clock (never the replica's).
type Claims struct {
	Purpose string `json:"p"`
	// Subject is the application id, or the operator id of a link.
	Subject string `json:"s"`
	// Link is a link's own id (single use, registry_portal_links_used).
	Link string `json:"j,omitempty"`
	// Number is a link's registration public part (reporter_org).
	Number string `json:"n,omitempty"`
	Exp    int64  `json:"e"`
}

// Expires is Exp as a time.
func (c Claims) Expires() time.Time { return time.Unix(c.Exp, 0).UTC() }

// ErrToken is a token that does not verify: malformed, of another
// purpose, or not signed with this key.
var ErrToken = errors.New("the link token does not verify")

// Signer signs and verifies the portal's link tokens (HMAC-SHA-256 under
// REGISTRY_PORTAL_KEY_FILE) and keys the address hashes of its budgets.
// A token is a capability mailed to an address: whoever reads the mail
// holds it, which is the whole of the applicant's authentication (plan
// Q-A17: no accounts).
type Signer struct{ key []byte }

// NewSigner builds a signer from a 32-byte key.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) != KeyBytes {
		return nil, core.Fieldf("REGISTRY_PORTAL_KEY_FILE", "the key is %d bytes, not %d", len(key), KeyBytes)
	}
	return &Signer{key: append([]byte(nil), key...)}, nil
}

// LoadSigner reads the key from path: 32 bytes of standard base64 on one
// line (openssl rand -base64 32).
func LoadSigner(path string) (*Signer, error) {
	key, err := LoadKey("REGISTRY_PORTAL_KEY_FILE", path)
	if err != nil {
		return nil, err
	}
	return NewSigner(key)
}

// LoadKey reads one line of base64 from path, naming variable on error.
func LoadKey(variable, path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return nil, core.Fieldf(variable, "%q cannot be read: %v", path, errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, core.Fieldf(variable, "%q cannot be read", path)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, core.Fieldf(variable, "%q is not one line of base64 (openssl rand -base64 32)", path)
	}
	return key, nil
}

func (s *Signer) mac(domain string, b []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	m.Write(b)
	return m.Sum(nil)
}

// Sign returns the token of c.
func (s *Signer) Sign(c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString(s.mac("regportal:token:"+tokenVersion, []byte(p)))
	return tokenVersion + "." + p + "." + sig, nil
}

// Verify checks tok's signature and purpose and returns its claims. It
// does not judge the expiry: the caller compares Exp with the database
// clock.
func (s *Signer) Verify(tok, purpose string) (Claims, error) {
	if len(tok) > MaxTokenBytes {
		return Claims{}, ErrToken
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return Claims{}, ErrToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, s.mac("regportal:token:"+tokenVersion, []byte(parts[1]))) {
		return Claims{}, ErrToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrToken
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil || c.Purpose != purpose || c.Subject == "" || c.Exp <= 0 {
		return Claims{}, ErrToken
	}
	return c, nil
}

// Hash is the keyed hash of a budget key (a client address, an operator
// id): the database counts requests without holding the address.
func (s *Signer) Hash(domain, value string) string {
	return hex.EncodeToString(s.mac("regportal:hash:"+domain, []byte(value)))
}
