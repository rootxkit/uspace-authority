package tokens

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// AssertionType is RFC 7523's client_assertion_type.
const AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// MaxAssertionLifetime bounds exp - now of a client assertion: an
// assertion is minted for one request (RFC 7523 §3 lets the server
// limit it).
const MaxAssertionLifetime = 5 * time.Minute

// Counter of client assertions.
const (
	CounterReplayed = "assertion_replayed" // an assertion id used twice
)

// UnverifiedIssuer reads the iss of a compact JWT without verifying it,
// only to choose whose keys verify it (a client assertion's client, a
// bearer token's issuer); core's Verifier then checks iss against
// exactly that issuer. Anything unreadable returns "".
func UnverifiedIssuer(assertion string) string {
	if len(assertion) > auth.DefaultMaxTokenBytes {
		return ""
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var cl struct {
		Iss json.RawMessage `json:"iss"`
	}
	if json.Unmarshal(raw, &cl) != nil {
		return ""
	}
	var iss string
	if json.Unmarshal(cl.Iss, &iss) != nil {
		return ""
	}
	return iss
}

// VerifyAssertion verifies a private_key_jwt client assertion of client
// c with core's Verifier: RS256 only, kid in the client's registered
// JWKS, iss and sub both the client id, aud one of audiences (this
// issuer and its token endpoint), exp within MaxAssertionLifetime, a
// jti. It returns the jti and exp for the replay memory.
func VerifyAssertion(ctx context.Context, c ClientRecord, assertion string, audiences []string, now time.Time) (jti string, exp time.Time, err error) {
	set, err := ValidateClientJWKS(c.JWKS)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("the client's registered JWKS is unusable: %w", err)
	}
	v, err := auth.NewVerifier(ctx, auth.Config{
		Issuers:             map[string]auth.IssuerConfig{c.ID: {Keys: set}},
		Audiences:           audiences,
		StrictSessionClaims: true,
		Now:                 func() time.Time { return now },
	})
	if err != nil {
		return "", time.Time{}, err
	}
	cl, err := v.Verify(ctx, assertion)
	if err != nil {
		return "", time.Time{}, err
	}
	if cl.Subject != c.ID {
		return "", time.Time{}, core.Fieldf("client_assertion", "sub is not the client id")
	}
	if cl.ExpiresAt.Sub(now) > MaxAssertionLifetime {
		return "", time.Time{}, core.Fieldf("client_assertion", "exp is more than %s ahead", MaxAssertionLifetime)
	}
	return cl.JTI, cl.ExpiresAt, nil
}

// MaxAssertionJTI bounds the jti of an assertion.
const MaxAssertionJTI = 256
