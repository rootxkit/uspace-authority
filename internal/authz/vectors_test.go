package authz

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/vectors"
)

type jwtFixtures struct {
	Issuer   string          `json:"issuer"`
	Audience string          `json:"audience"`
	MaxSkewS float64         `json:"max_skew_s"`
	JWKS     json.RawMessage `json:"jwks"`
}

type jwtInput struct {
	Token        string `json:"token"`
	NowS         int64  `json:"now_s"`
	RequireScope string `json:"require_scope"`
}

type jwtExpected struct {
	Accepted       bool     `json:"accepted"`
	Reason         string   `json:"reason"`
	Claim          string   `json:"claim"`
	Subject        string   `json:"subject"`
	Scopes         []string `json:"scopes"`
	RequireScopeOK *bool    `json:"require_scope_ok"`
}

// jwt_verify.json through this repository's wiring: the vector's issuer
// is configured as this system's own issuer (static keys, as
// tokens.Keys.TokenKeys supplies them), its audience as
// AUTHORITY_AUDIENCES, its skew as the verifier's. The test proves that
// the plumbing of authz.Verifier (routing by iss, StrictSessionClaims,
// the audience list) reaches core's verdicts, refusal reason and claim
// included; it re-implements no judgement.
func TestVectorsJWTVerifyThroughTheAuthorityWiring(t *testing.T) {
	f := vectors.Load(t, "jwt_verify.json")
	var fx jwtFixtures
	vectors.Unmarshal(t, f.Fixtures, &fx)
	set, err := jwk.Parse(fx.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in jwtInput
		var exp jwtExpected
		c.Decode(t, &in, &exp)
		now := time.Unix(in.NowS, 0).UTC()
		v, err := NewVerifier(context.Background(), VerifierConfig{
			SelfIssuer: fx.Issuer,
			SelfKeys:   func(time.Time) (jwk.Set, error) { return set, nil },
			Audiences:  []string{fx.Audience},
			MaxSkew:    time.Duration(fx.MaxSkewS * float64(time.Second)),
			Now:        func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		claims, err := v.Verify(context.Background(), in.Token)
		if got := err == nil; got != exp.Accepted {
			t.Fatalf("accepted %v, want %v (err %v)", got, exp.Accepted, err)
		}
		if !exp.Accepted {
			var te *auth.TokenError
			if !errors.As(err, &te) {
				t.Fatalf("error %T is not a *auth.TokenError", err)
			}
			if te.Counter != exp.Reason || te.Claim != exp.Claim {
				t.Errorf("refused %s on %s, want %s on %s", te.Counter, te.Claim, exp.Reason, exp.Claim)
			}
			if v.Counters().Get(exp.Reason) != 1 {
				t.Errorf("counter %s not counted: %v", exp.Reason, v.Counters().Snapshot())
			}
			return
		}
		if claims.Subject != exp.Subject || !slices.Equal(claims.Scopes, exp.Scopes) {
			t.Errorf("subject %q scopes %q, want %q %q", claims.Subject, claims.Scopes, exp.Subject, exp.Scopes)
		}
		if exp.RequireScopeOK != nil {
			if got := auth.RequireScope(claims, in.RequireScope) == nil; got != *exp.RequireScopeOK {
				t.Errorf("RequireScope(%q) ok %v, want %v", in.RequireScope, got, *exp.RequireScopeOK)
			}
		}
	})
}
