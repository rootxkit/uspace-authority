package certs

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/tokens"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

// The ANSP of these tests: its public host and a lab alias, its
// ANSP_AUDIENCES (M18).
const (
	anspHost  = "ansp.example.test"
	anspAlias = "ansp"
)

// anspRoute is one ANSP operation a USSP calls (02 F4, F13).
type anspRoute struct{ path, method string }

var usspANSPRoutes = []anspRoute{
	{"/v1/manned-traffic/snapshot", "get"},
	{"/v1/manned-traffic/stream", "get"},
	{"/v1/coordination/notices", "post"},
	{"/v1/coordination/notices/{ack_id}", "get"},
}

// anspScopes reads the scopes the ANSP's token rule demands of an
// operation from its published contract (api/clients/ansp.yaml, the
// pinned copy; x-auth "token:<scope>[+<scope>...][+mtls][ or ...]"), so
// the test follows the ANSP rather than a list written here.
func anspScopes(t *testing.T, r anspRoute) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", "api", "clients", "ansp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	inPath, inOp := false, false
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "  /"):
			inPath, inOp = line == "  "+r.path+":", false
		case inPath && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     "):
			inOp = strings.TrimSpace(line) == r.method+":"
		case inPath && inOp && strings.HasPrefix(line, "      x-auth: "):
			for _, alt := range strings.Split(strings.TrimPrefix(line, "      x-auth: "), " or ") {
				if rest, ok := strings.CutPrefix(alt, "token:"); ok {
					return slices.DeleteFunc(strings.Split(rest, "+"), func(s string) bool { return s == "mtls" })
				}
			}
			t.Fatalf("%s %s admits no machine token", r.method, r.path)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("%s %s is not in api/clients/ansp.yaml", r.method, r.path)
	return nil
}

// anspVerifier is the ANSP's machine verifier (uspace-ansp
// internal/config VerifierConfig): core's Verifier, this issuer on its
// ANSP_TOKEN_ISSUERS with its published JWKS, ANSP_AUDIENCES its host
// and lab alias, StrictSessionClaims.
func anspVerifier(t *testing.T, keys *tokens.Keys) *auth.Verifier {
	t.Helper()
	set, err := keys.JWKS(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers:             map[string]auth.IssuerConfig{issuer: {Keys: set}},
		Audiences:           []string{anspHost, anspAlias},
		StrictSessionClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Audit H-3: a USSP certified here asks this token service for the
// ANSP's scopes with aud the ANSP's host, as uspace-ussp does
// (internal/manned ansp.traffic, internal/coordination
// ansp.coordination), and the token passes the ANSP's verifier and the
// token rule of every ANSP route a USSP calls. Beside it, the refusals:
// an audience off the client's list, a scope the client does not hold,
// and the ANSP's verifier refusing a token issued for another host.
func TestIntegrationUSSPTokenIsAcceptedByTheANSP(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	w := audit.NewWriter(r.db)
	hasher, err := passhash.New(passhash.Params{MemoryKiB: 64, Time: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	parts, err := tokens.Assemble(ctx, tokens.Setup{
		Issuer: issuer, SigningKeyFiles: []string{tokentest.WriteKey(t, t.TempDir(), 0)}, TTL: time.Hour,
		RetireGrace: 24 * time.Hour, ConfirmWindow: 10 * time.Minute, RatePerMin: 600, RateBurst: 100, RateMaxClients: 100,
		Store: tokens.PG{DB: r.db, Audit: w}, Hasher: hasher, Logger: logging.Discard(),
	})
	if err != nil {
		t.Fatal(err)
	}
	is, err := r.svc.Issue(ctx, ussp("DEV01"), admin)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(is.Client.Audiences, anspHost) {
		t.Fatalf("the client cannot name the ANSP: %v", is.Client.Audiences)
	}
	ask := func(scope, aud string) (tokens.TokenResponse, *tokens.OAuthError) {
		return parts.Service.Token(ctx, tokens.TokenRequest{
			GrantType: tokens.GrantClientCredentials, ClientID: is.Client.ID, ClientSecret: is.Secret, HasSecret: true,
			Scope: scope, Audience: aud, HasAudience: true,
		})
	}
	v := anspVerifier(t, parts.Keys)

	for _, rt := range usspANSPRoutes {
		need := anspScopes(t, rt)
		tok, oerr := ask(strings.Join(need, " "), "https://"+anspHost)
		if oerr != nil {
			t.Fatalf("%s %s: token for %v refused: %+v", rt.method, rt.path, need, oerr)
		}
		c, err := v.Verify(ctx, tok.AccessToken)
		if err != nil {
			t.Fatalf("%s %s: the ANSP's verifier refuses the token: %v", rt.method, rt.path, err)
		}
		if c.Issuer != issuer || c.Subject != "ussp-DEV01-01" || c.Audience != anspHost || c.JTI == "" {
			t.Fatalf("%s %s: claims %+v", rt.method, rt.path, c)
		}
		for _, s := range need {
			if !slices.Contains(c.Scopes, s) {
				t.Fatalf("%s %s: the token lacks %s: %v", rt.method, rt.path, s, c.Scopes)
			}
		}
	}

	// An audience off the client's list, for a national scope.
	if _, oerr := ask("ansp.traffic", "https://elsewhere.example.test"); oerr == nil || oerr.Reason != tokens.ReasonAudienceNotAllowed {
		t.Fatalf("another host: %+v", oerr)
	}
	// A scope no USSP holds (ansp.requests is the authority's, F11).
	if _, oerr := ask("ansp.requests", "https://"+anspHost); oerr == nil || oerr.Reason != tokens.ReasonScopeNotAllowed {
		t.Fatalf("ansp.requests: %+v", oerr)
	}
	// A token issued for the CISP is not the ANSP's.
	tok, oerr := ask("cis.read", "https://cisp.example.test")
	if oerr != nil {
		t.Fatalf("cis.read: %+v", oerr)
	}
	if _, err := v.Verify(ctx, tok.AccessToken); err == nil {
		t.Fatal("the ANSP's verifier accepts a token for the CISP's host")
	}
}
