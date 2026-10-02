package authz

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// The session contract of every uspace system (M21, M22;
// docs/runbooks/session-contract.md).
const (
	CookieSession = "uspace_session"
	CookieCSRF    = "uspace_csrf"
	HeaderCSRF    = "X-CSRF-Token"
)

// Authenticator resolves the identity of a request from its bearer
// token: a console session of this issuer (checked against the
// sessions table) or an ecosystem machine token.
type Authenticator struct {
	Verifier *Verifier
	Sessions *Service
	// SelfIssuer is this issuer: sessions are accepted from it only.
	SelfIssuer string
}

// Identify is the apiserver.IdentifyFunc of api.
func (a *Authenticator) Identify(r *http.Request) (apiserver.Identity, error) {
	vals := r.Header.Values("Authorization")
	if len(vals) == 0 {
		return apiserver.Identity{}, errors.New("no bearer token: sign in through /v1/auth/login")
	}
	if len(vals) > 1 {
		return apiserver.Identity{}, errors.New("more than one Authorization header")
	}
	scheme, token, ok := strings.Cut(vals[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
		return apiserver.Identity{}, errors.New("the Authorization header is not a bearer token")
	}
	return a.IdentifyToken(r.Context(), strings.TrimSpace(token))
}

// IdentifyToken verifies token with core (through Verifier) and, for a
// session, checks the session row. The error never contains the token.
func (a *Authenticator) IdentifyToken(ctx context.Context, token string) (apiserver.Identity, error) {
	cl, err := a.Verifier.Verify(ctx, token)
	if err != nil {
		var te *auth.TokenError
		if errors.As(err, &te) {
			return apiserver.Identity{}, fmt.Errorf("token refused: %s", te.Error())
		}
		return apiserver.Identity{}, errors.New("token refused")
	}
	if !cl.HasScope(tokens.SessionScope) {
		return apiserver.Identity{ActorType: "client", Subject: cl.Subject, Scopes: cl.Scopes, Issuer: cl.Issuer, JTI: cl.JTI}, nil
	}
	return a.session(ctx, cl)
}

// session checks a token claiming scope "session": issued here, carrying
// no other scope, a known realm, and a live session row.
func (a *Authenticator) session(ctx context.Context, cl auth.Claims) (apiserver.Identity, error) {
	switch {
	case cl.Issuer != a.SelfIssuer:
		return apiserver.Identity{}, errors.New("token refused: a session of another issuer")
	case len(cl.Scopes) != 1:
		return apiserver.Identity{}, errors.New("token refused: a session token carries scope \"session\" alone")
	case cl.Realm != apiserver.RealmConsole && cl.Realm != apiserver.RealmPolice:
		return apiserver.Identity{}, errors.New("token refused: unknown realm")
	}
	sess, err := a.Sessions.CheckSession(ctx, cl.JTI, cl.Subject)
	if err != nil {
		if errors.Is(err, ErrSessionRefused) {
			return apiserver.Identity{}, err
		}
		return apiserver.Identity{}, errors.New("the session could not be checked")
	}
	return apiserver.Identity{
		ActorType: "user", Subject: sess.UserID, Roles: sess.Roles, Realm: sess.Realm, Session: true, JTI: sess.JTI, Issuer: cl.Issuer,
	}, nil
}

// FromCookie is the WebSocket rule of M22: a same-origin upgrade carries
// the uspace_session cookie, its Origin must be on the allow-list (exact
// scheme://host[:port]), and the token must be a session (scope
// "session"; a machine token in the cookie is refused). picture-ws
// (WP-13) uses it; no ticket in a query string.
func (a *Authenticator) FromCookie(r *http.Request, allowedOrigins []string) (apiserver.Identity, error) {
	origin := r.Header.Get("Origin")
	if origin == "" || !slices.Contains(allowedOrigins, origin) {
		return apiserver.Identity{}, errors.New("the Origin is not allowed")
	}
	c, err := r.Cookie(CookieSession)
	if err != nil || c.Value == "" {
		return apiserver.Identity{}, errors.New("no " + CookieSession + " cookie")
	}
	id, err := a.IdentifyToken(r.Context(), c.Value)
	if err != nil {
		return apiserver.Identity{}, err
	}
	if !id.Session {
		return apiserver.Identity{}, errors.New("the " + CookieSession + " cookie holds a token whose scope is not \"session\"")
	}
	return id, nil
}

// CheckCSRF is the double-submit check of M21 for a state-changing
// request that carries the session in a cookie: the X-CSRF-Token header
// equals the uspace_csrf cookie (constant time), both present. Safe
// methods pass.
func CheckCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	c, err := r.Cookie(CookieCSRF)
	h := r.Header.Get(HeaderCSRF)
	if err != nil || c.Value == "" || h == "" {
		return errors.New("the CSRF cookie or header is missing")
	}
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(h)) != 1 {
		return errors.New("the CSRF header does not match its cookie")
	}
	return nil
}

// MaxPurposeLen bounds a purpose.
const MaxPurposeLen = 200

type purposeKey struct{}

// PurposeFrom is the purpose RequirePurpose admitted.
func PurposeFrom(ctx context.Context) string {
	p, _ := ctx.Value(purposeKey{}).(string)
	return p
}

// ParsePurpose reads the purpose query parameter of a PII read
// (CLAUDE.md rule 6): required, at most MaxPurposeLen characters, no
// control characters.
func ParsePurpose(r *http.Request) (string, error) {
	p := strings.TrimSpace(r.URL.Query().Get("purpose"))
	switch {
	case p == "":
		return "", core.Fieldf("purpose", "required: this operation reads personal data")
	case len([]rune(p)) > MaxPurposeLen:
		return "", core.Fieldf("purpose", "longer than %d characters", MaxPurposeLen)
	case strings.IndexFunc(p, unicode.IsControl) >= 0:
		return "", core.Fieldf("purpose", "contains a control character")
	}
	return p, nil
}

// RequirePurpose refuses (400) the operations of ops without a purpose
// and hands the purpose to the handler (PurposeFrom) for its events row.
// The operations are those whose x-audit says purpose: required.
func RequirePurpose(ops map[string]bool) apiserver.Middleware {
	return func(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
		if !ops[operationID] {
			return f
		}
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			p, err := ParsePurpose(r)
			if err != nil {
				var fe *core.FieldError
				errors.As(err, &fe)
				httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "Invalid request", "a purpose is required", fe).Write(w, r)
				return nil, nil
			}
			return f(context.WithValue(ctx, purposeKey{}, p), w, r, request)
		}
	}
}
