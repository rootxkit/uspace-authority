package apiserver

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Console roles (docs/PLAN.md §7).
const (
	RoleViewer          = "viewer"
	RoleInspector       = "inspector"
	RoleRegistrar       = "registrar"
	RoleIncidentOfficer = "incident_officer"
	RoleAdmin           = "admin"
	RoleAuditor         = "auditor"
)

// Roles maps every /v1 operation id (as the generated code names it) to
// the roles allowed. It mirrors x-roles in api/openapi.yaml, and a test
// compares the two. An operation absent here is refused (fail closed).
var Roles = map[string][]string{
	"GetPolicy":       {RoleAdmin},
	"CreatePolicy":    {RoleAdmin},
	"ActivatePolicy":  {RoleAdmin},
	"ListAuditEvents": {RoleAdmin, RoleAuditor},
}

// Identity is who makes a request: the actor of its events rows.
type Identity struct {
	// ActorType is "user" for a console session, "client" for a machine.
	ActorType string
	// Subject is the account or client id.
	Subject string
	Roles   []string
	// Realm is "console" or "police" for a session.
	Realm string
}

type identityKey struct{}

// WithIdentity returns ctx carrying id.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom is the identity RequireRole admitted.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// IdentifyFunc resolves the identity of a request.
type IdentifyFunc func(r *http.Request) (Identity, error)

// ErrNoSession is the placeholder's answer: console sessions arrive
// with WP-2.
var ErrNoSession = errors.New("no console session: sign-in arrives with WP-2")

// NoSession is the production IdentifyFunc until WP-2 replaces it: it
// admits nobody.
func NoSession(*http.Request) (Identity, error) { return Identity{}, ErrNoSession }

// RequireRole admits a request when identify resolves an identity that
// holds one of the operation's roles: 401 unauthenticated without an
// identity, 403 forbidden without the role or for an operation that
// names none.
func RequireRole(identify IdentifyFunc, roles map[string][]string) Middleware {
	return func(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
		allowed := roles[operationID]
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			id, err := identify(r)
			if err != nil {
				httpx.NewProblem(http.StatusUnauthorized, httpx.SlugUnauthn, "", err.Error()).Write(w, r)
				return nil, nil
			}
			if !slices.ContainsFunc(id.Roles, func(role string) bool { return slices.Contains(allowed, role) }) {
				detail := "this operation has no role rule"
				if len(allowed) > 0 {
					detail = "this operation needs one of the roles " + strings.Join(allowed, ", ")
				}
				httpx.NewProblem(http.StatusForbidden, httpx.SlugForbidden, "", detail).Write(w, r)
				return nil, nil
			}
			return f(WithIdentity(ctx, id), w, r, request)
		}
	}
}
