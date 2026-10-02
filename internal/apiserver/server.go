package apiserver

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// HealthHandler serves the health group (every process, admin port).
type HealthHandler interface {
	GetHealthz(ctx context.Context, request gen.GetHealthzRequestObject) (gen.GetHealthzResponseObject, error)
	GetReadyz(ctx context.Context, request gen.GetReadyzRequestObject) (gen.GetReadyzResponseObject, error)
}

// PolicyHandler serves /v1/policy* (api, WP-1).
type PolicyHandler interface {
	GetPolicy(ctx context.Context, request gen.GetPolicyRequestObject) (gen.GetPolicyResponseObject, error)
	CreatePolicy(ctx context.Context, request gen.CreatePolicyRequestObject) (gen.CreatePolicyResponseObject, error)
	ActivatePolicy(ctx context.Context, request gen.ActivatePolicyRequestObject) (gen.ActivatePolicyResponseObject, error)
}

// AuditHandler serves /v1/audit/* (api, WP-1).
type AuditHandler interface {
	ListAuditEvents(ctx context.Context, request gen.ListAuditEventsRequestObject) (gen.ListAuditEventsResponseObject, error)
}

// TokenHandler serves the token service's public operations
// (/oauth/token, /.well-known/*; api, WP-2).
type TokenHandler interface {
	RequestToken(ctx context.Context, request gen.RequestTokenRequestObject) (gen.RequestTokenResponseObject, error)
	GetJWKS(ctx context.Context, request gen.GetJWKSRequestObject) (gen.GetJWKSResponseObject, error)
	GetIssuerMetadata(ctx context.Context, request gen.GetIssuerMetadataRequestObject) (gen.GetIssuerMetadataResponseObject, error)
}

// OAuthAdminHandler serves /v1/oauth/* (api, WP-2).
type OAuthAdminHandler interface {
	ListOAuthClients(ctx context.Context, request gen.ListOAuthClientsRequestObject) (gen.ListOAuthClientsResponseObject, error)
	CreateOAuthClient(ctx context.Context, request gen.CreateOAuthClientRequestObject) (gen.CreateOAuthClientResponseObject, error)
	GetOAuthClient(ctx context.Context, request gen.GetOAuthClientRequestObject) (gen.GetOAuthClientResponseObject, error)
	UpdateOAuthClient(ctx context.Context, request gen.UpdateOAuthClientRequestObject) (gen.UpdateOAuthClientResponseObject, error)
	ListSigningKeys(ctx context.Context, request gen.ListSigningKeysRequestObject) (gen.ListSigningKeysResponseObject, error)
	RotateSigningKey(ctx context.Context, request gen.RotateSigningKeyRequestObject) (gen.RotateSigningKeyResponseObject, error)
	CompromiseSigningKey(ctx context.Context, request gen.CompromiseSigningKeyRequestObject) (gen.CompromiseSigningKeyResponseObject, error)
}

// AuthHandler serves /v1/auth/* (api, WP-2).
type AuthHandler interface {
	Login(ctx context.Context, request gen.LoginRequestObject) (gen.LoginResponseObject, error)
	VerifyMFA(ctx context.Context, request gen.VerifyMFARequestObject) (gen.VerifyMFAResponseObject, error)
	GetSession(ctx context.Context, request gen.GetSessionRequestObject) (gen.GetSessionResponseObject, error)
	Logout(ctx context.Context, request gen.LogoutRequestObject) (gen.LogoutResponseObject, error)
}

// UsersHandler serves /v1/users* (api, WP-2).
type UsersHandler interface {
	ListUsers(ctx context.Context, request gen.ListUsersRequestObject) (gen.ListUsersResponseObject, error)
	CreateUser(ctx context.Context, request gen.CreateUserRequestObject) (gen.CreateUserResponseObject, error)
	GetUser(ctx context.Context, request gen.GetUserRequestObject) (gen.GetUserResponseObject, error)
	SetUserRoles(ctx context.Context, request gen.SetUserRolesRequestObject) (gen.SetUserRolesResponseObject, error)
	DisableUser(ctx context.Context, request gen.DisableUserRequestObject) (gen.DisableUserResponseObject, error)
	EnableUser(ctx context.Context, request gen.EnableUserRequestObject) (gen.EnableUserResponseObject, error)
	ResetUserMFA(ctx context.Context, request gen.ResetUserMFARequestObject) (gen.ResetUserMFAResponseObject, error)
	RevokeUserSessions(ctx context.Context, request gen.RevokeUserSessionsRequestObject) (gen.RevokeUserSessionsResponseObject, error)
	UnlockUserMFA(ctx context.Context, request gen.UnlockUserMFARequestObject) (gen.UnlockUserMFAResponseObject, error)
}

// RegistryHandler serves /v1/registry/* (api, WP-3): the registrar's
// operations, the personal-data reads and the F8 lookups.
type RegistryHandler interface {
	ListRegistryChanges(ctx context.Context, request gen.ListRegistryChangesRequestObject) (gen.ListRegistryChangesResponseObject, error)
	ListRegistryOperators(ctx context.Context, request gen.ListRegistryOperatorsRequestObject) (gen.ListRegistryOperatorsResponseObject, error)
	CreateRegistryOperator(ctx context.Context, request gen.CreateRegistryOperatorRequestObject) (gen.CreateRegistryOperatorResponseObject, error)
	GetRegistryOperator(ctx context.Context, request gen.GetRegistryOperatorRequestObject) (gen.GetRegistryOperatorResponseObject, error)
	UpdateRegistryOperator(ctx context.Context, request gen.UpdateRegistryOperatorRequestObject) (gen.UpdateRegistryOperatorResponseObject, error)
	GetRegistryOperatorPersonalData(ctx context.Context, request gen.GetRegistryOperatorPersonalDataRequestObject) (gen.GetRegistryOperatorPersonalDataResponseObject, error)
	SetRegistryOperatorStatus(ctx context.Context, request gen.SetRegistryOperatorStatusRequestObject) (gen.SetRegistryOperatorStatusResponseObject, error)
	ListRegistryPilots(ctx context.Context, request gen.ListRegistryPilotsRequestObject) (gen.ListRegistryPilotsResponseObject, error)
	CreateRegistryPilot(ctx context.Context, request gen.CreateRegistryPilotRequestObject) (gen.CreateRegistryPilotResponseObject, error)
	GetRegistryPilot(ctx context.Context, request gen.GetRegistryPilotRequestObject) (gen.GetRegistryPilotResponseObject, error)
	UpdateRegistryPilot(ctx context.Context, request gen.UpdateRegistryPilotRequestObject) (gen.UpdateRegistryPilotResponseObject, error)
	RecordPilotCompetency(ctx context.Context, request gen.RecordPilotCompetencyRequestObject) (gen.RecordPilotCompetencyResponseObject, error)
	GetRegistryPilotPersonalData(ctx context.Context, request gen.GetRegistryPilotPersonalDataRequestObject) (gen.GetRegistryPilotPersonalDataResponseObject, error)
	SetRegistryPilotStatus(ctx context.Context, request gen.SetRegistryPilotStatusRequestObject) (gen.SetRegistryPilotStatusResponseObject, error)
	ListRegistryUAS(ctx context.Context, request gen.ListRegistryUASRequestObject) (gen.ListRegistryUASResponseObject, error)
	CreateRegistryUAS(ctx context.Context, request gen.CreateRegistryUASRequestObject) (gen.CreateRegistryUASResponseObject, error)
	GetRegistryUAS(ctx context.Context, request gen.GetRegistryUASRequestObject) (gen.GetRegistryUASResponseObject, error)
	UpdateRegistryUAS(ctx context.Context, request gen.UpdateRegistryUASRequestObject) (gen.UpdateRegistryUASResponseObject, error)
	SetRegistryUASStatus(ctx context.Context, request gen.SetRegistryUASStatusRequestObject) (gen.SetRegistryUASStatusResponseObject, error)
	ValidateRegistry(ctx context.Context, request gen.ValidateRegistryRequestObject) (gen.ValidateRegistryResponseObject, error)
	ValidateRegistryBatch(ctx context.Context, request gen.ValidateRegistryBatchRequestObject) (gen.ValidateRegistryBatchResponseObject, error)
}

// Server implements gen.StrictServerInterface by delegating to one
// handler per group. A group left nil must not be mounted.
type Server struct {
	HealthHandler
	PolicyHandler
	AuditHandler
	TokenHandler
	OAuthAdminHandler
	AuthHandler
	UsersHandler
	RegistryHandler
}

var _ gen.StrictServerInterface = Server{}

// Middleware wraps every mounted operation; it is the generated strict
// middleware type, named here so cmd/* need not import api/gen.
type Middleware = gen.StrictMiddlewareFunc

// Options configures Mount.
type Options struct {
	Logger *slog.Logger
	// Middlewares run around every mounted operation (RequireRole).
	Middlewares []Middleware
	// Keep selects the ServeMux patterns ("GET /v1/policy") mounted.
	Keep func(pattern string) bool
}

// PathPrefix keeps the patterns whose path starts with one of prefixes.
func PathPrefix(prefixes ...string) func(string) bool {
	return func(pattern string) bool {
		_, path, _ := strings.Cut(pattern, " ")
		for _, p := range prefixes {
			if strings.HasPrefix(path, p) {
				return true
			}
		}
		return false
	}
}

// subsetMux registers only the patterns keep accepts.
type subsetMux struct {
	*http.ServeMux
	keep    func(string) bool
	mounted *[]string
}

// HandleFunc registers h when keep accepts pattern.
func (m subsetMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	if m.keep(pattern) {
		m.ServeMux.HandleFunc(pattern, h)
		*m.mounted = append(*m.mounted, pattern)
	}
}

func badRequest(w http.ResponseWriter, r *http.Request, err error) {
	httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "Invalid request", "",
		&core.FieldError{Field: "request", Reason: err.Error()}).Write(w, r)
}

// Mount registers on mux the operations of s that o.Keep selects and
// returns their patterns. A malformed request (an unparsable parameter
// or body) is a 400 validation problem naming what failed; an error a
// handler returns is mapped by httpx.ProblemFromError, and a 5xx is
// logged without echoing its text to the client.
func Mount(mux *http.ServeMux, s Server, o Options) []string {
	logger := o.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	strict := gen.NewStrictHandlerWithOptions(s, o.Middlewares, gen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: badRequest,
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			p := httpx.ProblemFromError(err)
			if p.Status >= http.StatusInternalServerError {
				logging.Error(r.Context(), logger, "request failed", err, slog.String("route", httpx.Route(r)))
			}
			p.Write(w, r)
		},
	})
	var mounted []string
	gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{
		BaseRouter:       subsetMux{ServeMux: mux, keep: o.Keep, mounted: &mounted},
		ErrorHandlerFunc: badRequest,
	})
	return mounted
}
