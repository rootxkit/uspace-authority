package authz

import (
	"context"
	"errors"
	"math"
	"net/http"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Handler serves /v1/auth/* and /v1/users* (apiserver.AuthHandler and
// apiserver.UsersHandler).
type Handler struct {
	Service *Service
}

var (
	_ apiserver.AuthHandler  = Handler{}
	_ apiserver.UsersHandler = Handler{}
)

func noBody() error {
	return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", &core.FieldError{Field: "body", Reason: "required"})
}

func rateLimited(e *RateLimitedError) gen.RateLimitedApplicationProblemPlusJSONResponse {
	secs := max(1, int(math.Ceil(e.RetryAfter.Seconds())))
	p := e.Problem
	return gen.RateLimitedApplicationProblemPlusJSONResponse{
		Body:    gen.Problem{Type: p.Type, Title: p.Title, Status: p.Status, Detail: &p.Detail, Errors: []gen.FieldProblem{}},
		Headers: gen.RateLimitedResponseHeaders{RetryAfter: &secs},
	}
}

// Login is the password step.
func (h Handler) Login(ctx context.Context, req gen.LoginRequestObject) (gen.LoginResponseObject, error) {
	if req.Body == nil {
		return nil, noBody()
	}
	res, err := h.Service.Login(ctx, req.Body.Username, req.Body.Password, apiserver.RequestInfoFrom(ctx))
	var rl *RateLimitedError
	if errors.As(err, &rl) {
		return gen.Login429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: rateLimited(rl)}, nil
	}
	if err != nil {
		return nil, err
	}
	noStore := "no-store"
	out := gen.Login200JSONResponse{Body: gen.LoginChallenge{MfaToken: res.Token, ExpiresAt: res.ExpiresAt.UTC()},
		Headers: gen.Login200ResponseHeaders{CacheControl: &noStore}}
	if res.EnrolSecret != "" {
		out.Body.Enrolment = &gen.MFAEnrolment{Secret: res.EnrolSecret, OtpauthUri: res.EnrolURI}
	}
	return out, nil
}

// VerifyMFA is the TOTP step.
func (h Handler) VerifyMFA(ctx context.Context, req gen.VerifyMFARequestObject) (gen.VerifyMFAResponseObject, error) {
	if req.Body == nil {
		return nil, noBody()
	}
	b := req.Body
	res, err := h.Service.VerifyMFA(ctx, b.MfaToken, deref(b.Code), deref(b.RecoveryCode), apiserver.RequestInfoFrom(ctx))
	var rl *RateLimitedError
	if errors.As(err, &rl) {
		return gen.VerifyMFA429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: rateLimited(rl)}, nil
	}
	if err != nil {
		return nil, err
	}
	noStore := "no-store"
	out := gen.VerifyMFA200JSONResponse{
		Body: gen.SessionIssued{
			Token: res.Token, TokenType: gen.SessionIssuedTokenTypeBearer, ExpiresAt: res.Session.ExpiresAt.UTC(),
			IdleTimeoutS: int(h.Service.Config.IdleTimeout.Seconds()), Session: h.sessionInfo(res.Session),
		},
		Headers: gen.VerifyMFA200ResponseHeaders{CacheControl: &noStore},
	}
	if len(res.RecoveryCodes) > 0 {
		out.Body.RecoveryCodes = &res.RecoveryCodes
	}
	return out, nil
}

func (h Handler) sessionInfo(s Session) gen.SessionInfo {
	roles := s.Roles
	if roles == nil {
		roles = []string{}
	}
	return gen.SessionInfo{
		Sub: s.UserID, Roles: roles, Realm: gen.Realm(s.Realm), Jti: s.JTI, ExpiresAt: s.ExpiresAt.UTC(),
		IdleExpiresAt: h.Service.IdleExpiry(s.LastSeenAt).UTC(),
	}
}

// GetSession answers the caller's session.
func (h Handler) GetSession(ctx context.Context, _ gen.GetSessionRequestObject) (gen.GetSessionResponseObject, error) {
	id, ok := apiserver.IdentityFrom(ctx)
	if !ok || !id.Session {
		return nil, httpx.Refuse(http.StatusUnauthorized, httpx.SlugUnauthn, "no session")
	}
	s, err := h.Service.Store.Session(ctx, id.JTI)
	if err != nil {
		return nil, err
	}
	return gen.GetSession200JSONResponse(h.sessionInfo(s)), nil
}

// Logout ends the caller's session.
func (h Handler) Logout(ctx context.Context, _ gen.LogoutRequestObject) (gen.LogoutResponseObject, error) {
	id, ok := apiserver.IdentityFrom(ctx)
	if !ok || !id.Session {
		return nil, httpx.Refuse(http.StatusUnauthorized, httpx.SlugUnauthn, "no session")
	}
	if err := h.Service.Logout(ctx, id); err != nil {
		return nil, err
	}
	return gen.Logout204Response{}, nil
}

func userToAPI(u User, enrolled bool) gen.User {
	roles := u.Roles
	if roles == nil {
		roles = []string{}
	}
	return gen.User{
		Id: u.ID, Username: u.Username, DisplayName: u.DisplayName, Roles: roles, Realm: gen.Realm(u.Realm),
		Status: gen.UserStatus(u.Status), MfaEnrolled: enrolled, CreatedAt: u.CreatedAt.UTC(), CreatedBy: u.CreatedBy,
		UpdatedAt: u.UpdatedAt.UTC(), UpdatedBy: u.UpdatedBy,
		MfaFailures: &u.MFAFailures, MfaHardLocked: &u.MFAHardLocked, MfaLockedUntil: u.MFALockedUntil,
	}
}

// ListUsers lists the accounts.
func (h Handler) ListUsers(ctx context.Context, _ gen.ListUsersRequestObject) (gen.ListUsersResponseObject, error) {
	us, enrolled, err := h.Service.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := gen.ListUsers200JSONResponse{Users: make([]gen.User, 0, len(us))}
	for i := range us {
		out.Users = append(out.Users, userToAPI(us[i], enrolled[i]))
	}
	return out, nil
}

// CreateUser creates an account.
func (h Handler) CreateUser(ctx context.Context, req gen.CreateUserRequestObject) (gen.CreateUserResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	b := req.Body
	roles := make([]string, 0, len(b.Roles))
	for _, r := range b.Roles {
		roles = append(roles, string(r))
	}
	u, err := h.Service.CreateUser(ctx, NewUser{Username: b.Username, Password: b.Password, DisplayName: deref(b.DisplayName),
		Roles: roles, Realm: string(b.Realm)}, actor)
	if err != nil {
		return nil, err
	}
	return gen.CreateUser201JSONResponse(userToAPI(u, false)), nil
}

// GetUser reads one account.
func (h Handler) GetUser(ctx context.Context, req gen.GetUserRequestObject) (gen.GetUserResponseObject, error) {
	u, enrolled, err := h.Service.GetUser(ctx, req.UserId)
	if err != nil {
		return nil, err
	}
	return gen.GetUser200JSONResponse(userToAPI(u, enrolled)), nil
}

func (h Handler) changed(ctx context.Context, u User) (gen.User, error) {
	enrolled, err := h.Service.enrolled(ctx, u.ID)
	return userToAPI(u, enrolled), err
}

// SetUserRoles replaces an account's roles.
func (h Handler) SetUserRoles(ctx context.Context, req gen.SetUserRolesRequestObject) (gen.SetUserRolesResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	roles := make([]string, 0, len(req.Body.Roles))
	for _, r := range req.Body.Roles {
		roles = append(roles, string(r))
	}
	u, err := h.Service.SetRoles(ctx, req.UserId, roles, actor)
	if err != nil {
		return nil, err
	}
	out, err := h.changed(ctx, u)
	return gen.SetUserRoles200JSONResponse(out), err
}

// DisableUser disables an account.
func (h Handler) DisableUser(ctx context.Context, req gen.DisableUserRequestObject) (gen.DisableUserResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.Service.SetStatus(ctx, req.UserId, StatusDisabled, actor)
	if err != nil {
		return nil, err
	}
	out, err := h.changed(ctx, u)
	return gen.DisableUser200JSONResponse(out), err
}

// EnableUser enables an account.
func (h Handler) EnableUser(ctx context.Context, req gen.EnableUserRequestObject) (gen.EnableUserResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.Service.SetStatus(ctx, req.UserId, StatusActive, actor)
	if err != nil {
		return nil, err
	}
	out, err := h.changed(ctx, u)
	return gen.EnableUser200JSONResponse(out), err
}

// ResetUserMFA resets an account's TOTP.
func (h Handler) ResetUserMFA(ctx context.Context, req gen.ResetUserMFARequestObject) (gen.ResetUserMFAResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.Service.ResetMFA(ctx, req.UserId, actor)
	if err != nil {
		return nil, err
	}
	return gen.ResetUserMFA200JSONResponse(userToAPI(u, false)), nil
}

// RevokeUserSessions ends an account's sessions.
func (h Handler) RevokeUserSessions(ctx context.Context, req gen.RevokeUserSessionsRequestObject) (gen.RevokeUserSessionsResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	n, err := h.Service.RevokeSessions(ctx, req.UserId, actor)
	if err != nil {
		return nil, err
	}
	return gen.RevokeUserSessions200JSONResponse{Revoked: n}, nil
}

// UnlockUserMFA clears the MFA lock of an account.
func (h Handler) UnlockUserMFA(ctx context.Context, req gen.UnlockUserMFARequestObject) (gen.UnlockUserMFAResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	u, err := h.Service.UnlockMFA(ctx, req.UserId, actor)
	if err != nil {
		return nil, err
	}
	out, err := h.changed(ctx, u)
	return gen.UnlockUserMFA200JSONResponse(out), err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
