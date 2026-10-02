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

// AllRoles lists the console roles.
var AllRoles = []string{RoleViewer, RoleInspector, RoleRegistrar, RoleIncidentOfficer, RoleAdmin, RoleAuditor}

// Session realms (docs/PLAN.md §7, M20).
const (
	RealmConsole = "console"
	RealmPolice  = "police"
)

// Roles maps every /v1 operation id (as the generated code names it) to
// the roles allowed. It mirrors x-roles in api/openapi.yaml, and a test
// compares the two. An operation absent from Roles, Public and
// AnySession is refused (fail closed).
var Roles = map[string][]string{
	"GetPolicy":            {RoleAdmin},
	"CreatePolicy":         {RoleAdmin},
	"ActivatePolicy":       {RoleAdmin},
	"ListAuditEvents":      {RoleAdmin, RoleAuditor},
	"ListOAuthClients":     {RoleAdmin},
	"CreateOAuthClient":    {RoleAdmin},
	"GetOAuthClient":       {RoleAdmin},
	"UpdateOAuthClient":    {RoleAdmin},
	"ListSigningKeys":      {RoleAdmin},
	"RotateSigningKey":     {RoleAdmin},
	"CompromiseSigningKey": {RoleAdmin},
	"ListUsers":            {RoleAdmin},
	"CreateUser":           {RoleAdmin},
	"GetUser":              {RoleAdmin},
	"SetUserRoles":         {RoleAdmin},
	"DisableUser":          {RoleAdmin},
	"EnableUser":           {RoleAdmin},
	"ResetUserMFA":         {RoleAdmin},
	"RevokeUserSessions":   {RoleAdmin},
	"UnlockUserMFA":        {RoleAdmin},

	"ListRegistryOperators":           {RoleRegistrar, RoleInspector, RoleViewer},
	"CreateRegistryOperator":          {RoleRegistrar},
	"GetRegistryOperator":             {RoleRegistrar, RoleInspector, RoleViewer},
	"UpdateRegistryOperator":          {RoleRegistrar},
	"SetRegistryOperatorStatus":       {RoleRegistrar},
	"GetRegistryOperatorPersonalData": {RoleRegistrar, RoleInspector},
	"ListRegistryUAS":                 {RoleRegistrar, RoleInspector, RoleViewer},
	"CreateRegistryUAS":               {RoleRegistrar},
	"GetRegistryUAS":                  {RoleRegistrar, RoleInspector, RoleViewer},
	"UpdateRegistryUAS":               {RoleRegistrar},
	"SetRegistryUASStatus":            {RoleRegistrar},
	"ListRegistryPilots":              {RoleRegistrar, RoleInspector, RoleViewer},
	"CreateRegistryPilot":             {RoleRegistrar},
	"GetRegistryPilot":                {RoleRegistrar, RoleInspector, RoleViewer},
	"UpdateRegistryPilot":             {RoleRegistrar},
	"SetRegistryPilotStatus":          {RoleRegistrar},
	"GetRegistryPilotPersonalData":    {RoleRegistrar, RoleInspector},
	"RecordPilotCompetency":           {RoleRegistrar},

	"ListRIDReceivers":      {RoleAdmin},
	"CreateRIDReceiver":     {RoleAdmin},
	"GetRIDReceiver":        {RoleAdmin},
	"UpdateRIDReceiver":     {RoleAdmin},
	"DeleteRIDReceiver":     {RoleAdmin},
	"SetRIDReceiverStatus":  {RoleAdmin},
	"RotateRIDReceiverKeys": {RoleAdmin},
	"ListRIDFrames":         {RoleIncidentOfficer, RoleInspector},
	"GetRIDFrame":           {RoleIncidentOfficer, RoleInspector},

	"GetCellOwnership": {RoleAdmin},
	"PutCellOwnership": {RoleAdmin},

	"ListSources":          {RoleAdmin},
	"SwitchSourceType":     {RoleAdmin},
	"SwitchSourceInstance": {RoleAdmin},

	"ListZones":            {RoleInspector, RoleAdmin, RoleViewer},
	"GetZone":              {RoleInspector, RoleAdmin, RoleViewer},
	"ListZoneVersions":     {RoleInspector, RoleAdmin, RoleViewer},
	"GetZoneApplicability": {RoleInspector, RoleAdmin, RoleViewer},
	"ExportZones":          {RoleInspector, RoleAdmin, RoleViewer},
	"CreateZone":           {RoleInspector},
	"ReplaceZone":          {RoleInspector},
	"ImportZones":          {RoleInspector},
	"ImportGovGeZones":     {RoleInspector},
	"ApproveZone":          {RoleAdmin},
	"PublishZones":         {RoleAdmin},

	"ListUSpaceAirspaces":     {RoleAdmin},
	"GetUSpaceAirspace":       {RoleAdmin},
	"ListUSpaceVersions":      {RoleAdmin},
	"CreateUSpaceAirspace":    {RoleAdmin},
	"ReplaceUSpaceAirspace":   {RoleAdmin},
	"DesignateUSpaceAirspace": {RoleAdmin},
	"PublishUSpaceAirspaces":  {RoleAdmin},

	"ListPublications": {RoleAdmin, RoleInspector, RoleViewer},

	"ListViolations":  {RoleInspector},
	"GetViolation":    {RoleInspector},
	"ReviewViolation": {RoleInspector},
}

// Receiver lists the operations a Remote ID receiver calls (`x-receiver:
// true` in the contract, WP-7): its bearer key and the HMAC of its body
// authenticate it inside internal/receivers, so they are excluded from
// the generated server (api/oapi-codegen.yaml) and never reach
// Authorize. A test holds the three lists to each other.
var Receiver = map[string]bool{
	"GetRIDReceiverConfig":     true,
	"PostRIDReceiverHeartbeat": true,
	"PostRIDObservations":      true,
}

// Delivery lists the CIS change-notification receiver (`x-cis-delivery:
// true` in the contract, WP-6): the compact JWS of its body is its
// credential, verified inside internal/cisp, so it is excluded from the
// generated server and never reaches Authorize. It has `security: []`
// (no bearer), so it is also in Public. A test holds the lists to each
// other.
var Delivery = map[string]bool{"ReceiveCISNotification": true}

// PIIRoles are the only roles that may read personal data: an operation
// whose response carries it names no other role (CLAUDE.md rule 6; a
// test holds every personal-data operation to it). viewer never reads
// personal data.
var PIIRoles = []string{RoleRegistrar, RoleInspector}

// Scopes maps every machine operation to the ecosystem scope it
// requires (WP-2 table B), mirroring x-scope in api/openapi.yaml; a
// test compares the two. A console session is never admitted to one.
var Scopes = map[string]string{
	"ValidateRegistry":      "registry.validate",
	"ValidateRegistryBatch": "registry.validate",
	"ListRegistryChanges":   "registry.validate",
}

// Public lists the operations with `security: []` in the contract: no
// identity is resolved for them (a client authenticates in the body of
// /oauth/token; a person signs in through /v1/auth/login). A test
// compares it with the contract.
var Public = map[string]bool{
	"GetHealthz":        true,
	"GetReadyz":         true,
	"GetMetrics":        true,
	"RequestToken":      true,
	"GetJWKS":           true,
	"GetIssuerMetadata": true,
	"Login":             true,
	"VerifyMFA":         true,

	"ReceiveCISNotification": true,
}

// AnySession lists the operations open to every console session
// whatever its roles (`x-session: any` in the contract).
var AnySession = map[string]bool{"GetSession": true, "Logout": true}

// Rules is the access rule set Authorize applies.
type Rules struct {
	Public     map[string]bool
	AnySession map[string]bool
	Roles      map[string][]string
	// Scopes names the scope a machine operation requires: an ecosystem
	// token (not a session) granting it is admitted (06 §3). No
	// operation of WP-2 has one; WP-3 adds the first.
	Scopes map[string]string
	// Realms names the realm an operation requires; an operation with
	// roles and no entry requires the console realm.
	Realms map[string]string
}

// DefaultRules are the contract's rules.
func DefaultRules() Rules {
	return Rules{Public: Public, AnySession: AnySession, Roles: Roles, Scopes: Scopes}
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
	// Session is true for a console session token (scope "session").
	Session bool
	// JTI is the token's id: the session id of a session.
	JTI string
	// Scopes are a machine token's scopes.
	Scopes []string
	// Issuer is the token's iss.
	Issuer string
}

type identityKey struct{}

// WithIdentity returns ctx carrying id.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom is the identity Authorize admitted.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// RequestInfo is what a handler may need of the HTTP request behind a
// strict operation.
type RequestInfo struct {
	RemoteIP  string
	UserAgent string
}

type requestInfoKey struct{}

// RequestInfoFrom returns the request info Authorize stored.
func RequestInfoFrom(ctx context.Context) RequestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(RequestInfo)
	return ri
}

// WithRequestInfo returns ctx carrying ri.
func WithRequestInfo(ctx context.Context, ri RequestInfo) context.Context {
	return context.WithValue(ctx, requestInfoKey{}, ri)
}

// IdentifyFunc resolves the identity of a request.
type IdentifyFunc func(r *http.Request) (Identity, error)

// ErrNoSession is the answer of NoSession.
var ErrNoSession = errors.New("no credential: sign in through /v1/auth/login")

// NoSession admits nobody: the IdentifyFunc of a process without a
// verifier, and of tests.
func NoSession(*http.Request) (Identity, error) { return Identity{}, ErrNoSession }

// RequireRole is Authorize with roles alone.
func RequireRole(identify IdentifyFunc, roles map[string][]string) Middleware {
	return Authorize(identify, Rules{Roles: roles})
}

// Authorize applies rules to every operation: a public operation runs
// without an identity; any other needs identify to resolve one (401
// unauthenticated otherwise); a scope operation admits only an
// ecosystem token granting its scope (a session is 403); every other
// operation needs a console session (a machine token is 403); an
// any-session operation then runs; a role
// operation needs a session of the operation's realm (console by
// default) holding one of its roles (403 forbidden otherwise). An
// operation that no rule names is refused (403, fail closed).
func Authorize(identify IdentifyFunc, rules Rules) Middleware {
	return func(f gen.StrictHandlerFunc, operationID string) gen.StrictHandlerFunc {
		allowed, hasRoles := rules.Roles[operationID]
		scope, hasScope := rules.Scopes[operationID]
		public := rules.Public[operationID]
		anySession := rules.AnySession[operationID]
		realm := rules.Realms[operationID]
		if realm == "" {
			realm = RealmConsole
		}
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			ctx = WithRequestInfo(ctx, RequestInfo{RemoteIP: httpx.RemoteIP(r), UserAgent: r.UserAgent()})
			if public {
				return f(ctx, w, r, request)
			}
			if !hasRoles && !anySession && !hasScope {
				httpx.NewProblem(http.StatusForbidden, httpx.SlugForbidden, "", "this operation has no role rule").Write(w, r)
				return nil, nil
			}
			id, err := identify(r)
			if err != nil {
				httpx.NewProblem(http.StatusUnauthorized, httpx.SlugUnauthn, "", err.Error()).Write(w, r)
				return nil, nil
			}
			if hasScope {
				if id.Session || !slices.Contains(id.Scopes, scope) {
					httpx.NewProblem(http.StatusForbidden, httpx.SlugForbidden, "", "this operation needs an ecosystem token granting "+scope).Write(w, r)
					return nil, nil
				}
				return f(WithIdentity(ctx, id), w, r, request)
			}
			if !id.Session {
				httpx.NewProblem(http.StatusForbidden, httpx.SlugForbidden, "", "this operation needs a console session, not a machine token").Write(w, r)
				return nil, nil
			}
			if hasRoles {
				if id.Realm != realm {
					httpx.NewProblem(http.StatusForbidden, httpx.SlugForbidden, "", "this operation needs a session of the "+realm+" realm").Write(w, r)
					return nil, nil
				}
				if !slices.ContainsFunc(id.Roles, func(role string) bool { return slices.Contains(allowed, role) }) {
					httpx.NewProblem(http.StatusForbidden, httpx.SlugForbidden, "", "this operation needs one of the roles "+strings.Join(allowed, ", ")).Write(w, r)
					return nil, nil
				}
			}
			return f(WithIdentity(ctx, id), w, r, request)
		}
	}
}
