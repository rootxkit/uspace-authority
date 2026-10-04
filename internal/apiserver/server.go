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
	SetUserPoliceAccess(ctx context.Context, request gen.SetUserPoliceAccessRequestObject) (gen.SetUserPoliceAccessResponseObject, error)
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

// RegistryImportHandler serves POST /v1/registry/import (api, WP-20):
// the uas.gov.ge import under the rules file.
type RegistryImportHandler interface {
	ImportRegistry(ctx context.Context, request gen.ImportRegistryRequestObject) (gen.ImportRegistryResponseObject, error)
}

// RegistryPortalHandler serves the public check, the registration
// applications and the operator's occurrence link (api, WP-20).
type RegistryPortalHandler interface {
	CheckRegistration(ctx context.Context, request gen.CheckRegistrationRequestObject) (gen.CheckRegistrationResponseObject, error)
	SubmitRegistryApplication(ctx context.Context, request gen.SubmitRegistryApplicationRequestObject) (gen.SubmitRegistryApplicationResponseObject, error)
	ListRegistryApplications(ctx context.Context, request gen.ListRegistryApplicationsRequestObject) (gen.ListRegistryApplicationsResponseObject, error)
	GetRegistryApplicationStatus(ctx context.Context, request gen.GetRegistryApplicationStatusRequestObject) (gen.GetRegistryApplicationStatusResponseObject, error)
	VerifyRegistryApplication(ctx context.Context, request gen.VerifyRegistryApplicationRequestObject) (gen.VerifyRegistryApplicationResponseObject, error)
	GetRegistryApplicationPersonalData(ctx context.Context, request gen.GetRegistryApplicationPersonalDataRequestObject) (gen.GetRegistryApplicationPersonalDataResponseObject, error)
	StartRegistryApplicationReview(ctx context.Context, request gen.StartRegistryApplicationReviewRequestObject) (gen.StartRegistryApplicationReviewResponseObject, error)
	ApproveRegistryApplication(ctx context.Context, request gen.ApproveRegistryApplicationRequestObject) (gen.ApproveRegistryApplicationResponseObject, error)
	RefuseRegistryApplication(ctx context.Context, request gen.RefuseRegistryApplicationRequestObject) (gen.RefuseRegistryApplicationResponseObject, error)
	RequestOperatorLink(ctx context.Context, request gen.RequestOperatorLinkRequestObject) (gen.RequestOperatorLinkResponseObject, error)
	CreateOperatorOccurrence(ctx context.Context, request gen.CreateOperatorOccurrenceRequestObject) (gen.CreateOperatorOccurrenceResponseObject, error)
}

// RIDReceiversHandler serves the admin operations of /v1/rid/receivers*
// and the raw frames /v1/rid/frames* (api, WP-7). The receivers' own
// config and heartbeat endpoints are x-receiver operations served
// outside the generated server (Receiver).
type RIDReceiversHandler interface {
	ListRIDReceivers(ctx context.Context, request gen.ListRIDReceiversRequestObject) (gen.ListRIDReceiversResponseObject, error)
	CreateRIDReceiver(ctx context.Context, request gen.CreateRIDReceiverRequestObject) (gen.CreateRIDReceiverResponseObject, error)
	GetRIDReceiver(ctx context.Context, request gen.GetRIDReceiverRequestObject) (gen.GetRIDReceiverResponseObject, error)
	UpdateRIDReceiver(ctx context.Context, request gen.UpdateRIDReceiverRequestObject) (gen.UpdateRIDReceiverResponseObject, error)
	DeleteRIDReceiver(ctx context.Context, request gen.DeleteRIDReceiverRequestObject) (gen.DeleteRIDReceiverResponseObject, error)
	SetRIDReceiverStatus(ctx context.Context, request gen.SetRIDReceiverStatusRequestObject) (gen.SetRIDReceiverStatusResponseObject, error)
	RotateRIDReceiverKeys(ctx context.Context, request gen.RotateRIDReceiverKeysRequestObject) (gen.RotateRIDReceiverKeysResponseObject, error)
	ListRIDFrames(ctx context.Context, request gen.ListRIDFramesRequestObject) (gen.ListRIDFramesResponseObject, error)
	GetRIDFrame(ctx context.Context, request gen.GetRIDFrameRequestObject) (gen.GetRIDFrameResponseObject, error)
}

// CellsHandler serves /v1/cells (api, WP-10): the cell ownership map.
type CellsHandler interface {
	GetCellOwnership(ctx context.Context, request gen.GetCellOwnershipRequestObject) (gen.GetCellOwnershipResponseObject, error)
	PutCellOwnership(ctx context.Context, request gen.PutCellOwnershipRequestObject) (gen.PutCellOwnershipResponseObject, error)
}

// SourcesHandler serves /v1/sources* (api, WP-10): source control.
type SourcesHandler interface {
	ListSources(ctx context.Context, request gen.ListSourcesRequestObject) (gen.ListSourcesResponseObject, error)
	SwitchSourceType(ctx context.Context, request gen.SwitchSourceTypeRequestObject) (gen.SwitchSourceTypeResponseObject, error)
	SwitchSourceInstance(ctx context.Context, request gen.SwitchSourceInstanceRequestObject) (gen.SwitchSourceInstanceResponseObject, error)
}

// ZonesHandler serves /v1/zones* (api, WP-5): geo-zone authoring,
// import, export and publication.
type ZonesHandler interface {
	ListZones(ctx context.Context, request gen.ListZonesRequestObject) (gen.ListZonesResponseObject, error)
	CreateZone(ctx context.Context, request gen.CreateZoneRequestObject) (gen.CreateZoneResponseObject, error)
	ExportZones(ctx context.Context, request gen.ExportZonesRequestObject) (gen.ExportZonesResponseObject, error)
	ImportZones(ctx context.Context, request gen.ImportZonesRequestObject) (gen.ImportZonesResponseObject, error)
	ImportGovGeZones(ctx context.Context, request gen.ImportGovGeZonesRequestObject) (gen.ImportGovGeZonesResponseObject, error)
	PublishZones(ctx context.Context, request gen.PublishZonesRequestObject) (gen.PublishZonesResponseObject, error)
	GetZone(ctx context.Context, request gen.GetZoneRequestObject) (gen.GetZoneResponseObject, error)
	ReplaceZone(ctx context.Context, request gen.ReplaceZoneRequestObject) (gen.ReplaceZoneResponseObject, error)
	ApproveZone(ctx context.Context, request gen.ApproveZoneRequestObject) (gen.ApproveZoneResponseObject, error)
	ListZoneVersions(ctx context.Context, request gen.ListZoneVersionsRequestObject) (gen.ListZoneVersionsResponseObject, error)
	GetZoneApplicability(ctx context.Context, request gen.GetZoneApplicabilityRequestObject) (gen.GetZoneApplicabilityResponseObject, error)
}

// USpaceHandler serves /v1/uspace* (api, WP-5): U-space airspace
// designations.
type USpaceHandler interface {
	ListUSpaceAirspaces(ctx context.Context, request gen.ListUSpaceAirspacesRequestObject) (gen.ListUSpaceAirspacesResponseObject, error)
	CreateUSpaceAirspace(ctx context.Context, request gen.CreateUSpaceAirspaceRequestObject) (gen.CreateUSpaceAirspaceResponseObject, error)
	PublishUSpaceAirspaces(ctx context.Context, request gen.PublishUSpaceAirspacesRequestObject) (gen.PublishUSpaceAirspacesResponseObject, error)
	GetUSpaceAirspace(ctx context.Context, request gen.GetUSpaceAirspaceRequestObject) (gen.GetUSpaceAirspaceResponseObject, error)
	ReplaceUSpaceAirspace(ctx context.Context, request gen.ReplaceUSpaceAirspaceRequestObject) (gen.ReplaceUSpaceAirspaceResponseObject, error)
	DesignateUSpaceAirspace(ctx context.Context, request gen.DesignateUSpaceAirspaceRequestObject) (gen.DesignateUSpaceAirspaceResponseObject, error)
	ListUSpaceVersions(ctx context.Context, request gen.ListUSpaceVersionsRequestObject) (gen.ListUSpaceVersionsResponseObject, error)
}

// CISPHandler serves GET /v1/publications (api, WP-6): the publication
// outbox and the CIS subscriber's state. POST /v1/cis/notifications is
// an x-cis-delivery operation served outside the generated server.
type CISPHandler interface {
	ListPublications(ctx context.Context, request gen.ListPublicationsRequestObject) (gen.ListPublicationsResponseObject, error)
}

// ViolationsHandler serves /v1/violations* (api, WP-12): the violations
// detect raised, and their review.
type ViolationsHandler interface {
	ListViolations(ctx context.Context, request gen.ListViolationsRequestObject) (gen.ListViolationsResponseObject, error)
	GetViolation(ctx context.Context, request gen.GetViolationRequestObject) (gen.GetViolationResponseObject, error)
	ReviewViolation(ctx context.Context, request gen.ReviewViolationRequestObject) (gen.ReviewViolationResponseObject, error)
}

// IncidentsHandler serves /v1/incidents* (api, WP-17): the case files
// and their evidence packs.
type IncidentsHandler interface {
	ListIncidents(ctx context.Context, request gen.ListIncidentsRequestObject) (gen.ListIncidentsResponseObject, error)
	CreateIncident(ctx context.Context, request gen.CreateIncidentRequestObject) (gen.CreateIncidentResponseObject, error)
	GetIncident(ctx context.Context, request gen.GetIncidentRequestObject) (gen.GetIncidentResponseObject, error)
	UpdateIncident(ctx context.Context, request gen.UpdateIncidentRequestObject) (gen.UpdateIncidentResponseObject, error)
	CreateEvidencePack(ctx context.Context, request gen.CreateEvidencePackRequestObject) (gen.CreateEvidencePackResponseObject, error)
	GetEvidencePack(ctx context.Context, request gen.GetEvidencePackRequestObject) (gen.GetEvidencePackResponseObject, error)
	DownloadEvidencePack(ctx context.Context, request gen.DownloadEvidencePackRequestObject) (gen.DownloadEvidencePackResponseObject, error)
	VerifyEvidencePack(ctx context.Context, request gen.VerifyEvidencePackRequestObject) (gen.VerifyEvidencePackResponseObject, error)
}

// OccurrencesHandler serves /v1/occurrences* (api, WP-18): the
// 376/2014 intake, the officers' handling, the reporter's identity for
// incident officers only and the de-identified export.
type OccurrencesHandler interface {
	CreateOccurrence(ctx context.Context, request gen.CreateOccurrenceRequestObject) (gen.CreateOccurrenceResponseObject, error)
	ListOccurrences(ctx context.Context, request gen.ListOccurrencesRequestObject) (gen.ListOccurrencesResponseObject, error)
	ExportOccurrences(ctx context.Context, request gen.ExportOccurrencesRequestObject) (gen.ExportOccurrencesResponseObject, error)
	GetOccurrence(ctx context.Context, request gen.GetOccurrenceRequestObject) (gen.GetOccurrenceResponseObject, error)
	GetOccurrenceReporter(ctx context.Context, request gen.GetOccurrenceReporterRequestObject) (gen.GetOccurrenceReporterResponseObject, error)
	ClassifyOccurrence(ctx context.Context, request gen.ClassifyOccurrenceRequestObject) (gen.ClassifyOccurrenceResponseObject, error)
	UpdateOccurrenceAnalysis(ctx context.Context, request gen.UpdateOccurrenceAnalysisRequestObject) (gen.UpdateOccurrenceAnalysisResponseObject, error)
}

// DPHandler serves /v1/dp/* administration (api, WP-14): oversight
// areas, the Service Providers seen, USS availability arbitration. The
// x-dp operations are served by dp-poller (DisplayProvider).
type DPHandler interface {
	ListDPViews(ctx context.Context, request gen.ListDPViewsRequestObject) (gen.ListDPViewsResponseObject, error)
	CreateDPView(ctx context.Context, request gen.CreateDPViewRequestObject) (gen.CreateDPViewResponseObject, error)
	ListDPProviders(ctx context.Context, request gen.ListDPProvidersRequestObject) (gen.ListDPProvidersResponseObject, error)
	SetDPProviderAvailability(ctx context.Context, request gen.SetDPProviderAvailabilityRequestObject) (gen.SetDPProviderAvailabilityResponseObject, error)
}

// CertificatesHandler serves /v1/certificates* (api, WP-16): USSP and
// CISP certificates, their operating status, the public register and
// the USSP list.
type CertificatesHandler interface {
	ListCertificates(ctx context.Context, request gen.ListCertificatesRequestObject) (gen.ListCertificatesResponseObject, error)
	IssueCertificate(ctx context.Context, request gen.IssueCertificateRequestObject) (gen.IssueCertificateResponseObject, error)
	GetCertificateRegister(ctx context.Context, request gen.GetCertificateRegisterRequestObject) (gen.GetCertificateRegisterResponseObject, error)
	PublishUSSPList(ctx context.Context, request gen.PublishUSSPListRequestObject) (gen.PublishUSSPListResponseObject, error)
	GetCertificate(ctx context.Context, request gen.GetCertificateRequestObject) (gen.GetCertificateResponseObject, error)
	UpdateCertificate(ctx context.Context, request gen.UpdateCertificateRequestObject) (gen.UpdateCertificateResponseObject, error)
	PostCertificateStatus(ctx context.Context, request gen.PostCertificateStatusRequestObject) (gen.PostCertificateStatusResponseObject, error)
	RecordCertificateStatusNotice(ctx context.Context, request gen.RecordCertificateStatusNoticeRequestObject) (gen.RecordCertificateStatusNoticeResponseObject, error)
	SuspendCertificate(ctx context.Context, request gen.SuspendCertificateRequestObject) (gen.SuspendCertificateResponseObject, error)
	LimitCertificate(ctx context.Context, request gen.LimitCertificateRequestObject) (gen.LimitCertificateResponseObject, error)
	RevokeCertificate(ctx context.Context, request gen.RevokeCertificateRequestObject) (gen.RevokeCertificateResponseObject, error)
	ReinstateCertificate(ctx context.Context, request gen.ReinstateCertificateRequestObject) (gen.ReinstateCertificateResponseObject, error)
}

// PoliceHandler serves /v1/police/* (api, WP-19): the police realm's
// purpose-logged queries and legal exports.
type PoliceHandler interface {
	QueryPoliceAircraft(ctx context.Context, request gen.QueryPoliceAircraftRequestObject) (gen.QueryPoliceAircraftResponseObject, error)
	QueryPoliceOperator(ctx context.Context, request gen.QueryPoliceOperatorRequestObject) (gen.QueryPoliceOperatorResponseObject, error)
	QueryPoliceSerial(ctx context.Context, request gen.QueryPoliceSerialRequestObject) (gen.QueryPoliceSerialResponseObject, error)
	CreatePoliceExport(ctx context.Context, request gen.CreatePoliceExportRequestObject) (gen.CreatePoliceExportResponseObject, error)
	DownloadPoliceExport(ctx context.Context, request gen.DownloadPoliceExportRequestObject) (gen.DownloadPoliceExportResponseObject, error)
}

// DPOHandler serves GET /v1/audit/dpo-report (api, WP-19).
type DPOHandler interface {
	GetDPOReport(ctx context.Context, request gen.GetDPOReportRequestObject) (gen.GetDPOReportResponseObject, error)
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
	RegistryImportHandler
	RegistryPortalHandler
	RIDReceiversHandler
	CellsHandler
	SourcesHandler
	ZonesHandler
	USpaceHandler
	CISPHandler
	ViolationsHandler
	IncidentsHandler
	OccurrencesHandler
	DPHandler
	CertificatesHandler
	PoliceHandler
	DPOHandler
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
	// BodyLimits sets the body cap of the patterns it names (an import
	// larger than the listener's default), counted in BodyCounters.
	BodyLimits   map[string]int64
	BodyCounters *core.Counters
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
	keep     func(string) bool
	mounted  *[]string
	limits   map[string]int64
	counters *core.Counters
}

// HandleFunc registers h when keep accepts pattern, under its own body
// cap when limits names it.
func (m subsetMux) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	if !m.keep(pattern) {
		return
	}
	if n, ok := m.limits[pattern]; ok {
		counters := m.counters
		if counters == nil {
			counters = &core.Counters{}
		}
		m.Handle(pattern, httpx.BodyLimit(n, counters, http.HandlerFunc(h)))
	} else {
		m.ServeMux.HandleFunc(pattern, h)
	}
	*m.mounted = append(*m.mounted, pattern)
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
		BaseRouter:       subsetMux{ServeMux: mux, keep: o.Keep, mounted: &mounted, limits: o.BodyLimits, counters: o.BodyCounters},
		ErrorHandlerFunc: badRequest,
	})
	return mounted
}
