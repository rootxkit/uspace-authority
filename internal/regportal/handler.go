package regportal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
)

// Page bounds of the registrars' list.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Handler serves the public check, the applications and the operator
// links (apiserver.RegistryPortalHandler).
type Handler struct {
	Service *Service
	// Check is the registry the public check reads (status only).
	Check interface {
		CheckNumber(ctx context.Context, number string) (registry.PublicCheck, error)
	}
	// CheckLimit is the public check's per-address limiter (bounded,
	// E-10); nil admits every request.
	CheckLimit *httpx.RateLimiter
}

var _ apiserver.RegistryPortalHandler = Handler{}

func problemBody(p *httpx.Problem) gen.Problem {
	errs := make([]gen.FieldProblem, 0, len(p.Errors))
	for _, e := range p.Errors {
		errs = append(errs, gen.FieldProblem{Field: e.Field, Reason: e.Reason})
	}
	out := gen.Problem{Type: p.Type, Title: p.Title, Status: p.Status, Detail: &p.Detail, Errors: errs}
	if p.Truncated {
		t := true
		out.Truncated = &t
	}
	return out
}

// rateLimited is the 429 of a spent budget, or nil when err is not one.
func rateLimited(err error) *gen.RateLimitedApplicationProblemPlusJSONResponse {
	var be *BudgetSpentError
	if !errors.As(err, &be) {
		return nil
	}
	secs := max(1, int(math.Ceil(be.RetryAfter.Seconds())))
	p := httpx.NewProblem(http.StatusTooManyRequests, SlugBudget, "Too many requests", be.Error())
	return &gen.RateLimitedApplicationProblemPlusJSONResponse{Body: problemBody(p), Headers: gen.RateLimitedResponseHeaders{RetryAfter: &secs}}
}

// CheckRegistration answers the public status-only check.
func (h Handler) CheckRegistration(ctx context.Context, req gen.CheckRegistrationRequestObject) (gen.CheckRegistrationResponseObject, error) {
	if h.CheckLimit != nil {
		if ok, wait := h.CheckLimit.Allow(apiserver.RequestInfoFrom(ctx).RemoteIP); !ok {
			h.Service.count(CounterCheckLimited)
			secs := max(1, int(math.Ceil(wait.Seconds())))
			p := httpx.NewProblem(http.StatusTooManyRequests, httpx.SlugRateLimited, "Too many requests", "the client's request budget is spent")
			return gen.CheckRegistration429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: gen.RateLimitedApplicationProblemPlusJSONResponse{
				Body: problemBody(p), Headers: gen.RateLimitedResponseHeaders{RetryAfter: &secs},
			}}, nil
		}
	}
	c, err := h.Check.CheckNumber(ctx, req.Params.Number)
	if err != nil {
		return nil, err
	}
	return gen.CheckRegistration200JSONResponse{Status: gen.RegistryCheckStatus(c.Status), ValidUntil: c.ValidUntil}, nil
}

func statusOf(a *Application) gen.RegistryApplicationStatus {
	out := gen.RegistryApplicationStatus{ApplicationId: a.ID, State: gen.RegistryApplicationState(a.State), SubmittedAt: a.SubmittedAt.UTC(),
		DecidedAt: a.DecidedAt}
	if a.State == StateUnverified {
		e := a.VerifyExpiresAt.UTC()
		out.VerifyExpiresAt = &e
	}
	if a.RefusalReason != "" {
		r := a.RefusalReason
		out.RefusalReason = &r
	}
	if a.State == StateApproved && a.IssuedNumber != "" {
		n := a.IssuedNumber
		out.RegistrationNumber = &n
	}
	return out
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func applicationBody(a *Application) gen.RegistryApplication {
	out := gen.RegistryApplication{
		ApplicationId: a.ID, Kind: "operator_registration", State: gen.RegistryApplicationState(a.State),
		OperatorType: gen.OperatorType(a.OperatorType), Lang: gen.RegistryApplicationLang(a.Lang), SubmittedAt: a.SubmittedAt.UTC(),
		VerifiedAt: a.VerifiedAt, RegistrarId: opt(a.RegistrarID), ReviewStartedAt: a.ReviewStartedAt, DecidedAt: a.DecidedAt,
		RefusalReason: opt(a.RefusalReason), OperatorId: opt(a.OperatorID), ValidUntil: a.ValidUntil,
	}
	// The number is chosen before the registration commits; it is the
	// application's number only once approved.
	if a.State == StateApproved {
		out.RegistrationNumber = opt(a.IssuedNumber)
	}
	return out
}

func dateIn(d *openapi_types.Date) string {
	if d == nil {
		return ""
	}
	return d.Format(time.DateOnly)
}

func deref2(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// SubmitRegistryApplication receives an application.
func (h Handler) SubmitRegistryApplication(ctx context.Context, req gen.SubmitRegistryApplicationRequestObject) (gen.SubmitRegistryApplicationResponseObject, error) {
	if err := h.Service.needApplications(); err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, core.Fieldf("body", "required")
	}
	in := Applicant{OperatorType: string(b.OperatorType), PII: registry.OperatorPII{
		FullName: deref2(b.FullName), LegalName: deref2(b.LegalName), DateOfBirth: dateIn(b.DateOfBirth),
		LegalIdentificationNumber: deref2(b.LegalIdentificationNumber), PostalAddress: b.PostalAddress, ContactEmail: b.ContactEmail,
		ContactPhone: b.ContactPhone, InsurancePolicyNumber: deref2(b.InsurancePolicyNumber),
	}}
	if b.CompetencyConfirmation != nil {
		in.CompetencyConfirmation = *b.CompetencyConfirmation
	}
	if b.Authorisations != nil {
		raw, err := json.Marshal(*b.Authorisations)
		if err != nil {
			return nil, core.Fieldf("authorisations", "not encodable")
		}
		in.Authorisations = raw
	}
	a, err := h.Service.Submit(ctx, in, string(b.Lang), apiserver.RequestInfoFrom(ctx).RemoteIP)
	if rl := rateLimited(err); rl != nil {
		return gen.SubmitRegistryApplication429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: *rl}, nil
	}
	if err != nil {
		return nil, err
	}
	return gen.SubmitRegistryApplication202JSONResponse(statusOf(&a)), nil
}

// GetRegistryApplicationStatus answers an application's state to its
// link.
func (h Handler) GetRegistryApplicationStatus(ctx context.Context, req gen.GetRegistryApplicationStatusRequestObject) (gen.GetRegistryApplicationStatusResponseObject, error) {
	a, err := h.Service.Status(ctx, req.ApplicationId, deref2(req.Params.XApplicationToken))
	if err != nil {
		return nil, err
	}
	return gen.GetRegistryApplicationStatus200JSONResponse(statusOf(&a)), nil
}

// VerifyRegistryApplication follows the verification link.
func (h Handler) VerifyRegistryApplication(ctx context.Context, req gen.VerifyRegistryApplicationRequestObject) (gen.VerifyRegistryApplicationResponseObject, error) {
	a, err := h.Service.Verify(ctx, req.ApplicationId, deref2(req.Params.XApplicationToken))
	if err != nil {
		return nil, err
	}
	return gen.VerifyRegistryApplication200JSONResponse(statusOf(&a)), nil
}

var cursorID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// EncodeCursor is the opaque cursor after an application.
func EncodeCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(at.UTC().Format(time.RFC3339Nano) + "|" + id))
}

// DecodeCursor reads a cursor EncodeCursor wrote.
func DecodeCursor(s string) (time.Time, string, error) {
	bad := &core.FieldError{Field: "cursor", Reason: "not a cursor of this endpoint"}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", bad
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || !cursorID.MatchString(id) {
		return time.Time{}, "", bad
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, "", bad
	}
	return t, id, nil
}

// ListRegistryApplications answers one page for registrars.
func (h Handler) ListRegistryApplications(ctx context.Context, req gen.ListRegistryApplicationsRequestObject) (gen.ListRegistryApplicationsResponseObject, error) {
	p := req.Params
	limit := DefaultLimit
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > MaxLimit {
		return nil, core.Fieldf("limit", "must be between 1 and %d", MaxLimit)
	}
	page := Page{Limit: limit + 1, AfterAt: time.Unix(0, 0).UTC()}
	if p.State != nil {
		page.State = string(*p.State)
	}
	if p.Cursor != nil {
		at, id, err := DecodeCursor(*p.Cursor)
		if err != nil {
			return nil, err
		}
		page.AfterAt, page.AfterID = at, id
	}
	rows, err := h.Service.List(ctx, page)
	if err != nil {
		return nil, err
	}
	out := gen.RegistryApplicationPage{Applications: []gen.RegistryApplication{}}
	for i := range rows {
		if i == limit {
			c := EncodeCursor(rows[i-1].SubmittedAt, rows[i-1].ID)
			out.NextCursor = &c
			break
		}
		out.Applications = append(out.Applications, applicationBody(&rows[i]))
	}
	return gen.ListRegistryApplications200JSONResponse(out), nil
}

// GetRegistryApplicationPersonalData opens an application for a
// registrar, with a purpose.
func (h Handler) GetRegistryApplicationPersonalData(ctx context.Context, req gen.GetRegistryApplicationPersonalDataRequestObject) (gen.GetRegistryApplicationPersonalDataResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	a, err := h.Service.PersonalData(ctx, req.ApplicationId, req.Params.Purpose, actor)
	if err != nil {
		return nil, err
	}
	cc := a.CompetencyConfirmation
	out := gen.RegistryApplicationPersonalData{
		ApplicationId: req.ApplicationId, OperatorType: gen.OperatorType(a.OperatorType), FullName: opt(a.PII.FullName),
		LegalName: opt(a.PII.LegalName), DateOfBirth: opt(a.PII.DateOfBirth), LegalIdentificationNumber: opt(a.PII.LegalIdentificationNumber),
		PostalAddress: opt(a.PII.PostalAddress), ContactEmail: opt(a.PII.ContactEmail), ContactPhone: opt(a.PII.ContactPhone),
		InsurancePolicyNumber: opt(a.PII.InsurancePolicyNumber), CompetencyConfirmation: &cc,
	}
	if len(a.Authorisations) > 0 {
		var items []map[string]any
		if err := json.Unmarshal(a.Authorisations, &items); err == nil {
			out.Authorisations = &items
		}
	}
	return gen.GetRegistryApplicationPersonalData200JSONResponse(out), nil
}

// StartRegistryApplicationReview takes an application for review.
func (h Handler) StartRegistryApplicationReview(ctx context.Context, req gen.StartRegistryApplicationReviewRequestObject) (gen.StartRegistryApplicationReviewResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	a, err := h.Service.StartReview(ctx, req.ApplicationId, actor)
	if err != nil {
		return nil, err
	}
	return gen.StartRegistryApplicationReview200JSONResponse(applicationBody(&a)), nil
}

// ApproveRegistryApplication approves an application under review.
func (h Handler) ApproveRegistryApplication(ctx context.Context, req gen.ApproveRegistryApplicationRequestObject) (gen.ApproveRegistryApplicationResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	var until *time.Time
	if req.Body != nil {
		until = req.Body.ValidUntil
	}
	a, err := h.Service.Approve(ctx, req.ApplicationId, until, actor)
	if err != nil {
		return nil, err
	}
	return gen.ApproveRegistryApplication200JSONResponse(applicationBody(&a)), nil
}

// RefuseRegistryApplication refuses an application.
func (h Handler) RefuseRegistryApplication(ctx context.Context, req gen.RefuseRegistryApplicationRequestObject) (gen.RefuseRegistryApplicationResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, core.Fieldf("body", "required")
	}
	a, err := h.Service.Refuse(ctx, req.ApplicationId, req.Body.Reason, actor)
	if err != nil {
		return nil, err
	}
	return gen.RefuseRegistryApplication200JSONResponse(applicationBody(&a)), nil
}

// RequestOperatorLink mails an operator its occurrence link; 202
// whatever the number.
func (h Handler) RequestOperatorLink(ctx context.Context, req gen.RequestOperatorLinkRequestObject) (gen.RequestOperatorLinkResponseObject, error) {
	if err := h.Service.needOperatorReports(); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, core.Fieldf("body", "required")
	}
	lang := ""
	if req.Body.Lang != nil {
		lang = string(*req.Body.Lang)
	}
	err := h.Service.RequestLink(ctx, req.Body.RegistrationNumber, lang, apiserver.RequestInfoFrom(ctx).RemoteIP)
	if rl := rateLimited(err); rl != nil {
		return gen.RequestOperatorLink429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: *rl}, nil
	}
	if err != nil {
		return nil, err
	}
	return gen.RequestOperatorLink202Response{}, nil
}

// CreateOperatorOccurrence takes an operator's report through its link.
func (h Handler) CreateOperatorOccurrence(ctx context.Context, req gen.CreateOperatorOccurrenceRequestObject) (gen.CreateOperatorOccurrenceResponseObject, error) {
	rc, err := h.Service.ReportOccurrence(ctx, deref2(req.Params.XOperatorToken), req.Body)
	if err != nil {
		return nil, err
	}
	out := gen.OccurrenceReceipt{OccurrenceId: rc.Report.ID, ReportRef: rc.Report.ReportRef, ReceivedAt: rc.Report.ReceivedAt,
		Within72h: rc.Report.Within72h, State: gen.OccurrenceState(rc.Report.State), Replayed: rc.Replayed}
	if rc.Replayed {
		return gen.CreateOperatorOccurrence200JSONResponse(out), nil
	}
	return gen.CreateOperatorOccurrence201JSONResponse(out), nil
}
