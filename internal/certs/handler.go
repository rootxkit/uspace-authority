package certs

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// RegisterMaxAge is how long a client or cache may keep the public
// register.
const RegisterMaxAge = 60 * time.Second

// Handler serves /v1/certificates* (apiserver.CertificatesHandler).
type Handler struct {
	Service *Service
	// Limit rate-limits the public register per client address (the
	// trusted proxies' X-Forwarded-For, httpx.RemoteIP); nil admits all.
	Limit *httpx.RateLimiter
}

var _ apiserver.CertificatesHandler = Handler{}

func noBody() error { return &core.FieldError{Field: "body", Reason: "required"} }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func certOut(r *pggen.Certificate) gen.Certificate {
	services := make([]gen.CertificateService, 0, len(r.Services))
	for _, s := range r.Services {
		services = append(services, gen.CertificateService(s))
	}
	limits := r.Limitations
	if limits == nil {
		limits = []string{}
	}
	utc := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		u := t.UTC()
		return &u
	}
	return gen.Certificate{
		Id: r.ID, Holder: gen.CertificateHolder(r.Holder), HolderName: r.HolderName, HolderAddress: r.HolderAddress,
		HolderEmail: r.HolderEmail, HolderPhone: r.HolderPhone, HolderUrl: r.HolderUrl, Code: r.Code, ClientId: r.ClientID,
		BaseUrl: r.BaseUrl, Services: services, Conditions: r.Conditions, Limitations: limits, TermsUrl: r.TermsUrl,
		IssuedAt: r.IssuedAt.UTC(), ValidUntil: r.ValidUntil.UTC(), Status: gen.CertificateStatus(r.Status),
		Operations: gen.CertificateOperations(r.Operations), OperationsStartedAt: utc(r.OperationsStartedAt),
		OperationsCeasedAt: utc(r.OperationsCeasedAt), Limited: r.Limited, Suspended: r.Suspended, EndedAt: utc(r.EndedAt),
		StatusReason: r.StatusReason, StatusChangedAt: r.StatusChangedAt.UTC(), StatusChangedBy: r.StatusChangedBy,
		LapseUnusedAfterMonths: int(r.LapseUnusedAfterMonths), LapseCeasedAfterMonths: int(r.LapseCeasedAfterMonths),
		LapsesAt: LapsesAt(r), CreatedAt: r.CreatedAt.UTC(), CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt.UTC(), UpdatedBy: r.UpdatedBy,
	}
}

func pubOut(p Publication) gen.ListPublication {
	out := gen.ListPublication{State: gen.ListPublicationState(p.State)}
	if p.Reason != "" {
		r := p.Reason
		out.Reason = &r
	}
	if p.PublicationID != 0 {
		id := p.PublicationID
		out.PublicationId = &id
	}
	return out
}

func changeOut(c Change) gen.CertificateChange {
	out := gen.CertificateChange{Certificate: certOut(&c.Certificate), ListPublication: pubOut(c.List), TokensValidUntil: c.TokensValidUntil}
	if c.ClientStatus != "" {
		st := gen.CertificateChangeClientStatus(c.ClientStatus)
		out.ClientStatus = &st
	}
	return out
}

func noticeOut(n *pggen.CertificateNotice) gen.CertificateNotice {
	return gen.CertificateNotice{Id: n.ID, State: gen.CertificateNoticeState(n.State), At: n.At.UTC(), Reference: n.Reference,
		Source: gen.CertificateNoticeSource(n.Source), RecordedBy: n.RecordedBy, ReceivedAt: n.ReceivedAt.UTC()}
}

func noticeResultOut(r NoticeResult) gen.CertificateNoticeResult {
	return gen.CertificateNoticeResult{Notice: noticeOut(&r.Notice), Certificate: certOut(&r.Certificate), Replayed: r.Replayed,
		ListPublication: pubOut(r.List)}
}

// ListCertificates lists the certificates, newest first.
func (h Handler) ListCertificates(ctx context.Context, req gen.ListCertificatesRequestObject) (gen.ListCertificatesResponseObject, error) {
	var holder, status *string
	if req.Params.Holder != nil {
		v := string(*req.Params.Holder)
		holder = &v
	}
	if req.Params.Status != nil {
		v := string(*req.Params.Status)
		status = &v
	}
	rows, err := h.Service.DB.Queries().ListCertificates(ctx, pggen.ListCertificatesParams{Holder: holder, Status: status, MaxRows: MaxListRows})
	if err != nil {
		return nil, err
	}
	out := gen.CertificateList{Certificates: make([]gen.Certificate, 0, len(rows))}
	for i := range rows {
		out.Certificates = append(out.Certificates, certOut(&rows[i]))
	}
	return gen.ListCertificates200JSONResponse(out), nil
}

// IssueCertificate issues a certificate with its client.
func (h Handler) IssueCertificate(ctx context.Context, req gen.IssueCertificateRequestObject) (gen.IssueCertificateResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, noBody()
	}
	in := IssueInput{
		Holder: string(b.Holder), HolderName: b.HolderName, HolderAddress: deref(b.HolderAddress), HolderEmail: deref(b.HolderEmail),
		HolderPhone: deref(b.HolderPhone), HolderURL: deref(b.HolderUrl), Code: b.Code, BaseURL: deref(b.BaseUrl),
		Conditions: deref(b.Conditions), TermsURL: deref(b.TermsUrl), ValidFrom: b.ValidFrom, ValidUntil: b.ValidUntil,
		AuthMethod: string(b.AuthMethod),
	}
	for _, s := range b.Services {
		in.Services = append(in.Services, string(s))
	}
	if b.Limitations != nil {
		in.Limitations = *b.Limitations
	}
	if b.Jwks != nil {
		raw, err := json.Marshal(*b.Jwks)
		if err != nil {
			return nil, core.Fieldf("jwks", "not a JSON object")
		}
		in.JWKS = raw
	}
	res, err := h.Service.Issue(ctx, in, actor)
	if err != nil {
		return nil, err
	}
	noStore := "no-store"
	out := gen.CertificateIssued{
		Certificate: certOut(&res.Certificate),
		Client: gen.CertificateClient{ClientId: res.Client.ID, Status: gen.CertificateClientStatus(res.Client.Status),
			Scopes: res.Client.Scopes, Audiences: res.Client.Audiences, AuthMethod: gen.CertificateClientAuthMethod(res.Client.AuthMethod)},
	}
	if res.Secret != "" {
		secret := res.Secret
		out.ClientSecret = &secret
	}
	return gen.IssueCertificate201JSONResponse{Body: out, Headers: gen.IssueCertificate201ResponseHeaders{CacheControl: &noStore}}, nil
}

// GetCertificateRegister serves the public register (Art. 18(a)):
// status-only, cacheable, rate-limited.
func (h Handler) GetCertificateRegister(ctx context.Context, _ gen.GetCertificateRegisterRequestObject) (gen.GetCertificateRegisterResponseObject, error) {
	if h.Limit != nil {
		if ok, wait := h.Limit.Allow(apiserver.RequestInfoFrom(ctx).RemoteIP); !ok {
			h.Service.inc(CounterRegisterLimited)
			secs := max(1, int(math.Ceil(wait.Seconds())))
			p := httpx.NewProblem(http.StatusTooManyRequests, httpx.SlugRateLimited, "Too many requests", "the client's request budget is spent")
			return gen.GetCertificateRegister429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: gen.RateLimitedApplicationProblemPlusJSONResponse{
				Body:    gen.Problem{Type: p.Type, Title: p.Title, Status: p.Status, Detail: &p.Detail, Errors: []gen.FieldProblem{}},
				Headers: gen.RateLimitedResponseHeaders{RetryAfter: &secs},
			}}, nil
		}
	}
	q := h.Service.DB.Queries()
	now, err := q.DBNow(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := q.CertificateRegister(ctx, MaxRegisterRow)
	if err != nil {
		return nil, err
	}
	out := RegisterOf(rows, now)
	h.Service.inc(CounterRegisterServed)
	cc := "public, max-age=" + strconv.Itoa(int(RegisterMaxAge.Seconds()))
	return gen.GetCertificateRegister200JSONResponse{Body: out, Headers: gen.GetCertificateRegister200ResponseHeaders{CacheControl: &cc}}, nil
}

// RegisterOf is the public register of rows: the status-only columns
// the query reads, nothing else (a test holds the response schema to
// it).
func RegisterOf(rows []pggen.CertificateRegisterRow, now time.Time) gen.CertificateRegister {
	out := gen.CertificateRegister{GeneratedAt: now.UTC(), Certificates: make([]gen.CertificateRegisterEntry, 0, len(rows))}
	for i := range rows {
		r := &rows[i]
		services := make([]gen.CertificateService, 0, len(r.Services))
		for _, s := range r.Services {
			services = append(services, gen.CertificateService(s))
		}
		limits := r.Limitations
		if limits == nil {
			limits = []string{}
		}
		out.Certificates = append(out.Certificates, gen.CertificateRegisterEntry{
			CertificateId: r.ID, Holder: gen.CertificateHolder(r.Holder), HolderName: r.HolderName, Code: r.Code,
			Services: services, Status: gen.CertificateStatus(r.Status), ValidFrom: r.IssuedAt.UTC(), ValidUntil: r.ValidUntil.UTC(),
			Limitations: limits,
		})
	}
	return out
}

// PublishUSSPList queues the USSP list now.
func (h Handler) PublishUSSPList(ctx context.Context, _ gen.PublishUSSPListRequestObject) (gen.PublishUSSPListResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	pub, wanted, n, err := h.Service.PublishList(ctx, actor)
	if err != nil {
		return nil, err
	}
	return gen.PublishUSSPList200JSONResponse(gen.USSPListPublication{PublicationId: pub.PublicationID, Ussps: n, Wanted: wanted}), nil
}

// GetCertificate reads one certificate with its newest notices.
func (h Handler) GetCertificate(ctx context.Context, req gen.GetCertificateRequestObject) (gen.GetCertificateResponseObject, error) {
	q := h.Service.DB.Queries()
	row, err := q.CertificateByID(ctx, req.Id)
	if store.IsNoRows(err) {
		return nil, notFound(req.Id)
	}
	if err != nil {
		return nil, err
	}
	notices, err := q.ListCertificateNotices(ctx, pggen.ListCertificateNoticesParams{CertificateID: req.Id, MaxRows: MaxNoticesRead})
	if err != nil {
		return nil, err
	}
	out := gen.CertificateDetail{Certificate: certOut(&row), Notices: make([]gen.CertificateNotice, 0, len(notices))}
	for i := range notices {
		out.Notices = append(out.Notices, noticeOut(&notices[i]))
	}
	if c, err := q.OAuthClient(ctx, row.ClientID); err == nil {
		st := gen.CertificateDetailClientStatus(c.Status)
		out.ClientStatus = &st
	} else if !store.IsNoRows(err) {
		return nil, err
	}
	return gen.GetCertificate200JSONResponse(out), nil
}

// UpdateCertificate corrects a certificate's details.
func (h Handler) UpdateCertificate(ctx context.Context, req gen.UpdateCertificateRequestObject) (gen.UpdateCertificateResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, noBody()
	}
	c, err := h.Service.Update(ctx, req.Id, Patch{
		HolderName: b.HolderName, HolderAddress: b.HolderAddress, HolderEmail: b.HolderEmail, HolderPhone: b.HolderPhone,
		HolderURL: b.HolderUrl, BaseURL: b.BaseUrl, Conditions: b.Conditions, TermsURL: b.TermsUrl, Limitations: b.Limitations,
		ValidUntil: b.ValidUntil,
	}, actor)
	if err != nil {
		return nil, err
	}
	return gen.UpdateCertificate200JSONResponse(changeOut(c)), nil
}

func noticeIn(b *gen.CertificateStatusNotice) NoticeInput {
	return NoticeInput{State: string(b.State), At: b.At, Reference: deref(b.Reference)}
}

// PostCertificateStatus records the holder's own notice (02 F7): its
// client's token, verified by Authorize for certificates.status, must
// be this issuer's and name the certificate's client as sub.
func (h Handler) PostCertificateStatus(ctx context.Context, req gen.PostCertificateStatusRequestObject) (gen.PostCertificateStatusResponseObject, error) {
	id, ok := apiserver.IdentityFrom(ctx)
	if !ok || id.Session {
		return nil, httpx.Refuse(http.StatusForbidden, httpx.SlugForbidden, "an ecosystem token of the holder's client is required")
	}
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	r, err := h.Service.RecordNotice(ctx, req.Id, noticeIn(req.Body), SourceMachine, &Caller{Subject: id.Subject, Issuer: id.Issuer}, actor)
	if err != nil {
		return nil, err
	}
	if r.Replayed {
		return gen.PostCertificateStatus200JSONResponse(noticeResultOut(r)), nil
	}
	return gen.PostCertificateStatus201JSONResponse(noticeResultOut(r)), nil
}

// RecordCertificateStatusNotice enters a notice received by letter.
func (h Handler) RecordCertificateStatusNotice(ctx context.Context, req gen.RecordCertificateStatusNoticeRequestObject) (gen.RecordCertificateStatusNoticeResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	r, err := h.Service.RecordNotice(ctx, req.Id, noticeIn(req.Body), SourceManual, nil, actor)
	if err != nil {
		return nil, err
	}
	if r.Replayed {
		return gen.RecordCertificateStatusNotice200JSONResponse(noticeResultOut(r)), nil
	}
	return gen.RecordCertificateStatusNotice201JSONResponse(noticeResultOut(r)), nil
}

func (h Handler) transition(ctx context.Context, id, action string, body *gen.CertificateReason) (Change, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return Change{}, err
	}
	if body == nil {
		return Change{}, noBody()
	}
	return h.Service.Transition(ctx, id, action, body.Reason, nil, actor)
}

// SuspendCertificate suspends a certificate and its client.
func (h Handler) SuspendCertificate(ctx context.Context, req gen.SuspendCertificateRequestObject) (gen.SuspendCertificateResponseObject, error) {
	c, err := h.transition(ctx, req.Id, ActionSuspend, req.Body)
	if err != nil {
		return nil, err
	}
	return gen.SuspendCertificate200JSONResponse(changeOut(c)), nil
}

// LimitCertificate limits a certificate.
func (h Handler) LimitCertificate(ctx context.Context, req gen.LimitCertificateRequestObject) (gen.LimitCertificateResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, noBody()
	}
	c, err := h.Service.Transition(ctx, req.Id, ActionLimit, req.Body.Reason, req.Body.Limitations, actor)
	if err != nil {
		return nil, err
	}
	return gen.LimitCertificate200JSONResponse(changeOut(c)), nil
}

// RevokeCertificate revokes a certificate and its client.
func (h Handler) RevokeCertificate(ctx context.Context, req gen.RevokeCertificateRequestObject) (gen.RevokeCertificateResponseObject, error) {
	c, err := h.transition(ctx, req.Id, ActionRevoke, req.Body)
	if err != nil {
		return nil, err
	}
	return gen.RevokeCertificate200JSONResponse(changeOut(c)), nil
}

// ReinstateCertificate lifts a suspension, or else a limitation.
func (h Handler) ReinstateCertificate(ctx context.Context, req gen.ReinstateCertificateRequestObject) (gen.ReinstateCertificateResponseObject, error) {
	c, err := h.transition(ctx, req.Id, ActionReinstate, req.Body)
	if err != nil {
		return nil, err
	}
	return gen.ReinstateCertificate200JSONResponse(changeOut(c)), nil
}
