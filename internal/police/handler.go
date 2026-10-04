package police

import (
	"bytes"
	"context"
	"errors"
	"math"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Handler serves /v1/police/* and GET /v1/audit/dpo-report
// (apiserver.PoliceHandler, apiserver.DPOHandler).
type Handler struct {
	Service *Service
}

var (
	_ apiserver.PoliceHandler = Handler{}
	_ apiserver.DPOHandler    = Handler{}
)

// rateLimited is the 429 body and Retry-After of a spent budget, or nil.
func rateLimited(err error) *gen.RateLimitedApplicationProblemPlusJSONResponse {
	var spent *BudgetSpentError
	if !errors.As(err, &spent) {
		return nil
	}
	secs := max(1, int(math.Ceil(spent.RetryAfter.Seconds())))
	detail := spent.Error()
	p := httpx.NewProblem(429, httpx.SlugRateLimited, "Too many requests", detail)
	return &gen.RateLimitedApplicationProblemPlusJSONResponse{
		Body:    gen.Problem{Type: p.Type, Title: p.Title, Status: p.Status, Detail: &detail, Errors: []gen.FieldProblem{}},
		Headers: gen.RateLimitedResponseHeaders{RetryAfter: &secs},
	}
}

// QueryPoliceAircraft serves GET /v1/police/aircraft.
func (h Handler) QueryPoliceAircraft(ctx context.Context, req gen.QueryPoliceAircraftRequestObject) (gen.QueryPoliceAircraftResponseObject, error) {
	p := req.Params
	out, err := h.Service.QueryAircraft(ctx, AircraftQuery{BBox: p.Bbox, At: p.At, Purpose: p.Purpose, CaseRef: p.CaseRef})
	if rl := rateLimited(err); rl != nil {
		return gen.QueryPoliceAircraft429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: *rl}, nil
	}
	if err != nil {
		return nil, err
	}
	return gen.QueryPoliceAircraft200JSONResponse(out), nil
}

// QueryPoliceOperator serves GET /v1/police/operators/{reg}.
func (h Handler) QueryPoliceOperator(ctx context.Context, req gen.QueryPoliceOperatorRequestObject) (gen.QueryPoliceOperatorResponseObject, error) {
	out, err := h.Service.QueryOperator(ctx, LookupQuery{Term: req.Reg, Purpose: req.Params.Purpose, CaseRef: req.Params.CaseRef})
	if rl := rateLimited(err); rl != nil {
		return gen.QueryPoliceOperator429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: *rl}, nil
	}
	if err != nil {
		return nil, err
	}
	return gen.QueryPoliceOperator200JSONResponse(out), nil
}

// QueryPoliceSerial serves GET /v1/police/serials/{serial}.
func (h Handler) QueryPoliceSerial(ctx context.Context, req gen.QueryPoliceSerialRequestObject) (gen.QueryPoliceSerialResponseObject, error) {
	out, err := h.Service.QuerySerial(ctx, LookupQuery{Term: req.Serial, Purpose: req.Params.Purpose, CaseRef: req.Params.CaseRef})
	if rl := rateLimited(err); rl != nil {
		return gen.QueryPoliceSerial429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: *rl}, nil
	}
	if err != nil {
		return nil, err
	}
	return gen.QueryPoliceSerial200JSONResponse(out), nil
}

// CreatePoliceExport serves POST /v1/police/exports.
func (h Handler) CreatePoliceExport(ctx context.Context, req gen.CreatePoliceExportRequestObject) (gen.CreatePoliceExportResponseObject, error) {
	if req.Body == nil {
		return nil, httpx.Refuse(400, httpx.SlugValidation, "a body is required")
	}
	b := req.Body
	r := ExportRequest{Purpose: b.Purpose, CaseRef: b.CaseRef, From: b.From, To: b.To}
	if b.IncidentId != nil {
		r.IncidentID = *b.IncidentId
	}
	if b.Query != nil {
		box := b.Query.Bbox
		r.BBox = &box
	}
	out, err := h.Service.Export(ctx, r)
	if rl := rateLimited(err); rl != nil {
		return gen.CreatePoliceExport429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: *rl}, nil
	}
	if err != nil {
		return nil, err
	}
	return gen.CreatePoliceExport201JSONResponse(out), nil
}

// DownloadPoliceExport serves GET /v1/police/exports/{pack_id}/download.
func (h Handler) DownloadPoliceExport(ctx context.Context, req gen.DownloadPoliceExportRequestObject) (gen.DownloadPoliceExportResponseObject, error) {
	data, row, err := h.Service.Download(ctx, req.PackId, req.Params.Purpose, req.Params.CaseRef)
	if rl := rateLimited(err); rl != nil {
		return gen.DownloadPoliceExport429ApplicationProblemPlusJSONResponse{RateLimitedApplicationProblemPlusJSONResponse: *rl}, nil
	}
	if err != nil {
		return nil, err
	}
	hash := row.ContentHash
	return gen.DownloadPoliceExport200ApplicationzipResponse{Body: bytes.NewReader(data), ContentLength: int64(len(data)),
		Headers: gen.DownloadPoliceExport200ResponseHeaders{XContentSHA256: &hash, XEvidenceSignature: row.Signature}}, nil
}

// GetDPOReport serves GET /v1/audit/dpo-report.
func (h Handler) GetDPOReport(ctx context.Context, req gen.GetDPOReportRequestObject) (gen.GetDPOReportResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.Service.DPOReport(ctx, actor, req.Params.Month)
	if err != nil {
		return nil, err
	}
	return gen.GetDPOReport200JSONResponse(out), nil
}
