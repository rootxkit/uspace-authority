package occurrences

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
)

// Handler serves /v1/occurrences*: the intake (scope occurrences.write),
// the reads (incident_officer, inspector, without the reporter), the
// reporter (incident_officer only) and the officers' handling and export
// (incident_officer).
type Handler struct {
	Service *Service
}

// Page bounds.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

var idPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// EncodeCursor is the opaque cursor after a report.
func EncodeCursor(receivedAt time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(receivedAt.UTC().Format(time.RFC3339Nano) + "|" + id))
}

// DecodeCursor reads a cursor EncodeCursor wrote; the error names it.
func DecodeCursor(s string) (time.Time, string, error) {
	bad := &core.FieldError{Field: "cursor", Reason: "not a cursor of this endpoint"}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", bad
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || !idPattern.MatchString(id) {
		return time.Time{}, "", bad
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, "", bad
	}
	return t, id, nil
}

// CreateOccurrence is the intake of a USSP's or the ANSP's report.
func (h Handler) CreateOccurrence(ctx context.Context, req gen.CreateOccurrenceRequestObject) (gen.CreateOccurrenceResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	in, err := Normalise(req.Body, h.Service.PublicPart)
	if err != nil {
		h.Service.Refused()
		return nil, err
	}
	rc, err := h.Service.Intake(ctx, ClientOrigin(actor), in)
	if err != nil {
		return nil, err
	}
	out := gen.OccurrenceReceipt{OccurrenceId: rc.Report.ID, ReportRef: rc.Report.ReportRef, ReceivedAt: rc.Report.ReceivedAt,
		Within72h: rc.Report.Within72h, State: gen.OccurrenceState(rc.Report.State), Replayed: rc.Replayed}
	if rc.Replayed {
		return gen.CreateOccurrence200JSONResponse(out), nil
	}
	return gen.CreateOccurrence201JSONResponse(out), nil
}

// ListOccurrences answers one page, newest received first.
func (h Handler) ListOccurrences(ctx context.Context, req gen.ListOccurrencesRequestObject) (gen.ListOccurrencesResponseObject, error) {
	p := req.Params
	limit := DefaultLimit
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > MaxLimit {
		return nil, core.Fieldf("limit", "must be between 1 and %d", MaxLimit)
	}
	f := Filter{From: p.From, To: p.To, Limit: limit + 1}
	if p.State != nil {
		f.State = string(*p.State)
	}
	if p.Category != nil {
		f.Category = string(*p.Category)
	}
	if p.Channel != nil {
		f.Channel = string(*p.Channel)
	}
	if p.Cursor != nil {
		at, id, err := DecodeCursor(*p.Cursor)
		if err != nil {
			return nil, err
		}
		f.CursorReceived, f.CursorID = &at, id
	}
	rows, err := h.Service.List(ctx, f)
	if err != nil {
		return nil, err
	}
	out := gen.OccurrencePage{Occurrences: []gen.OccurrenceSummary{}}
	for i := range rows {
		if i == limit {
			c := EncodeCursor(rows[i-1].ReceivedAt, rows[i-1].ID)
			out.NextCursor = &c
			break
		}
		r := &rows[i]
		out.Occurrences = append(out.Occurrences, gen.OccurrenceSummary{OccurrenceId: r.ID, Channel: gen.OccurrenceChannel(r.Channel),
			Origin: gen.OccurrenceSummaryOrigin(r.Origin), Category: gen.OccurrenceCategory(r.Category), OccurredAt: r.OccurredAt,
			BecameAwareAt: r.BecameAwareAt, ReceivedAt: r.ReceivedAt, ReportedAt: r.ReportedAt, Within72h: r.Within72h,
			State: gen.OccurrenceState(r.State), RiskClassification: ptr(r.RiskClassification), HasReporterPerson: len(r.PersonSealed) > 0,
			ClosedAt: r.ClosedAt, UpdatedAt: r.UpdatedAt})
	}
	return gen.ListOccurrences200JSONResponse(out), nil
}

func ptr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// OccurrenceOf is the answer for a report: never its reporter.
func OccurrenceOf(r *Report) gen.Occurrence {
	out := gen.Occurrence{OccurrenceId: r.ID, Channel: gen.OccurrenceChannel(r.Channel), Origin: gen.OccurrenceOrigin(r.Origin),
		Category: gen.OccurrenceCategory(r.Category), OccurredAt: r.OccurredAt, BecameAwareAt: r.BecameAwareAt, ReceivedAt: r.ReceivedAt,
		ReportedAt: r.ReportedAt, Within72h: r.Within72h, ReportDeadlineS: r.DeadlineS, State: gen.OccurrenceState(r.State),
		RiskClassification: ptr(r.RiskClassification), ClassifiedAt: r.ClassifiedAt, ClassifiedBy: ptr(r.ClassifiedBy),
		HasReporterPerson: len(r.PersonSealed) > 0, Aircraft: []gen.OccurrenceAircraft{}, Manned: []gen.OccurrenceManned{},
		IntentRefs: r.IntentRefs, Narrative: r.Narrative, EvidenceUrls: r.EvidenceURLs, Analysis: r.Analysis, FollowUp: r.FollowUp,
		ClosedAt: r.ClosedAt, UpdatedAt: r.UpdatedAt, UpdatedBy: ptr(r.UpdatedBy)}
	if out.IntentRefs == nil {
		out.IntentRefs = []string{}
	}
	if out.EvidenceUrls == nil {
		out.EvidenceUrls = []string{}
	}
	for _, a := range r.Aircraft {
		out.Aircraft = append(out.Aircraft, gen.OccurrenceAircraft{Serial: ptr(a.Serial), OperatorReg: ptr(a.OperatorReg),
			FlightId: ptr(a.FlightID), AuthorisationNumber: ptr(a.AuthorisationNumber)})
	}
	for _, m := range r.Manned {
		out.Manned = append(out.Manned, gen.OccurrenceManned{Icao24: ptr(m.ICAO24), Callsign: ptr(m.Callsign)})
	}
	if s := r.MinSeparation; s != nil {
		out.MinSeparation = &gen.OccurrenceSeparation{HM: s.HM, VM: s.VM, At: s.At}
	}
	return out
}

// GetOccurrence answers one report without its reporter.
func (h Handler) GetOccurrence(ctx context.Context, req gen.GetOccurrenceRequestObject) (gen.GetOccurrenceResponseObject, error) {
	r, err := h.Service.Get(ctx, req.OccurrenceId)
	if err != nil {
		return nil, err
	}
	return gen.GetOccurrence200JSONResponse(OccurrenceOf(&r)), nil
}

// GetOccurrenceReporter answers the reporter, audited with the purpose.
func (h Handler) GetOccurrenceReporter(ctx context.Context, req gen.GetOccurrenceReporterRequestObject) (gen.GetOccurrenceReporterResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.Service.Reporter(ctx, actor, req.OccurrenceId, req.Params.Purpose)
	if err != nil {
		return nil, err
	}
	noStore := "no-store"
	return gen.GetOccurrenceReporter200JSONResponse{Body: gen.OccurrenceReporter{OccurrenceId: v.OccurrenceID, ReporterOrg: v.ReporterOrg,
		ReportRef: v.ReportRef, PersonRef: ptr(v.PersonRef)}, Headers: gen.GetOccurrenceReporter200ResponseHeaders{CacheControl: &noStore}}, nil
}

// ClassifyOccurrence records the risk class.
func (h Handler) ClassifyOccurrence(ctx context.Context, req gen.ClassifyOccurrenceRequestObject) (gen.ClassifyOccurrenceResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	r, err := h.Service.Classify(ctx, actor, req.OccurrenceId, req.Body.RiskClassification)
	if err != nil {
		return nil, err
	}
	return gen.ClassifyOccurrence200JSONResponse(OccurrenceOf(&r)), nil
}

// UpdateOccurrenceAnalysis records the analysis, the follow-up and the
// state.
func (h Handler) UpdateOccurrenceAnalysis(ctx context.Context, req gen.UpdateOccurrenceAnalysisRequestObject) (gen.UpdateOccurrenceAnalysisResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	p := AnalysisPatch{Analysis: req.Body.Analysis, FollowUp: req.Body.FollowUp}
	if req.Body.State != nil {
		s := string(*req.Body.State)
		p.State = &s
	}
	r, err := h.Service.UpdateAnalysis(ctx, actor, req.OccurrenceId, p)
	if err != nil {
		return nil, err
	}
	return gen.UpdateOccurrenceAnalysis200JSONResponse(OccurrenceOf(&r)), nil
}

// ExportOccurrences builds and seals a de-identified export.
func (h Handler) ExportOccurrences(ctx context.Context, req gen.ExportOccurrencesRequestObject) (gen.ExportOccurrencesResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	res, err := h.Service.Export(ctx, actor, ExportRequest{From: req.Body.From, To: req.Body.To, Format: deref(req.Body.Format)})
	if err != nil {
		return nil, err
	}
	e := res.Export
	return gen.ExportOccurrences201JSONResponse{ExportId: e.ID, Format: e.Format, CreatedAt: e.CreatedAt, RecordCount: e.RecordCount,
		SizeBytes: e.SizeBytes, ContentHash: e.ContentHash, Content: string(res.Content)}, nil
}
