package violations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Handler serves /v1/violations* (inspector).
type Handler struct {
	Service *Service
}

// Page bounds.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// ParseBBox reads min_lon,min_lat,max_lon,max_lat (WGS84 degrees, min
// below max, finite and in range); the error names the parameter.
func ParseBBox(s string) (minLon, minLat, maxLon, maxLat float64, err error) {
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return 0, 0, 0, 0, &core.FieldError{Field: "bbox", Reason: "must be min_lon,min_lat,max_lon,max_lat"}
	}
	var v [4]float64
	for i, p := range parts {
		f, perr := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if perr != nil || !core.IsFinite(f) {
			return 0, 0, 0, 0, &core.FieldError{Field: "bbox", Reason: "every member must be a finite number"}
		}
		v[i] = f
	}
	switch {
	case v[0] < -180 || v[2] > 180 || v[1] < -90 || v[3] > 90:
		return 0, 0, 0, 0, &core.FieldError{Field: "bbox", Reason: "outside WGS84 degrees"}
	case !(v[0] < v[2]) || !(v[1] < v[3]):
		return 0, 0, 0, 0, &core.FieldError{Field: "bbox", Reason: "min must be below max"}
	}
	return v[0], v[1], v[2], v[3], nil
}

// EncodeCursor is the opaque cursor after a row.
func EncodeCursor(openedAt time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(openedAt.UTC().Format(time.RFC3339Nano) + "|" + id))
}

// DecodeCursor reads a cursor EncodeCursor wrote; the error names it.
func DecodeCursor(s string) (time.Time, string, error) {
	bad := &core.FieldError{Field: "cursor", Reason: "not a cursor of this endpoint"}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", bad
	}
	at, id, ok := strings.Cut(string(raw), "|")
	if !ok || id == "" {
		return time.Time{}, "", bad
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return time.Time{}, "", bad
	}
	return t, id, nil
}

// ListViolations answers one page, newest first.
func (h Handler) ListViolations(ctx context.Context, req gen.ListViolationsRequestObject) (gen.ListViolationsResponseObject, error) {
	p := req.Params
	limit := DefaultLimit
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > MaxLimit {
		return nil, core.Fieldf("limit", "must be between 1 and %d", MaxLimit)
	}
	q := pggen.ListViolationsParams{FromTs: p.From, ToTs: p.To, Lim: int32(limit + 1)}
	if p.Status != nil {
		st := string(*p.Status)
		q.Status = &st
	}
	if p.Kind != nil {
		k := string(*p.Kind)
		q.Kind = &k
	}
	if p.Bbox != nil {
		minLon, minLat, maxLon, maxLat, err := ParseBBox(*p.Bbox)
		if err != nil {
			return nil, err
		}
		q.MinLon, q.MinLat, q.MaxLon, q.MaxLat = &minLon, &minLat, &maxLon, &maxLat
	}
	if p.Cursor != nil {
		at, id, err := DecodeCursor(*p.Cursor)
		if err != nil {
			return nil, err
		}
		q.CursorOpened, q.CursorID = &at, &id
	}
	rows, err := h.Service.List(ctx, q)
	if err != nil {
		return nil, err
	}
	out := gen.ViolationPage{Violations: []gen.ViolationSummary{}}
	for i := range rows {
		if i == limit {
			c := EncodeCursor(rows[i-1].OpenedAt, rows[i-1].ViolationID)
			out.NextCursor = &c
			break
		}
		out.Violations = append(out.Violations, summaryOf(&rows[i]))
	}
	return gen.ListViolations200JSONResponse(out), nil
}

func peakOf(name *string, value *float64) *gen.ViolationPeak {
	if name == nil || value == nil {
		return nil
	}
	return &gen.ViolationPeak{Name: *name, Value: *value}
}

func summaryOf(r *pggen.ListViolationsRow) gen.ViolationSummary {
	return gen.ViolationSummary{
		ViolationId: r.ViolationID, Kind: gen.ViolationKind(r.Kind), Severity: gen.ViolationSummarySeverity(r.Severity),
		TrackId: r.TrackID, Serial: r.Serial, OperatorReg: r.OperatorReg, ZoneId: r.ZoneID, ZoneType: r.ZoneType,
		DetectorState: gen.ViolationSummaryDetectorState(r.DetectorState), OpenedAt: r.OpenedAt, ClosedAt: r.ClosedAt,
		ClearReason: r.ClearReason, LastCapturedAt: r.LastCapturedAt, PolicyVersion: r.PolicyVersion,
		Peak: peakOf(r.PeakName, r.PeakValue), InUspace: r.InUspace, EvidenceTrust: gen.ViolationSummaryEvidenceTrust(r.EvidenceTrust),
		ExcerptSamples: int(r.ExcerptSamples), Cell5: r.Cell5, Status: gen.ViolationStatus(r.Status), ReviewedAt: r.ReviewedAt,
	}
}

func objectOf(raw []byte) (*map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func objectsOf(raw []byte) ([]map[string]any, error) {
	out := []map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ViolationOf is the full answer for a stored row.
func ViolationOf(r pggen.GetViolationRow) (gen.Violation, error) {
	v := gen.Violation{
		ViolationId: r.ViolationID, Kind: gen.ViolationKind(r.Kind), Severity: gen.ViolationSeverity(r.Severity), AlertKey: r.AlertKey,
		TrackId: r.TrackID, Serial: r.Serial, OperatorReg: r.OperatorReg, RegistryUasId: r.RegistryUasID, ZoneId: r.ZoneID,
		ZoneVersion: r.ZoneVersion, ZoneType: r.ZoneType, DetectorState: gen.ViolationDetectorState(r.DetectorState),
		OpenedAt: r.OpenedAt, ClosedAt: r.ClosedAt, ClearReason: r.ClearReason, LastCapturedAt: r.LastCapturedAt,
		PolicyVersion: r.PolicyVersion, Peak: peakOf(r.PeakName, r.PeakValue), InUspace: r.InUspace,
		EvidenceTrust: gen.ViolationEvidenceTrust(r.EvidenceTrust), EvidenceTrackIds: r.EvidenceTrackIds,
		ExcerptSamples: int(r.ExcerptSamples), ExcerptTruncated: r.ExcerptTruncated, Cell5: r.Cell5,
		Status: gen.ViolationStatus(r.Status), ReviewedBy: r.ReviewedBy, ReviewedAt: r.ReviewedAt, ReviewNote: r.ReviewNote,
		IncidentRequested: r.IncidentRequested,
	}
	detail, err := objectOf(r.Detail)
	if err != nil {
		return v, err
	}
	v.Detail = map[string]any{}
	if detail != nil {
		v.Detail = *detail
	}
	if v.ClearingDetail, err = objectOf(r.ClearingDetail); err != nil {
		return v, err
	}
	if v.TerrainSource, err = objectOf(r.TerrainSource); err != nil {
		return v, err
	}
	if v.EvidenceRefs, err = objectsOf(r.EvidenceRefs); err != nil {
		return v, err
	}
	if v.EvidenceExcerpt, err = objectsOf(r.EvidenceExcerpt); err != nil {
		return v, err
	}
	if v.EvidenceTrackIds == nil {
		v.EvidenceTrackIds = []string{}
	}
	return v, nil
}

// GetViolation answers one violation with its excerpt.
func (h Handler) GetViolation(ctx context.Context, req gen.GetViolationRequestObject) (gen.GetViolationResponseObject, error) {
	r, err := h.Service.Get(ctx, req.ViolationId)
	if err != nil {
		return nil, err
	}
	v, err := ViolationOf(r)
	if err != nil {
		return nil, err
	}
	return gen.GetViolation200JSONResponse(v), nil
}

// ReviewViolation records an inspector's decision.
func (h Handler) ReviewViolation(ctx context.Context, req gen.ReviewViolationRequestObject) (gen.ReviewViolationResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	r, err := h.Service.Review(ctx, actor, req.ViolationId, string(req.Body.Decision), req.Body.Note)
	if err != nil {
		return nil, err
	}
	v, err := ViolationOf(r)
	if err != nil {
		return nil, err
	}
	return gen.ReviewViolation200JSONResponse(v), nil
}
