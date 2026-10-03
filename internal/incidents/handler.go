package incidents

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Handler serves /v1/incidents* (inspector, incident_officer).
type Handler struct {
	Service *Service
	Packs   *Packs
}

// Page bounds.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// piiRole says the session holds one of the personal-data roles
// (apiserver.PIIRoles): only such a session builds or downloads a legal
// pack (CLAUDE.md rule 6).
func piiRole(ctx context.Context) bool {
	id, ok := apiserver.IdentityFrom(ctx)
	if !ok {
		return false
	}
	return slices.ContainsFunc(id.Roles, func(r string) bool { return slices.Contains(apiserver.PIIRoles, r) })
}

// EncodeCursor is the opaque cursor after a row.
func EncodeCursor(createdAt time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(createdAt.UTC().Format(time.RFC3339Nano) + "|" + id))
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

// ListIncidents answers one page, newest first.
func (h Handler) ListIncidents(ctx context.Context, req gen.ListIncidentsRequestObject) (gen.ListIncidentsResponseObject, error) {
	p := req.Params
	limit := DefaultLimit
	if p.Limit != nil {
		limit = *p.Limit
	}
	if limit < 1 || limit > MaxLimit {
		return nil, core.Fieldf("limit", "must be between 1 and %d", MaxLimit)
	}
	q := pggen.ListIncidentsParams{ViolationID: p.ViolationId, Lim: int32(limit + 1)}
	if p.Status != nil {
		s := string(*p.Status)
		q.Status = &s
	}
	if p.Kind != nil {
		k := string(*p.Kind)
		q.Kind = &k
	}
	if p.Cursor != nil {
		at, id, err := DecodeCursor(*p.Cursor)
		if err != nil {
			return nil, err
		}
		q.CursorCreated, q.CursorID = &at, &id
	}
	rows, err := h.Service.List(ctx, q)
	if err != nil {
		return nil, err
	}
	out := gen.IncidentPage{Incidents: []gen.IncidentSummary{}}
	for i := range rows {
		if i == limit {
			c := EncodeCursor(rows[i-1].CreatedAt, rows[i-1].IncidentID)
			out.NextCursor = &c
			break
		}
		r := &rows[i]
		out.Incidents = append(out.Incidents, gen.IncidentSummary{IncidentId: r.IncidentID, Kind: gen.IncidentKind(r.Kind),
			OccurredAt: r.OccurredAt, OpenedFrom: gen.IncidentOpenedFrom(r.OpenedFrom), SourceViolationId: r.SourceViolationID,
			Severity: gen.IncidentSeverity(r.Severity), Status: gen.IncidentStatus(r.Status), Assignee: r.Assignee,
			ClosedAt: r.ClosedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt})
	}
	return gen.ListIncidents200JSONResponse(out), nil
}

func aircraftIn(list *[]gen.IncidentAircraftInput) []Aircraft {
	if list == nil {
		return nil
	}
	out := make([]Aircraft, 0, len(*list))
	for _, a := range *list {
		x := Aircraft{Serial: a.Serial, OperatorReg: a.OperatorReg}
		if a.TrackIds != nil {
			x.TrackIDs = *a.TrackIds
		}
		if id := a.Identification; id != nil {
			x.Identification = Identification{Status: deref(id.Status), Reason: deref(id.Reason), Basis: deref(id.Basis),
				EvidenceTrust: deref(id.EvidenceTrust)}
		}
		out = append(out, x)
	}
	return out
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// IncidentOf is the answer for a view.
func IncidentOf(v *View) (gen.Incident, error) {
	inc := v.Incident
	out := gen.Incident{IncidentId: inc.IncidentID, Kind: gen.IncidentKind(inc.Kind), OccurredAt: inc.OccurredAt,
		OpenedFrom: gen.IncidentOpenedFrom(inc.OpenedFrom), SourceViolationId: inc.SourceViolationID, NoticeRef: inc.NoticeRef,
		IntentRefs: inc.IntentRefs, Narrative: inc.Narrative, Severity: gen.IncidentSeverity(inc.Severity),
		Status: gen.IncidentStatus(inc.Status), Assignee: inc.Assignee, ClosedAt: inc.ClosedAt, OpenedBy: inc.OpenedBy,
		CreatedAt: inc.CreatedAt, UpdatedAt: inc.UpdatedAt, Aircraft: []gen.IncidentAircraft{}, Notes: []gen.IncidentNote{},
		EvidencePacks: []gen.EvidencePackSummary{}}
	if out.IntentRefs == nil {
		out.IntentRefs = []string{}
	}
	for _, a := range v.Aircraft {
		var id Identification
		if len(a.Identification) > 0 {
			if err := json.Unmarshal(a.Identification, &id); err != nil {
				return out, err
			}
		}
		tracks := a.TrackIds
		if tracks == nil {
			tracks = []string{}
		}
		out.Aircraft = append(out.Aircraft, gen.IncidentAircraft{Id: a.ID, Serial: a.Serial, OperatorReg: a.OperatorReg,
			RegistryUasId: a.RegistryUasID, TrackIds: tracks, AddedBy: a.AddedBy, AddedAt: a.AddedAt,
			Identification: gen.IncidentIdentification{Status: optional(id.Status), Reason: optional(id.Reason),
				Basis: optional(id.Basis), EvidenceTrust: optional(id.EvidenceTrust)}})
	}
	for _, n := range v.Notes {
		out.Notes = append(out.Notes, gen.IncidentNote{Id: n.ID, Author: n.Author, Body: n.Body, CreatedAt: n.CreatedAt})
	}
	for i := range v.Packs {
		p := &v.Packs[i]
		out.EvidencePacks = append(out.EvidencePacks, gen.EvidencePackSummary{PackId: p.PackID, Kind: gen.EvidencePackKind(p.Kind),
			From: p.WindowFrom, To: p.WindowTo, ContentHash: p.ContentHash, SizeBytes: p.SizeBytes, SignatureKid: p.SignatureKid,
			CreatedBy: p.CreatedBy, CreatedAt: p.CreatedAt})
	}
	return out, nil
}

// CreateIncident opens an incident from an observation or a notice.
func (h Handler) CreateIncident(ctx context.Context, req gen.CreateIncidentRequestObject) (gen.CreateIncidentResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	b := req.Body
	in := NewIncident{Kind: string(b.Kind), OccurredAt: b.OccurredAt, OpenedFrom: string(b.OpenedFrom), NoticeRef: b.NoticeRef,
		Severity: string(b.Severity), Narrative: deref(b.Narrative), Aircraft: aircraftIn(b.Aircraft)}
	if b.IntentRefs != nil {
		in.IntentRefs = *b.IntentRefs
	}
	v, err := h.Service.Open(ctx, actor, in)
	if err != nil {
		return nil, err
	}
	out, err := IncidentOf(&v)
	if err != nil {
		return nil, err
	}
	return gen.CreateIncident201JSONResponse(out), nil
}

// GetIncident answers one incident.
func (h Handler) GetIncident(ctx context.Context, req gen.GetIncidentRequestObject) (gen.GetIncidentResponseObject, error) {
	v, err := h.Service.Get(ctx, req.IncidentId)
	if err != nil {
		return nil, err
	}
	out, err := IncidentOf(&v)
	if err != nil {
		return nil, err
	}
	return gen.GetIncident200JSONResponse(out), nil
}

// UpdateIncident applies a patch.
func (h Handler) UpdateIncident(ctx context.Context, req gen.UpdateIncidentRequestObject) (gen.UpdateIncidentResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	b := req.Body
	p := Patch{Narrative: b.Narrative, Assignee: b.Assignee, IntentRefs: b.IntentRefs, AddAircraft: aircraftIn(b.AddAircraft), Note: b.Note}
	if b.Severity != nil {
		s := string(*b.Severity)
		p.Severity = &s
	}
	if b.Status != nil {
		s := string(*b.Status)
		p.Status = &s
	}
	v, err := h.Service.Update(ctx, actor, req.IncidentId, p)
	if err != nil {
		return nil, err
	}
	out, err := IncidentOf(&v)
	if err != nil {
		return nil, err
	}
	return gen.UpdateIncident200JSONResponse(out), nil
}

// PackOf is the answer for a stored pack.
func PackOf(r *pggen.EvidencePack) (gen.EvidencePack, error) {
	out := gen.EvidencePack{PackId: r.PackID, IncidentId: r.IncidentID, Kind: gen.EvidencePackKind(r.Kind), From: r.WindowFrom,
		To: r.WindowTo, ContentHash: r.ContentHash, SizeBytes: r.SizeBytes, Signature: r.Signature, SignatureKid: r.SignatureKid,
		Purpose: r.Purpose, CaseRef: r.CaseRef, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt}
	if err := json.Unmarshal(r.SealStatement, &out.SealStatement); err != nil {
		return out, err
	}
	if err := json.Unmarshal(r.Manifest, &out.Manifest); err != nil {
		return out, err
	}
	return out, nil
}

// CreateEvidencePack builds and seals a pack.
func (h Handler) CreateEvidencePack(ctx context.Context, req gen.CreateEvidencePackRequestObject) (gen.CreateEvidencePackResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	b := req.Body
	row, err := h.Packs.Create(ctx, actor, piiRole(ctx), req.IncidentId, PackRequest{Kind: string(b.Kind), From: b.From, To: b.To,
		Purpose: b.Purpose, CaseRef: deref(b.CaseRef)})
	if err != nil {
		return nil, err
	}
	out, err := PackOf(&row)
	if err != nil {
		return nil, err
	}
	return gen.CreateEvidencePack201JSONResponse(out), nil
}

// GetEvidencePack answers a pack's manifest.
func (h Handler) GetEvidencePack(ctx context.Context, req gen.GetEvidencePackRequestObject) (gen.GetEvidencePackResponseObject, error) {
	row, err := h.Packs.Get(ctx, req.IncidentId, req.PackId)
	if err != nil {
		return nil, err
	}
	out, err := PackOf(&row)
	if err != nil {
		return nil, err
	}
	return gen.GetEvidencePack200JSONResponse(out), nil
}

// DownloadEvidencePack serves the archive after checking it.
func (h Handler) DownloadEvidencePack(ctx context.Context, req gen.DownloadEvidencePackRequestObject) (gen.DownloadEvidencePackResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	data, row, err := h.Packs.Download(ctx, actor, piiRole(ctx), req.IncidentId, req.PackId, req.Params.Purpose)
	if err != nil {
		return nil, err
	}
	hash := row.ContentHash
	return gen.DownloadEvidencePack200ApplicationzipResponse{Body: bytes.NewReader(data), ContentLength: int64(len(data)),
		Headers: gen.DownloadEvidencePack200ResponseHeaders{XContentSHA256: &hash, XEvidenceSignature: row.Signature}}, nil
}

// VerifyEvidencePack checks a stored pack.
func (h Handler) VerifyEvidencePack(ctx context.Context, req gen.VerifyEvidencePackRequestObject) (gen.VerifyEvidencePackResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	v, err := h.Packs.Verify(ctx, actor, req.IncidentId, req.PackId)
	if err != nil {
		return nil, err
	}
	return gen.VerifyEvidencePack200JSONResponse(gen.EvidencePackVerification{PackId: v.PackID, ContentHash: v.ContentHash,
		RecomputedHash: v.RecomputedHash, HashMatches: v.HashMatches, Problem: v.Problem,
		Signature: gen.EvidencePackVerificationSignature(v.Signature), SignatureDetail: v.SignatureDetail, VerifiedAt: v.VerifiedAt}), nil
}
