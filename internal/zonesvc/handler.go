package zonesvc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Handler serves /v1/zones* and /v1/uspace* (apiserver.ZonesHandler,
// apiserver.USpaceHandler).
type Handler struct {
	Service *Service
}

var (
	_ apiserver.ZonesHandler  = Handler{}
	_ apiserver.USpaceHandler = Handler{}
)

// defaultPageSize is a list page without a limit.
const defaultPageSize = 100

func bodyRequired() error {
	return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", &core.FieldError{Field: "body", Reason: "required"})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func optionalOut(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func designationOut(d *Designation) *gen.USpaceDesignation {
	if d == nil {
		return nil
	}
	out := gen.USpaceDesignation{
		AirspaceName: d.Name, InControlledAirspace: d.InControlledAirspace, RiskAssessmentRef: optionalOut(d.RiskAssessmentRef),
		AtsProviderId: optionalOut(d.ATSProviderID), CispId: optionalOut(d.CISPID), DesignationRef: optionalOut(d.DesignationRef),
		AipRef: optionalOut(d.AIPRef),
	}
	adj := append([]string{}, d.AdjacentIDs...)
	out.AdjacentIds = &adj
	for _, s := range d.ServicesRequired {
		out.ServicesRequired = append(out.ServicesRequired, gen.USpaceDesignationServicesRequired(s))
	}
	// Stored after checkDesignation accepted them as JSON objects.
	_ = json.Unmarshal(d.UASRequirements, &out.UasRequirements)
	_ = json.Unmarshal(d.OperationalConditions, &out.OperationalConditions)
	_ = json.Unmarshal(d.ServicePerformance, &out.ServicePerformance)
	_ = json.Unmarshal(d.AirspaceConstraints, &out.AirspaceConstraints)
	return &out
}

func versionOut(v *Version) gen.ZoneVersion {
	out := gen.ZoneVersion{
		Dataset: gen.ZoneDataset(v.Dataset), Identifier: v.Identifier, ZoneVersion: v.ZoneVersion, State: gen.ZoneState(v.State),
		Type: gen.ZoneVersionType(v.Type), Country: v.Country, Feature: v.Feature, ValidFrom: v.ValidFrom.UTC(),
		ValidTo: v.ValidTo.UTC(), Extensions: []gen.ZoneExtension{}, Designation: designationOut(v.Designation),
		PublishedVersion: v.PublishedVersion, PublishedBy: optionalOut(v.PublishedBy), CreatedAt: v.CreatedAt.UTC(),
		CreatedBy: v.CreatedBy, ApprovedBy: optionalOut(v.ApprovedBy),
	}
	for _, e := range v.Extensions() {
		out.Extensions = append(out.Extensions, gen.ZoneExtension{Field: "feature." + e.Field, Reason: e.Reason})
	}
	if v.PublishedAt != nil {
		t := v.PublishedAt.UTC()
		out.PublishedAt = &t
	}
	if v.ApprovedAt != nil {
		t := v.ApprovedAt.UTC()
		out.ApprovedAt = &t
	}
	return out
}

func versionsOut(vs []Version) []gen.ZoneVersion {
	out := make([]gen.ZoneVersion, 0, len(vs))
	for i := range vs {
		out = append(out, versionOut(&vs[i]))
	}
	return out
}

func listFilter(ds Dataset, state *gen.ZoneState, after *string, limit *int) ListFilter {
	f := ListFilter{Dataset: ds, After: deref(after), Limit: defaultPageSize}
	if state != nil {
		f.State = State(*state)
	}
	if limit != nil && *limit >= 1 && *limit <= MaxPageSize {
		f.Limit = *limit
	}
	return f
}

func listOut(vs []Version, limit int) gen.ZoneVersionList {
	out := gen.ZoneVersionList{Zones: versionsOut(vs)}
	if len(vs) == limit && limit > 0 {
		last := vs[len(vs)-1].Identifier
		out.NextAfter = &last
	}
	return out
}

func pageOut(vs []Version, limit int) gen.ZoneVersionPage {
	out := gen.ZoneVersionPage{Versions: versionsOut(vs)}
	if len(vs) == limit && limit > 0 {
		last := vs[len(vs)-1].ZoneVersion
		out.NextBefore = &last
	}
	return out
}

func publicationOut(p *Published) gen.ZonePublication {
	return gen.ZonePublication{
		Dataset: gen.ZoneDataset(p.Dataset), ZonesVersion: p.ZonesVersion, Published: versionsOut(p.Versions),
		Publication: gen.PublicationRow{
			Id: p.Publication.ID, Dataset: string(p.Publication.Dataset), Version: p.Publication.Version,
			PayloadHash: p.Publication.PayloadHash, FeatureCount: p.Publication.FeatureCount, Signature: p.Publication.Signature,
			State: gen.PublicationRowState(p.Publication.State), CreatedAt: p.Publication.CreatedAt.UTC(),
		},
	}
}

func zoneDraft(b *gen.ZoneDraftInput, identifier string) DraftInput {
	return DraftInput{Identifier: identifier, Feature: b.Feature, ValidFrom: &b.ValidFrom, ValidTo: &b.ValidTo}
}

func designationIn(d *gen.USpaceDesignation) (*Designation, error) {
	out := &Designation{
		Name: d.AirspaceName, InControlledAirspace: d.InControlledAirspace, RiskAssessmentRef: deref(d.RiskAssessmentRef),
		ATSProviderID: deref(d.AtsProviderId), CISPID: deref(d.CispId), DesignationRef: deref(d.DesignationRef), AIPRef: deref(d.AipRef),
		AdjacentIDs: []string{},
	}
	if d.AdjacentIds != nil {
		out.AdjacentIDs = *d.AdjacentIds
	}
	for _, s := range d.ServicesRequired {
		out.ServicesRequired = append(out.ServicesRequired, string(s))
	}
	var err error
	for _, m := range []struct {
		field string
		v     any
		dst   *json.RawMessage
	}{
		{"designation.uas_requirements", d.UasRequirements, &out.UASRequirements},
		{"designation.operational_conditions", d.OperationalConditions, &out.OperationalConditions},
		{"designation.service_performance", d.ServicePerformance, &out.ServicePerformance},
		{"designation.airspace_constraints", d.AirspaceConstraints, &out.AirspaceConstraints},
	} {
		if *m.dst, err = json.Marshal(m.v); err != nil {
			return nil, core.Fieldf(m.field, "not encodable")
		}
	}
	return out, nil
}

func uspaceDraft(b *gen.USpaceDraftInput, identifier string) (DraftInput, error) {
	d, err := designationIn(&b.Designation)
	if err != nil {
		return DraftInput{}, err
	}
	return DraftInput{Identifier: identifier, Feature: b.Feature, ValidFrom: &b.DesignatedFrom, ValidTo: &b.DesignatedTo, Designation: d}, nil
}

// ListZones answers one page of geo-zones.
func (h Handler) ListZones(ctx context.Context, req gen.ListZonesRequestObject) (gen.ListZonesResponseObject, error) {
	f := listFilter(DatasetZones, req.Params.State, req.Params.After, req.Params.Limit)
	vs, err := h.Service.List(ctx, f)
	if err != nil {
		return nil, err
	}
	return gen.ListZones200JSONResponse(listOut(vs, f.Limit)), nil
}

// CreateZone authors version 1 of a geo-zone.
func (h Handler) CreateZone(ctx context.Context, req gen.CreateZoneRequestObject) (gen.CreateZoneResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyRequired()
	}
	v, err := h.Service.Draft(ctx, DatasetZones, zoneDraft(req.Body, ""), true, actor)
	if err != nil {
		return nil, err
	}
	return gen.CreateZone201JSONResponse(versionOut(&v)), nil
}

// ReplaceZone authors the next version of a geo-zone.
func (h Handler) ReplaceZone(ctx context.Context, req gen.ReplaceZoneRequestObject) (gen.ReplaceZoneResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyRequired()
	}
	v, err := h.Service.Draft(ctx, DatasetZones, zoneDraft(req.Body, req.Identifier), false, actor)
	if err != nil {
		return nil, err
	}
	return gen.ReplaceZone201JSONResponse(versionOut(&v)), nil
}

// GetZone answers the newest version of a geo-zone.
func (h Handler) GetZone(ctx context.Context, req gen.GetZoneRequestObject) (gen.GetZoneResponseObject, error) {
	v, err := h.Service.Get(ctx, DatasetZones, req.Identifier)
	if err != nil {
		return nil, err
	}
	return gen.GetZone200JSONResponse(versionOut(&v)), nil
}

// ApproveZone approves a draft.
func (h Handler) ApproveZone(ctx context.Context, req gen.ApproveZoneRequestObject) (gen.ApproveZoneResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyRequired()
	}
	v, err := h.Service.Approve(ctx, DatasetZones, req.Identifier, req.Body.ZoneVersion, actor)
	if err != nil {
		return nil, err
	}
	return gen.ApproveZone200JSONResponse(versionOut(&v)), nil
}

// ListZoneVersions answers one page of a geo-zone's history.
func (h Handler) ListZoneVersions(ctx context.Context, req gen.ListZoneVersionsRequestObject) (gen.ListZoneVersionsResponseObject, error) {
	limit, before := pageParams(req.Params.Limit, req.Params.Before)
	vs, err := h.Service.Versions(ctx, DatasetZones, req.Identifier, before, limit)
	if err != nil {
		return nil, err
	}
	return gen.ListZoneVersions200JSONResponse(pageOut(vs, limit)), nil
}

func pageParams(limit, before *int) (int, int) {
	l, b := defaultPageSize, 0
	if limit != nil && *limit >= 1 && *limit <= MaxPageSize {
		l = *limit
	}
	if before != nil {
		b = *before
	}
	return l, b
}

// GetZoneApplicability answers whether a zone applies at an instant.
func (h Handler) GetZoneApplicability(ctx context.Context, req gen.GetZoneApplicabilityRequestObject) (gen.GetZoneApplicabilityResponseObject, error) {
	zv := 0
	if req.Params.ZoneVersion != nil {
		zv = *req.Params.ZoneVersion
	}
	a, err := h.Service.Applies(ctx, req.Identifier, zv, req.Params.At)
	if err != nil {
		return nil, err
	}
	return gen.GetZoneApplicability200JSONResponse{
		Identifier: a.Identifier, ZoneVersion: a.ZoneVersion, At: a.At.UTC(),
		Applicability: gen.ZoneApplicabilityApplicability(a.Answer), Reason: optionalOut(a.Reason),
	}, nil
}

// geoJSONResponse writes an export's bytes as ed318.Export wrote them:
// the generated response would re-encode them.
type geoJSONResponse []byte

// VisitExportZonesResponse implements gen.ExportZonesResponseObject.
func (r geoJSONResponse) VisitExportZonesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/geo+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(r)
	return err
}

// ExportZones answers the geo-zones in force as ED-318.
func (h Handler) ExportZones(ctx context.Context, req gen.ExportZonesRequestObject) (gen.ExportZonesResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.Service.Export(ctx, ExportInput{At: req.Params.At, AppliesAt: req.Params.AppliesAt}, actor)
	if err != nil {
		return nil, err
	}
	return geoJSONResponse(out), nil
}

// readBody reads at most MaxDocumentBytes; a longer body is refused
// naming the limit (E-10).
func readBody(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, bodyRequired()
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(MaxDocumentBytes)+1))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		return nil, err
	case err != nil:
		return nil, err
	case len(b) > MaxDocumentBytes:
		return nil, &http.MaxBytesError{Limit: int64(MaxDocumentBytes)}
	case len(b) == 0:
		return nil, bodyRequired()
	}
	return b, nil
}

// ImportZones imports an ED-318 or ED-269 file.
func (h Handler) ImportZones(ctx context.Context, req gen.ImportZonesRequestObject) (gen.ImportZonesResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	body, err := readBody(req.Body)
	if err != nil {
		return nil, err
	}
	format, vs, err := h.Service.Import(ctx, ImportInput{
		Body: body, ValidFrom: req.Params.ValidFrom, ValidTo: req.Params.ValidTo, Lang: deref(req.Params.Lang), Source: "file",
	}, actor)
	if err != nil {
		return nil, err
	}
	return gen.ImportZones201JSONResponse{Format: gen.ZoneImportResultFormat(format), Created: versionsOut(vs)}, nil
}

// ImportGovGeZones converts airspace.gov.ge's files with the rules and
// imports the result.
func (h Handler) ImportGovGeZones(ctx context.Context, req gen.ImportGovGeZonesRequestObject) (gen.ImportGovGeZonesResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	rules := &GovGeRules{Country: b.Rules.Country, Authority: b.Rules.Authority, Kinds: map[string]GovGeKind{}}
	if b.Rules.Identifiers != nil {
		rules.Identifiers = *b.Rules.Identifiers
	}
	for name, k := range b.Rules.Kinds {
		kind := GovGeKind{
			Restriction: string(k.Restriction), Uom: string(k.Uom), LowerReference: string(k.LowerReference),
			UpperReference: string(k.UpperReference), LowerLimit: k.LowerLimit, UpperLimit: k.UpperLimit, Message: k.Message,
		}
		if k.Reason != nil {
			kind.Reason = *k.Reason
		}
		for _, p := range k.Applicability {
			raw, err := json.Marshal(p)
			if err != nil {
				return nil, core.Fieldf("rules.kinds."+name+".applicability", "not encodable")
			}
			kind.Applicability = append(kind.Applicability, raw)
		}
		rules.Kinds[name] = kind
	}
	doc, errs := GovGeToED269(b.PointsJs, b.PageHtml, rules)
	if len(errs) > 0 {
		capped, more := capErrors(errs)
		return nil, h.Service.refused(validation("the airspace.gov.ge files were refused whole; nothing was imported", capped, more))
	}
	format, vs, err := h.Service.Import(ctx, ImportInput{
		Body: doc, ValidFrom: b.ValidFrom, ValidTo: b.ValidTo, Lang: deref(b.Lang), Source: "airspace.gov.ge",
	}, actor)
	if err != nil {
		return nil, err
	}
	return gen.ImportGovGeZones201JSONResponse{Format: gen.ZoneImportResultFormat(format), Created: versionsOut(vs)}, nil
}

// PublishZones publishes every approved geo-zone version.
func (h Handler) PublishZones(ctx context.Context, _ gen.PublishZonesRequestObject) (gen.PublishZonesResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.Publish(ctx, DatasetZones, actor)
	if err != nil {
		return nil, err
	}
	return gen.PublishZones200JSONResponse(publicationOut(&p)), nil
}

// ListUSpaceAirspaces answers one page of U-space airspaces.
func (h Handler) ListUSpaceAirspaces(ctx context.Context, req gen.ListUSpaceAirspacesRequestObject) (gen.ListUSpaceAirspacesResponseObject, error) {
	f := listFilter(DatasetUSpace, req.Params.State, req.Params.After, req.Params.Limit)
	vs, err := h.Service.List(ctx, f)
	if err != nil {
		return nil, err
	}
	return gen.ListUSpaceAirspaces200JSONResponse(listOut(vs, f.Limit)), nil
}

// CreateUSpaceAirspace drafts version 1 of a U-space airspace.
func (h Handler) CreateUSpaceAirspace(ctx context.Context, req gen.CreateUSpaceAirspaceRequestObject) (gen.CreateUSpaceAirspaceResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyRequired()
	}
	in, err := uspaceDraft(req.Body, "")
	if err != nil {
		return nil, err
	}
	v, err := h.Service.Draft(ctx, DatasetUSpace, in, true, actor)
	if err != nil {
		return nil, err
	}
	return gen.CreateUSpaceAirspace201JSONResponse(versionOut(&v)), nil
}

// ReplaceUSpaceAirspace drafts the next version of a U-space airspace.
func (h Handler) ReplaceUSpaceAirspace(ctx context.Context, req gen.ReplaceUSpaceAirspaceRequestObject) (gen.ReplaceUSpaceAirspaceResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyRequired()
	}
	in, err := uspaceDraft(req.Body, req.Identifier)
	if err != nil {
		return nil, err
	}
	v, err := h.Service.Draft(ctx, DatasetUSpace, in, false, actor)
	if err != nil {
		return nil, err
	}
	return gen.ReplaceUSpaceAirspace201JSONResponse(versionOut(&v)), nil
}

// GetUSpaceAirspace answers the newest version of a U-space airspace.
func (h Handler) GetUSpaceAirspace(ctx context.Context, req gen.GetUSpaceAirspaceRequestObject) (gen.GetUSpaceAirspaceResponseObject, error) {
	v, err := h.Service.Get(ctx, DatasetUSpace, req.Identifier)
	if err != nil {
		return nil, err
	}
	return gen.GetUSpaceAirspace200JSONResponse(versionOut(&v)), nil
}

// DesignateUSpaceAirspace designates (approves) a draft.
func (h Handler) DesignateUSpaceAirspace(ctx context.Context, req gen.DesignateUSpaceAirspaceRequestObject) (gen.DesignateUSpaceAirspaceResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, bodyRequired()
	}
	v, err := h.Service.Approve(ctx, DatasetUSpace, req.Identifier, req.Body.ZoneVersion, actor)
	if err != nil {
		return nil, err
	}
	return gen.DesignateUSpaceAirspace200JSONResponse(versionOut(&v)), nil
}

// ListUSpaceVersions answers one page of a U-space airspace's history.
func (h Handler) ListUSpaceVersions(ctx context.Context, req gen.ListUSpaceVersionsRequestObject) (gen.ListUSpaceVersionsResponseObject, error) {
	limit, before := pageParams(req.Params.Limit, req.Params.Before)
	vs, err := h.Service.Versions(ctx, DatasetUSpace, req.Identifier, before, limit)
	if err != nil {
		return nil, err
	}
	return gen.ListUSpaceVersions200JSONResponse(pageOut(vs, limit)), nil
}

// PublishUSpaceAirspaces publishes every designated U-space version.
func (h Handler) PublishUSpaceAirspaces(ctx context.Context, _ gen.PublishUSpaceAirspacesRequestObject) (gen.PublishUSpaceAirspacesResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.Publish(ctx, DatasetUSpace, actor)
	if err != nil {
		return nil, err
	}
	return gen.PublishUSpaceAirspaces200JSONResponse(publicationOut(&p)), nil
}
