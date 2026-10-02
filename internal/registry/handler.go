package registry

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Handler serves /v1/registry/* (apiserver.RegistryHandler).
type Handler struct {
	Service *Service
}

var _ apiserver.RegistryHandler = Handler{}

// defaultPageSize is a list page without a limit.
const defaultPageSize = 100

var noStore = "no-store"

func bodyRequired() error {
	return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", &core.FieldError{Field: "body", Reason: "required"})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func statusParam(s *gen.RegistryStatus) (Status, error) {
	if s == nil {
		return "", nil
	}
	st := Status(*s)
	if !ValidStatus(st) {
		return "", core.Fieldf("status", "must be active, suspended, revoked or expired")
	}
	return st, nil
}

func pageParam(after *string, limit *int) Page {
	p := Page{After: deref(after), Limit: defaultPageSize}
	if limit != nil {
		p.Limit = *limit
	}
	if p.Limit < 1 || p.Limit > MaxPageSize {
		p.Limit = defaultPageSize
	}
	return p
}

// nextAfter is the cursor of the next page: the last id of a full page.
func nextAfter(n, limit int, last string) *string {
	if n < limit || n == 0 {
		return nil
	}
	return &last
}

func authorisationsIn(items *[]map[string]any) (json.RawMessage, error) {
	if items == nil {
		return nil, nil
	}
	b, err := json.Marshal(*items)
	if err != nil {
		return nil, core.Fieldf("authorisations", "not encodable")
	}
	return b, nil
}

func authorisationsOut(raw json.RawMessage) []map[string]any {
	out := []map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out) // stored only after validAuthorisations accepted it
	}
	return out
}

func dateIn(d *openapi_types.Date) *string {
	if d == nil {
		return nil
	}
	s := d.Format(time.DateOnly)
	return &s
}

func dateOut(s string) *openapi_types.Date {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return nil
	}
	return &openapi_types.Date{Time: t}
}

func operatorOut(o *Operator) gen.RegistryOperator {
	return gen.RegistryOperator{
		Id: o.ID, OperatorType: gen.OperatorType(o.OperatorType), RegistrationNumber: o.RegistrationNumber,
		HasSecretPart: o.HasSecretPart, CompetencyConfirmation: o.CompetencyConfirmation,
		Authorisations: authorisationsOut(o.Authorisations), Status: gen.RegistryStatus(o.Status), StatusReason: o.StatusReason,
		ValidFrom: o.ValidFrom.UTC(), ValidUntil: o.ValidUntil.UTC(), Source: gen.RegistrySource(o.Source),
		RegistryVersion: o.RegistryVersion, CreatedAt: o.CreatedAt.UTC(), CreatedBy: o.CreatedBy,
		UpdatedAt: o.UpdatedAt.UTC(), UpdatedBy: o.UpdatedBy,
	}
}

func uasOut(u *UAS) gen.RegistryUAS {
	out := gen.RegistryUAS{
		Id: u.ID, OperatorId: u.OperatorID, Serial: u.Serial, ManufacturerCode: u.ManufacturerCode,
		RegistrationMark: optional(u.RegistrationMark), Manufacturer: u.Manufacturer, Model: u.Model,
		OwnerRef: optional(u.OwnerRef), MtomG: u.MTOMG, RidCapability: gen.RIDCapability(u.RIDCapability),
		Status: gen.RegistryStatus(u.Status), StatusReason: u.StatusReason, RegisteredAt: u.RegisteredAt.UTC(),
		RegistryVersion: u.RegistryVersion, CreatedBy: u.CreatedBy, UpdatedAt: u.UpdatedAt.UTC(), UpdatedBy: u.UpdatedBy,
	}
	if u.ClassLabel != "" {
		c := gen.ClassLabel(u.ClassLabel)
		out.ClassLabel = &c
	}
	return out
}

func pilotOut(p *Pilot) gen.RegistryPilot {
	out := gen.RegistryPilot{
		Id: p.ID, OperatorId: optional(p.OperatorID), Status: gen.RegistryStatus(p.Status), StatusReason: p.StatusReason,
		Competencies: make([]gen.PilotCompetency, 0, len(p.Competencies)), RegistryVersion: p.RegistryVersion,
		CreatedAt: p.CreatedAt.UTC(), CreatedBy: p.CreatedBy, UpdatedAt: p.UpdatedAt.UTC(), UpdatedBy: p.UpdatedBy,
	}
	for _, c := range p.Competencies {
		out.Competencies = append(out.Competencies, gen.PilotCompetency{
			Competency: c.Competency, CertificateRef: c.CertificateRef, ValidUntil: c.ValidUntil.UTC(),
			RecordedAt: c.RecordedAt.UTC(), RecordedBy: c.RecordedBy,
		})
	}
	return out
}

// ListRegistryOperators answers one page of operators.
func (h Handler) ListRegistryOperators(ctx context.Context, req gen.ListRegistryOperatorsRequestObject) (gen.ListRegistryOperatorsResponseObject, error) {
	st, err := statusParam(req.Params.Status)
	if err != nil {
		return nil, err
	}
	page := pageParam(req.Params.After, req.Params.Limit)
	rows, err := h.Service.ListOperators(ctx, deref(req.Params.Number), st, page)
	if err != nil {
		return nil, err
	}
	out := gen.RegistryOperatorList{Operators: make([]gen.RegistryOperator, 0, len(rows))}
	for i := range rows {
		out.Operators = append(out.Operators, operatorOut(&rows[i]))
	}
	if len(rows) > 0 {
		out.NextAfter = nextAfter(len(rows), page.Limit, rows[len(rows)-1].ID)
	}
	return gen.ListRegistryOperators200JSONResponse(out), nil
}

// CreateRegistryOperator registers an operator.
func (h Handler) CreateRegistryOperator(ctx context.Context, req gen.CreateRegistryOperatorRequestObject) (gen.CreateRegistryOperatorResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	auths, err := authorisationsIn(b.Authorisations)
	if err != nil {
		return nil, err
	}
	in := NewOperator{
		OperatorType: string(b.OperatorType), RegistrationNumber: b.RegistrationNumber, SecretPart: deref(b.SecretPart),
		PII: OperatorPII{
			FullName: deref(b.FullName), LegalName: deref(b.LegalName), DateOfBirth: deref(dateIn(b.DateOfBirth)),
			LegalIdentificationNumber: deref(b.LegalIdentificationNumber), PostalAddress: b.PostalAddress,
			ContactEmail: b.ContactEmail, ContactPhone: b.ContactPhone, InsurancePolicyNumber: deref(b.InsurancePolicyNumber),
		},
		Authorisations: auths, ValidUntil: b.ValidUntil,
	}
	if b.CompetencyConfirmation != nil {
		in.CompetencyConfirmation = *b.CompetencyConfirmation
	}
	if b.ValidFrom != nil {
		in.ValidFrom = *b.ValidFrom
	}
	if b.Source != nil {
		in.Source = string(*b.Source)
	}
	o, err := h.Service.CreateOperator(ctx, in, actor)
	if err != nil {
		return nil, err
	}
	return gen.CreateRegistryOperator201JSONResponse(operatorOut(&o)), nil
}

// GetRegistryOperator answers one operator without personal data.
func (h Handler) GetRegistryOperator(ctx context.Context, req gen.GetRegistryOperatorRequestObject) (gen.GetRegistryOperatorResponseObject, error) {
	o, err := h.Service.GetOperator(ctx, req.OperatorId)
	if err != nil {
		return nil, err
	}
	return gen.GetRegistryOperator200JSONResponse(operatorOut(&o)), nil
}

// UpdateRegistryOperator changes an operator's details.
func (h Handler) UpdateRegistryOperator(ctx context.Context, req gen.UpdateRegistryOperatorRequestObject) (gen.UpdateRegistryOperatorResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	auths, err := authorisationsIn(b.Authorisations)
	if err != nil {
		return nil, err
	}
	o, err := h.Service.UpdateOperator(ctx, req.OperatorId, OperatorPatch{
		FullName: b.FullName, LegalName: b.LegalName, DateOfBirth: dateIn(b.DateOfBirth),
		LegalIdentificationNumber: b.LegalIdentificationNumber, PostalAddress: b.PostalAddress,
		ContactEmail: b.ContactEmail, ContactPhone: b.ContactPhone, InsurancePolicyNumber: b.InsurancePolicyNumber,
		CompetencyConfirmation: b.CompetencyConfirmation, Authorisations: auths, ValidUntil: b.ValidUntil,
	}, actor)
	if err != nil {
		return nil, err
	}
	return gen.UpdateRegistryOperator200JSONResponse(operatorOut(&o)), nil
}

func statusBody(b *gen.RegistryStatusInput) (Status, string, error) {
	if b == nil {
		return "", "", bodyRequired()
	}
	return Status(b.Status), deref(b.Reason), nil
}

// SetRegistryOperatorStatus moves an operator along the status graph.
func (h Handler) SetRegistryOperatorStatus(ctx context.Context, req gen.SetRegistryOperatorStatusRequestObject) (gen.SetRegistryOperatorStatusResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	to, reason, err := statusBody(req.Body)
	if err != nil {
		return nil, err
	}
	o, err := h.Service.SetOperatorStatus(ctx, req.OperatorId, to, reason, actor)
	if err != nil {
		return nil, err
	}
	return gen.SetRegistryOperatorStatus200JSONResponse(operatorOut(&o)), nil
}

// GetRegistryOperatorPersonalData answers an operator's personal data,
// recorded with its purpose.
func (h Handler) GetRegistryOperatorPersonalData(ctx context.Context, req gen.GetRegistryOperatorPersonalDataRequestObject) (gen.GetRegistryOperatorPersonalDataResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.OperatorPersonalData(ctx, req.OperatorId, req.Params.Purpose, actor)
	if err != nil {
		return nil, err
	}
	return gen.GetRegistryOperatorPersonalData200JSONResponse{
		Body: gen.RegistryOperatorPersonalData{
			OperatorId: req.OperatorId, FullName: optional(p.FullName), LegalName: optional(p.LegalName),
			DateOfBirth: dateOut(p.DateOfBirth), LegalIdentificationNumber: optional(p.LegalIdentificationNumber),
			PostalAddress: p.PostalAddress, ContactEmail: p.ContactEmail, ContactPhone: p.ContactPhone,
			InsurancePolicyNumber: optional(p.InsurancePolicyNumber),
		},
		Headers: gen.GetRegistryOperatorPersonalData200ResponseHeaders{CacheControl: &noStore},
	}, nil
}

func classIn(c *gen.ClassLabel) string {
	if c == nil {
		return ""
	}
	return string(*c)
}

// ListRegistryUAS answers one page of aircraft.
func (h Handler) ListRegistryUAS(ctx context.Context, req gen.ListRegistryUASRequestObject) (gen.ListRegistryUASResponseObject, error) {
	st, err := statusParam(req.Params.Status)
	if err != nil {
		return nil, err
	}
	page := pageParam(req.Params.After, req.Params.Limit)
	rows, err := h.Service.ListUAS(ctx, deref(req.Params.Serial), deref(req.Params.OperatorId), st, page)
	if err != nil {
		return nil, err
	}
	out := gen.RegistryUASList{Uas: make([]gen.RegistryUAS, 0, len(rows))}
	for i := range rows {
		out.Uas = append(out.Uas, uasOut(&rows[i]))
	}
	if len(rows) > 0 {
		out.NextAfter = nextAfter(len(rows), page.Limit, rows[len(rows)-1].ID)
	}
	return gen.ListRegistryUAS200JSONResponse(out), nil
}

// CreateRegistryUAS registers an aircraft.
func (h Handler) CreateRegistryUAS(ctx context.Context, req gen.CreateRegistryUASRequestObject) (gen.CreateRegistryUASResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	u, err := h.Service.CreateUAS(ctx, NewUAS{
		OperatorID: b.OperatorId, Serial: b.Serial, RegistrationMark: deref(b.RegistrationMark),
		Manufacturer: deref(b.Manufacturer), Model: deref(b.Model), OwnerRef: deref(b.OwnerRef),
		ClassLabel: classIn(b.ClassLabel), MTOMG: b.MtomG, RIDCapability: string(b.RidCapability),
	}, actor)
	if err != nil {
		return nil, err
	}
	return gen.CreateRegistryUAS201JSONResponse(uasOut(&u)), nil
}

// GetRegistryUAS answers one aircraft.
func (h Handler) GetRegistryUAS(ctx context.Context, req gen.GetRegistryUASRequestObject) (gen.GetRegistryUASResponseObject, error) {
	u, err := h.Service.GetUAS(ctx, req.UasId)
	if err != nil {
		return nil, err
	}
	return gen.GetRegistryUAS200JSONResponse(uasOut(&u)), nil
}

// UpdateRegistryUAS changes an aircraft's details.
func (h Handler) UpdateRegistryUAS(ctx context.Context, req gen.UpdateRegistryUASRequestObject) (gen.UpdateRegistryUASResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	p := UASPatch{
		RegistrationMark: b.RegistrationMark, Manufacturer: b.Manufacturer, Model: b.Model, OwnerRef: b.OwnerRef, MTOMG: b.MtomG,
	}
	if b.ClassLabel != nil {
		c := string(*b.ClassLabel)
		p.ClassLabel = &c
	}
	if b.RidCapability != nil {
		r := string(*b.RidCapability)
		p.RIDCapability = &r
	}
	u, err := h.Service.UpdateUAS(ctx, req.UasId, p, actor)
	if err != nil {
		return nil, err
	}
	return gen.UpdateRegistryUAS200JSONResponse(uasOut(&u)), nil
}

// SetRegistryUASStatus moves an aircraft along the status graph.
func (h Handler) SetRegistryUASStatus(ctx context.Context, req gen.SetRegistryUASStatusRequestObject) (gen.SetRegistryUASStatusResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	to, reason, err := statusBody(req.Body)
	if err != nil {
		return nil, err
	}
	u, err := h.Service.SetUASStatus(ctx, req.UasId, to, reason, actor)
	if err != nil {
		return nil, err
	}
	return gen.SetRegistryUASStatus200JSONResponse(uasOut(&u)), nil
}

// ListRegistryPilots answers one page of pilots.
func (h Handler) ListRegistryPilots(ctx context.Context, req gen.ListRegistryPilotsRequestObject) (gen.ListRegistryPilotsResponseObject, error) {
	st, err := statusParam(req.Params.Status)
	if err != nil {
		return nil, err
	}
	page := pageParam(req.Params.After, req.Params.Limit)
	rows, err := h.Service.ListPilots(ctx, deref(req.Params.OperatorId), st, page)
	if err != nil {
		return nil, err
	}
	out := gen.RegistryPilotList{Pilots: make([]gen.RegistryPilot, 0, len(rows))}
	for i := range rows {
		out.Pilots = append(out.Pilots, pilotOut(&rows[i]))
	}
	if len(rows) > 0 {
		out.NextAfter = nextAfter(len(rows), page.Limit, rows[len(rows)-1].ID)
	}
	return gen.ListRegistryPilots200JSONResponse(out), nil
}

// CreateRegistryPilot registers a remote pilot.
func (h Handler) CreateRegistryPilot(ctx context.Context, req gen.CreateRegistryPilotRequestObject) (gen.CreateRegistryPilotResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	p, err := h.Service.CreatePilot(ctx, NewPilot{PersonRef: b.PersonRef, Name: b.Name, OperatorID: deref(b.OperatorId)}, actor)
	if err != nil {
		return nil, err
	}
	return gen.CreateRegistryPilot201JSONResponse(pilotOut(&p)), nil
}

// GetRegistryPilot answers one pilot without personal data.
func (h Handler) GetRegistryPilot(ctx context.Context, req gen.GetRegistryPilotRequestObject) (gen.GetRegistryPilotResponseObject, error) {
	p, err := h.Service.GetPilot(ctx, req.PilotId)
	if err != nil {
		return nil, err
	}
	return gen.GetRegistryPilot200JSONResponse(pilotOut(&p)), nil
}

// UpdateRegistryPilot changes a pilot's name or operator.
func (h Handler) UpdateRegistryPilot(ctx context.Context, req gen.UpdateRegistryPilotRequestObject) (gen.UpdateRegistryPilotResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	p, err := h.Service.UpdatePilot(ctx, req.PilotId, PilotPatch{Name: b.Name, OperatorID: b.OperatorId}, actor)
	if err != nil {
		return nil, err
	}
	return gen.UpdateRegistryPilot200JSONResponse(pilotOut(&p)), nil
}

// SetRegistryPilotStatus moves a pilot along the status graph.
func (h Handler) SetRegistryPilotStatus(ctx context.Context, req gen.SetRegistryPilotStatusRequestObject) (gen.SetRegistryPilotStatusResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	to, reason, err := statusBody(req.Body)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.SetPilotStatus(ctx, req.PilotId, to, reason, actor)
	if err != nil {
		return nil, err
	}
	return gen.SetRegistryPilotStatus200JSONResponse(pilotOut(&p)), nil
}

// GetRegistryPilotPersonalData answers a pilot's personal data,
// recorded with its purpose.
func (h Handler) GetRegistryPilotPersonalData(ctx context.Context, req gen.GetRegistryPilotPersonalDataRequestObject) (gen.GetRegistryPilotPersonalDataResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.PilotPersonalData(ctx, req.PilotId, req.Params.Purpose, actor)
	if err != nil {
		return nil, err
	}
	return gen.GetRegistryPilotPersonalData200JSONResponse{
		Body:    gen.RegistryPilotPersonalData{PilotId: req.PilotId, Name: p.Name, PersonRefLast4: p.PersonRefLast4},
		Headers: gen.GetRegistryPilotPersonalData200ResponseHeaders{CacheControl: &noStore},
	}, nil
}

// RecordPilotCompetency records or renews a competency.
func (h Handler) RecordPilotCompetency(ctx context.Context, req gen.RecordPilotCompetencyRequestObject) (gen.RecordPilotCompetencyResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	p, err := h.Service.RecordCompetency(ctx, req.PilotId, Competency{
		Competency: b.Competency, CertificateRef: b.CertificateRef, ValidUntil: b.ValidUntil,
	}, actor)
	if err != nil {
		return nil, err
	}
	return gen.RecordPilotCompetency200JSONResponse(pilotOut(&p)), nil
}
