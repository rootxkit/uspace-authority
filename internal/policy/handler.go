package policy

import (
	"context"
	"net/http"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Handler serves /v1/policy* (apiserver.PolicyHandler).
type Handler struct {
	Service *Service
}

var _ apiserver.PolicyHandler = Handler{}

// GetPolicy answers the active policy.
func (h Handler) GetPolicy(ctx context.Context, _ gen.GetPolicyRequestObject) (gen.GetPolicyResponseObject, error) {
	p, err := h.Service.Active(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetPolicy200JSONResponse(toAPI(p)), nil
}

// CreatePolicy stores a new, inactive version.
func (h Handler) CreatePolicy(ctx context.Context, req gen.CreatePolicyRequestObject) (gen.CreatePolicyResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", &core.FieldError{Field: "body", Reason: "required"})
	}
	b := req.Body
	t := Thresholds{
		HeightLimitAGLM:         b.HeightLimitAglM,
		PressureUncertaintyM:    b.PressureUncertaintyM,
		ZoneConditionalSeverity: core.Severity(b.ZoneConditionalSeverity),
		MismatchSeverity:        core.Severity(b.MismatchSeverity),
		IdentificationSeverity:  core.Severity(b.IdentificationSeverity),
		SpoofDistanceM:          b.SpoofDistanceM,
		IdentityTTLS:            b.IdentityTtlS,
		MaxGapS:                 b.MaxGapS,
		IdentifyWithinS:         b.IdentifyWithinS,
		BroadcastToleranceS:     b.BroadcastToleranceS,
		MaxLatencyS:             b.MaxLatencyS,
		LiveMaxAgeS:             b.LiveMaxAgeS,
		ClearAfterS:             b.ClearAfterS,
		StaleAfterS:             b.StaleAfterS,
		DPViewDiagonalKM:        b.DpViewDiagonalKm,
		DPPollHz:                b.DpPollHz,
		CISStaleBoundS:          b.CisStaleBoundS,
		HeightLimitInUspace:     string(b.HeightLimitInUspace),
	}
	note := ""
	if b.Note != nil {
		note = *b.Note
	}
	p, err := h.Service.Create(ctx, t, note, actor)
	if err != nil {
		return nil, err
	}
	return gen.CreatePolicy201JSONResponse(toAPI(p)), nil
}

// ActivatePolicy activates a newer version.
func (h Handler) ActivatePolicy(ctx context.Context, req gen.ActivatePolicyRequestObject) (gen.ActivatePolicyResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	p, err := h.Service.Activate(ctx, req.Version, actor)
	if err != nil {
		return nil, err
	}
	return gen.ActivatePolicy200JSONResponse(toAPI(p)), nil
}

func toAPI(p Policy) gen.Policy {
	out := gen.Policy{
		Version:                 p.Version,
		Active:                  p.Active,
		CreatedAt:               p.CreatedAt.UTC(),
		CreatedBy:               p.CreatedBy,
		Note:                    p.Note,
		HeightLimitAglM:         p.HeightLimitAGLM,
		PressureUncertaintyM:    p.PressureUncertaintyM,
		ZoneConditionalSeverity: gen.Severity(p.ZoneConditionalSeverity),
		MismatchSeverity:        gen.Severity(p.MismatchSeverity),
		IdentificationSeverity:  gen.Severity(p.IdentificationSeverity),
		SpoofDistanceM:          p.SpoofDistanceM,
		IdentityTtlS:            p.IdentityTTLS,
		MaxGapS:                 p.MaxGapS,
		IdentifyWithinS:         p.IdentifyWithinS,
		BroadcastToleranceS:     p.BroadcastToleranceS,
		MaxLatencyS:             p.MaxLatencyS,
		LiveMaxAgeS:             p.LiveMaxAgeS,
		ClearAfterS:             p.ClearAfterS,
		StaleAfterS:             p.StaleAfterS,
		DpViewDiagonalKm:        p.DPViewDiagonalKM,
		DpPollHz:                p.DPPollHz,
		CisStaleBoundS:          p.CISStaleBoundS,
		HeightLimitInUspace:     gen.PolicyHeightLimitInUspace(p.HeightLimitInUspace),
	}
	if p.ActivatedAt != nil {
		at := p.ActivatedAt.UTC()
		out.ActivatedAt = &at
	}
	if p.ActivatedBy != "" {
		by := p.ActivatedBy
		out.ActivatedBy = &by
	}
	return out
}
