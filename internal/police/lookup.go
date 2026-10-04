package police

import (
	"context"
	"errors"
	"net/http"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
)

// LookupQuery is GET /v1/police/operators/{reg} and /serials/{serial}.
type LookupQuery struct {
	Key     string
	Purpose string
	CaseRef string
}

// begin checks what every lookup carries: the caller, the purpose, the
// case reference and the path key.
func (s *Service) begin(ctx context.Context, q LookupQuery, field string) (Caller, string, string, string, error) {
	c, err := s.caller(ctx)
	if err != nil {
		return Caller{}, "", "", "", err
	}
	purpose, err := s.Purposes.Check(q.Purpose)
	if err != nil {
		return Caller{}, "", "", "", err
	}
	caseRef, err := CheckCaseRef(q.CaseRef)
	if err != nil {
		return Caller{}, "", "", "", err
	}
	key, err := checkIdentity(field, q.Key)
	if err != nil {
		return Caller{}, "", "", "", err
	}
	return c, purpose, caseRef, key, nil
}

func registrationOut(op *registry.Operator) gen.PoliceRegistration {
	return gen.PoliceRegistration{RegistrationNumber: op.RegistrationNumber, OperatorType: op.OperatorType,
		Status: gen.RegistryStatus(op.Status), ValidFrom: op.ValidFrom.UTC(), ValidUntil: op.ValidUntil.UTC()}
}

func uasOut(u *registry.UAS) gen.PoliceUAS {
	opt := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	return gen.PoliceUAS{Serial: u.Serial, Status: gen.RegistryStatus(u.Status), ClassLabel: opt(u.ClassLabel),
		Manufacturer: opt(u.Manufacturer), Model: opt(u.Model), RegistrationMark: opt(u.RegistrationMark)}
}

func notFound(field, what string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "the registry holds no "+what+"; the query is recorded",
		core.Fieldf(field, "not registered"))
}

func ambiguous(field string) error {
	return httpx.Refuse(http.StatusConflict, SlugAmbiguous, "more than one registration matches; the query is recorded",
		core.Fieldf(field, "ambiguous"))
}

// QueryOperator answers an operator's registry status and fleet, and
// its identity for a purpose that releases it.
func (s *Service) QueryOperator(ctx context.Context, q LookupQuery) (gen.PoliceOperatorAnswer, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	c, purpose, caseRef, reg, err := s.begin(ctx, q, "reg")
	if err != nil {
		return gen.PoliceOperatorAnswer{}, err
	}
	// Only the public part is ever stored or echoed (spec 06 §5).
	public := s.publicPart(reg)
	op, found, err := s.Registry.OperatorByNumber(ctx, public)
	isAmbiguous := errors.Is(err, registry.ErrAmbiguous)
	if err != nil && !isAmbiguous {
		return gen.PoliceOperatorAnswer{}, err
	}
	var fleet []registry.UAS
	if found {
		if fleet, err = s.Registry.ListUAS(ctx, "", op.ID, "", registry.Page{Limit: s.Limits.MaxFleet + 1}); err != nil {
			return gen.PoliceOperatorAnswer{}, err
		}
	}
	pii := s.Purposes.AllowsPII(purpose)
	n := 0
	if found {
		n = 1
	}
	e := Entry{Kind: KindOperator, Purpose: purpose, CaseRef: caseRef, Query: map[string]any{"registration_number": public},
		ResultCount: n, PII: pii && found, Caller: c}
	if err := s.record(ctx, &e); err != nil {
		return gen.PoliceOperatorAnswer{}, err
	}
	switch {
	case isAmbiguous:
		return gen.PoliceOperatorAnswer{}, ambiguous("reg")
	case !found:
		return gen.PoliceOperatorAnswer{}, notFound("reg", "operator of this registration number")
	}
	out := gen.PoliceOperatorAnswer{QueryId: e.ID, Purpose: purpose, CaseRef: caseRef, Operator: registrationOut(&op),
		Fleet: make([]gen.PoliceUAS, 0, len(fleet))}
	if len(fleet) > s.Limits.MaxFleet {
		fleet, out.FleetTruncated = fleet[:s.Limits.MaxFleet], true
	}
	for i := range fleet {
		out.Fleet = append(out.Fleet, uasOut(&fleet[i]))
	}
	if pii {
		id, err := s.identity(piiContext(ctx, &e), op, purpose, c.Actor)
		if err != nil {
			return gen.PoliceOperatorAnswer{}, err
		}
		v := identityOut(id)
		out.Identity, out.PiiReleased = &v, true
	}
	return out, nil
}

// QuerySerial answers an aircraft's registry status and its operator's
// registration, and the operator's identity for a purpose that
// releases it.
func (s *Service) QuerySerial(ctx context.Context, q LookupQuery) (gen.PoliceSerialAnswer, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	c, purpose, caseRef, sn, err := s.begin(ctx, q, "serial")
	if err != nil {
		return gen.PoliceSerialAnswer{}, err
	}
	u, found, err := s.Registry.UASBySerial(ctx, sn)
	if err != nil {
		return gen.PoliceSerialAnswer{}, err
	}
	var op registry.Operator
	if found {
		if op, err = s.Registry.GetOperator(ctx, u.OperatorID); err != nil {
			return gen.PoliceSerialAnswer{}, err
		}
	}
	pii := s.Purposes.AllowsPII(purpose)
	n := 0
	if found {
		n = 1
	}
	e := Entry{Kind: KindSerial, Purpose: purpose, CaseRef: caseRef, Query: map[string]any{"serial": sn},
		ResultCount: n, PII: pii && found, Caller: c}
	if err := s.record(ctx, &e); err != nil {
		return gen.PoliceSerialAnswer{}, err
	}
	if !found {
		return gen.PoliceSerialAnswer{}, notFound("serial", "aircraft of this serial")
	}
	out := gen.PoliceSerialAnswer{QueryId: e.ID, Purpose: purpose, CaseRef: caseRef, Uas: uasOut(&u), Operator: registrationOut(&op)}
	if pii {
		id, err := s.identity(piiContext(ctx, &e), op, purpose, c.Actor)
		if err != nil {
			return gen.PoliceSerialAnswer{}, err
		}
		v := identityOut(id)
		out.Identity, out.PiiReleased = &v, true
	}
	return out, nil
}
