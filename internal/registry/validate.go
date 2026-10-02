package registry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/serial"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Purposes of an F8 lookup (spec 02 F8).
const (
	PurposeAuthorisation  = "authorisation"
	PurposeIdentification = "identification"
)

// F8 validity statuses: status only, never a name (spec 02 F8).
const (
	ValidityValid     = "valid"
	ValiditySuspended = "suspended"
	ValidityRevoked   = "revoked"
	ValidityUnknown   = "unknown"
)

// MaxBatch bounds one batch lookup (E-10); the OpenAPI schema states the
// same maxItems.
const MaxBatch = 100

// Query is one F8 lookup; at least one key is set.
type Query struct {
	Operator string
	Serial   string
	Pilot    string
}

// OperatorValidity is the answer for an operator.
type OperatorValidity struct {
	Number     string
	Status     string
	ValidUntil *time.Time
}

// UASValidity is the answer for an aircraft.
type UASValidity struct {
	Serial     string
	Status     string
	ClassLabel string
	MTOMBand   string
}

// CompetencyValidity is one competency in a pilot's answer.
type CompetencyValidity struct {
	Competency string
	ValidUntil time.Time
}

// PilotValidity is the answer for a pilot.
type PilotValidity struct {
	Pilot        string
	Status       string
	Competencies []CompetencyValidity
}

// Validity is the answer to one Query: one part per key asked.
type Validity struct {
	Operator *OperatorValidity
	UAS      *UASValidity
	Pilot    *PilotValidity
}

// entityValidity maps a registry status onto F8's four values. An
// expired registration is not valid; F8 has no expired value, so it
// answers revoked, with the valid_until that shows why.
func entityValidity(st Status) string {
	switch st {
	case StatusActive:
		return ValidityValid
	case StatusSuspended:
		return ValiditySuspended
	case StatusRevoked, StatusExpired:
		return ValidityRevoked
	}
	return ValidityUnknown
}

// operatorValidity also refuses an active registration outside its
// validity window (the expiry job marks it within its period).
func operatorValidity(o *Operator, now time.Time) string {
	if o.Status == StatusActive && (now.Before(o.ValidFrom) || !now.Before(o.ValidUntil)) {
		return ValidityRevoked
	}
	return entityValidity(o.Status)
}

// MTOMBand names the band of mtomG under bounds (ascending grams):
// under_<bound>g for the first bound above it, from_<last>g beyond the
// last; "" when the mass is not registered.
func MTOMBand(mtomG *int, bounds []int) string {
	if mtomG == nil {
		return ""
	}
	for _, b := range bounds {
		if *mtomG < b {
			return fmt.Sprintf("under_%dg", b)
		}
	}
	if len(bounds) == 0 {
		return ""
	}
	return fmt.Sprintf("from_%dg", bounds[len(bounds)-1])
}

// checkQueries refuses a lookup F8 does not define.
func checkQueries(qs []Query, purpose string) error {
	var errs []error
	if purpose != PurposeAuthorisation && purpose != PurposeIdentification {
		errs = append(errs, core.Fieldf("purpose", "required: authorisation or identification"))
	}
	switch {
	case len(qs) == 0:
		errs = append(errs, core.Fieldf("items", "name at least one operator, serial or pilot"))
	case len(qs) > MaxBatch:
		errs = append(errs, core.Fieldf("items", "at most %d entities per request", MaxBatch))
	}
	for i, q := range qs {
		if q.Operator == "" && q.Serial == "" && q.Pilot == "" {
			errs = append(errs, core.Fieldf(fmt.Sprintf("items[%d]", i), "name an operator, a serial or a pilot"))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", fieldErrorsOf(err)...)
	}
	return nil
}

func fieldErrorsOf(err error) []*core.FieldError {
	var out []*core.FieldError
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			out = append(out, fieldErrorsOf(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		out = append(out, fe)
	}
	return out
}

// lookupSerial finds the aircraft a serial names with uspace-core's own
// matching (identify.Snapshot.UASBySerial: exact first, else a folded
// match only when it is unique, G-05, G-12), over the rows that share
// its fold key.
func (s *Service) lookupSerial(ctx context.Context, sn string) (UAS, bool, error) {
	rows, err := s.Store.UASByFold(ctx, serial.FoldKey(sn))
	if err != nil {
		return UAS{}, false, err
	}
	facts := make([]identify.UASFacts, 0, len(rows))
	for i := range rows {
		facts = append(facts, identify.UASFacts{DroneID: rows[i].ID, Serial: rows[i].Serial, RegistrationStatus: string(rows[i].Status), InRegistry: true})
	}
	f, m := identify.NewSnapshot(nil, facts).UASBySerial(sn)
	if m != identify.MatchExact && m != identify.MatchFolded {
		return UAS{}, false, nil
	}
	i := slices.IndexFunc(rows, func(u UAS) bool { return u.ID == f.DroneID })
	return rows[i], true, nil
}

func (s *Service) answer(ctx context.Context, q Query, compareKey func(string) string, now time.Time) (Validity, error) {
	var v Validity
	if q.Operator != "" {
		ov := &OperatorValidity{Number: q.Operator, Status: ValidityUnknown}
		r, err := s.Store.OperatorByKey(ctx, compareKey(q.Operator))
		switch {
		case err == nil:
			until := r.ValidUntil
			ov.Status, ov.ValidUntil = operatorValidity(&r.Operator, now), &until
		case !errors.Is(err, ErrNotFound):
			return Validity{}, err
		}
		v.Operator = ov
	}
	if q.Serial != "" {
		uv := &UASValidity{Serial: q.Serial, Status: ValidityUnknown}
		u, ok, err := s.lookupSerial(ctx, q.Serial)
		if err != nil {
			return Validity{}, err
		}
		if ok {
			uv.Status, uv.ClassLabel, uv.MTOMBand = entityValidity(u.Status), u.ClassLabel, MTOMBand(u.MTOMG, s.MTOMBandsG)
		}
		v.UAS = uv
	}
	if q.Pilot != "" {
		pv := &PilotValidity{Pilot: q.Pilot, Status: ValidityUnknown, Competencies: []CompetencyValidity{}}
		if ValidID(q.Pilot) {
			r, err := s.Store.Pilot(ctx, q.Pilot)
			switch {
			case err == nil:
				pv.Status = entityValidity(r.Status)
				for _, c := range r.Competencies {
					pv.Competencies = append(pv.Competencies, CompetencyValidity{Competency: c.Competency, ValidUntil: c.ValidUntil})
				}
			case !errors.Is(err, ErrNotFound):
				return Validity{}, err
			}
		}
		v.Pilot = pv
	}
	return v, nil
}

// Validate answers F8 lookups, status only, and records the call as one
// registry_validated event with the client and the purpose. No answer
// leaves without its events row.
func (s *Service) Validate(ctx context.Context, qs []Query, purpose string, actor audit.Actor) ([]Validity, error) {
	if err := checkQueries(qs, purpose); err != nil {
		return nil, s.refused(err)
	}
	v, err := s.validator()
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]Validity, 0, len(qs))
	var operators, serials, pilots []string
	unknown := 0
	for _, q := range qs {
		a, err := s.answer(ctx, q, v.CompareKey, now)
		if err != nil {
			return nil, err
		}
		for _, p := range []struct {
			key    string
			status string
			keys   *[]string
		}{
			{q.Operator, statusOf(a.Operator), &operators}, {q.Serial, statusOfUAS(a.UAS), &serials}, {q.Pilot, statusOfPilot(a.Pilot), &pilots},
		} {
			if p.key == "" {
				continue
			}
			*p.keys = append(*p.keys, p.key)
			if p.status == ValidityUnknown {
				unknown++
			}
		}
		out = append(out, a)
	}
	err = s.Store.InTx(ctx, func(tx Tx) error {
		return tx.Record(ctx, audit.Event{
			Actor: actor, Purpose: purpose, EntityType: "registry", EventType: audit.EventRegistryValidated,
			Payload: map[string]any{"operators": operators, "serials": serials, "pilots": pilots, "unknown": unknown},
		})
	})
	if err != nil {
		return nil, err
	}
	if s.Counters != nil {
		s.Counters.Add(CounterValidated, uint64(len(operators)+len(serials)+len(pilots)))
		s.Counters.Add(CounterValidatedUnknown, uint64(unknown))
	}
	return out, nil
}

func statusOf(v *OperatorValidity) string {
	if v == nil {
		return ""
	}
	return v.Status
}

func statusOfUAS(v *UASValidity) string {
	if v == nil {
		return ""
	}
	return v.Status
}

func statusOfPilot(v *PilotValidity) string {
	if v == nil {
		return ""
	}
	return v.Status
}

// MaxChangesPage bounds one change-feed page.
const MaxChangesPage = 1000

// Changes reads the change feed after since and returns the sequence
// the next page starts after (since itself when nothing is newer).
func (s *Service) Changes(ctx context.Context, since int64, limit int) ([]Change, int64, error) {
	if since < 0 {
		return nil, 0, s.refused(core.Fieldf("since", "must not be negative"))
	}
	if limit <= 0 || limit > MaxChangesPage {
		limit = MaxChangesPage
	}
	rows, err := s.Store.Changes(ctx, since, limit)
	if err != nil {
		return nil, 0, err
	}
	next := since
	if len(rows) > 0 {
		next = rows[len(rows)-1].Seq
	}
	return rows, next, nil
}
