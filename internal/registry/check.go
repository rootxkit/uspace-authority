package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// CounterChecked counts the public checks answered (WP-20).
const CounterChecked = "registry_public_checked"

// PublicCheck is the public answer for a registration number: its
// status (valid, suspended, revoked or unknown) and, when the number is
// registered, the end of its validity. Nothing else, ever: no name, no
// type, no id (CLAUDE.md rule 6).
type PublicCheck struct {
	Status     string
	ValidUntil *time.Time
}

// CheckNumber answers GET /v1/registry/check: the status of the
// operator registration number, compared on its public part ignoring
// case (G-04, G-12; a secret part sent with it is removed and never
// echoed or recorded), status only. An expired registration answers
// revoked with its valid_until, as F8 does.
func (s *Service) CheckNumber(ctx context.Context, number string) (PublicCheck, error) {
	number = strings.TrimSpace(number)
	switch {
	case number == "":
		return PublicCheck{}, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "",
			&core.FieldError{Field: "number", Reason: "required"})
	case len(number) > regnum.MaxLen:
		return PublicCheck{}, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "",
			core.Fieldf("number", "longer than %d characters", regnum.MaxLen))
	}
	v, err := s.validator()
	if err != nil {
		return PublicCheck{}, err
	}
	r, err := s.Store.OperatorByKey(ctx, v.CompareKey(number))
	switch {
	case errors.Is(err, ErrNotFound):
		s.count(CounterChecked)
		return PublicCheck{Status: ValidityUnknown}, nil
	case err != nil:
		return PublicCheck{}, err
	}
	s.count(CounterChecked)
	until := r.ValidUntil.UTC()
	return PublicCheck{Status: operatorValidity(&r.Operator, s.now()), ValidUntil: &until}, nil
}

// OperatorBySource reads the operator a source made under its own id
// (WP-20: a retried portal approval finds the operator it registered).
// The answer carries no personal data.
func (s *Service) OperatorBySource(ctx context.Context, source, ref string) (Operator, bool, error) {
	r, err := s.Store.OperatorBySourceRef(ctx, source, ref)
	switch {
	case errors.Is(err, ErrNotFound):
		return Operator{}, false, nil
	case err != nil:
		return Operator{}, false, err
	}
	return r.Operator, true, nil
}

// OperatorContact is what the portal needs to send an operator its
// occurrence link: the registration (public part, id, status) and the
// registered e-mail address, opened for that delivery only.
type OperatorContact struct {
	OperatorID         string
	RegistrationNumber string
	// Valid is true for a registration in good standing now (F8's
	// valid); only such an operator is sent a link.
	Valid        bool
	ContactEmail string
}

// ContactForLink reads the registered e-mail address of the operator a
// number names (public part, case ignored), for the portal's operator
// link (WP-20). found is false for an unknown number. The address is
// opened only to be sealed into the link's outbox row; the caller
// records the events row of that delivery in its own transaction.
func (s *Service) ContactForLink(ctx context.Context, number string) (OperatorContact, bool, error) {
	v, err := s.validator()
	if err != nil {
		return OperatorContact{}, false, err
	}
	r, err := s.Store.OperatorByKey(ctx, v.CompareKey(strings.TrimSpace(number)))
	switch {
	case errors.Is(err, ErrNotFound):
		return OperatorContact{}, false, nil
	case err != nil:
		return OperatorContact{}, false, err
	}
	email, err := s.open(r.Sealed.KeyID, tableOperators, r.ID, "contact_email", r.Sealed.ContactEmail)
	if err != nil {
		return OperatorContact{}, false, err
	}
	return OperatorContact{OperatorID: r.ID, RegistrationNumber: r.RegistrationNumber,
		Valid: operatorValidity(&r.Operator, s.now()) == ValidityValid, ContactEmail: email}, true, nil
}

// CheckApplicant checks a portal application's Art. 14(2) fields as a
// registration checks them (WP-20), naming every field at fault, so an
// application that could never be approved is refused at submission.
func CheckApplicant(operatorType string, p OperatorPII, authorisations json.RawMessage, now time.Time) error {
	errs := validatePII(operatorType, p, now)
	errs = append(errs, validAuthorisations(authorisations))
	return errors.Join(errs...)
}

// NumberFree checks a number the portal would issue (WP-20, Q-A10):
// valid under the active policy's pattern (regnum, G-07) and held by no
// registration (compared on its public part ignoring case, G-04). It
// answers the public part to register.
func (s *Service) NumberFree(ctx context.Context, number string) (public string, free bool, err error) {
	v, err := s.validator()
	if err != nil {
		return "", false, err
	}
	if err := v.Validate(number); err != nil {
		return "", false, err
	}
	public, key := v.Public(number)
	_, err = s.Store.OperatorByKey(ctx, key)
	switch {
	case errors.Is(err, ErrNotFound):
		return public, true, nil
	case err != nil:
		return "", false, err
	}
	return public, false, nil
}
