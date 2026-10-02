package registry

import (
	"context"
	"errors"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// CreateOperator registers an operator under the active policy's
// registration-number format. The number is validated and keyed by
// uspace-core regnum only; the secret part is stored as a keyed hash;
// the personal data is sealed. The registration, its change-feed entry,
// its events row and its projection row commit together.
func (s *Service) CreateOperator(ctx context.Context, in NewOperator, actor audit.Actor) (Operator, error) {
	v, err := s.validator()
	if err != nil {
		return Operator{}, err
	}
	now := s.now()
	public, key, err := checkNewOperator(v, &in, now)
	if err == nil && in.ValidFrom.After(now) {
		err = core.Fieldf("valid_from", "must not be in the future")
	}
	if err != nil {
		return Operator{}, s.refused(err)
	}
	id, err := newID()
	if err != nil {
		return Operator{}, err
	}
	sealed, err := s.sealOperator(id, &in.PII)
	if err != nil {
		return Operator{}, err
	}
	var salt []byte
	var hash string
	if in.SecretPart != "" {
		if salt, hash, err = s.Hasher.NewSecretPart(in.SecretPart); err != nil {
			return Operator{}, err
		}
	}
	var out Operator
	err = s.change(ctx, func(tx Tx, cs *changeSet) error {
		dup := conflict("this registration number is registered already",
			core.Fieldf("registration_number", "%q is registered already (compared on its public part, ignoring case)", public))
		if _, err := tx.OperatorByKey(ctx, key); err == nil {
			return dup
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		r, err := tx.InsertOperator(ctx, OperatorRecord{
			Operator: Operator{
				ID: id, OperatorType: in.OperatorType, RegistrationNumber: public, CompetencyConfirmation: in.CompetencyConfirmation,
				Authorisations: in.Authorisations, Status: StatusActive, ValidFrom: in.ValidFrom.UTC(), ValidUntil: in.ValidUntil.UTC(),
				Source: in.Source, RegistryVersion: cs.version, CreatedAt: cs.at, CreatedBy: actor.ID, UpdatedAt: cs.at, UpdatedBy: actor.ID,
			},
			Key: key, SecretSalt: salt, SecretHash: hash, Sealed: sealed,
		})
		if errors.Is(err, ErrDuplicate) {
			return dup
		}
		if err != nil {
			return err
		}
		if err := s.feed(ctx, tx, EntityOperator, id, public, StatusActive, cs.at); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityOperator, EntityID: id, EventType: audit.EventOperatorRegistered,
			Payload: map[string]any{
				"registration_number": public, "operator_type": in.OperatorType, "source": in.Source,
				"has_secret_part": hash != "", "valid_until": in.ValidUntil.UTC(), "registry_version": cs.version,
			},
		}); err != nil {
			return err
		}
		out = r.Operator
		return nil
	})
	return out, err
}

// feed writes one change-feed entry (F8: ids and statuses only).
func (s *Service) feed(ctx context.Context, tx Tx, entity, id, publicKey string, st Status, at time.Time) error {
	_, err := tx.InsertChange(ctx, Change{EntityType: entity, EntityID: id, PublicKey: publicKey, Status: st, At: at})
	return err
}

// patchedFields names the fields a patch sets, for the events row (the
// values are personal and never logged).
func patchedFields(p OperatorPatch) []string {
	var out []string
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"full_name", p.FullName != nil}, {"legal_name", p.LegalName != nil}, {"date_of_birth", p.DateOfBirth != nil},
		{"legal_identification_number", p.LegalIdentificationNumber != nil}, {"postal_address", p.PostalAddress != nil},
		{"contact_email", p.ContactEmail != nil}, {"contact_phone", p.ContactPhone != nil},
		{"insurance_policy_number", p.InsurancePolicyNumber != nil}, {"competency_confirmation", p.CompetencyConfirmation != nil},
		{"authorisations", p.Authorisations != nil}, {"valid_until", p.ValidUntil != nil},
	} {
		if f.set {
			out = append(out, f.name)
		}
	}
	return out
}

func (s *Service) operatorForUpdate(ctx context.Context, tx Tx, id string) (OperatorRecord, error) {
	r, err := tx.OperatorForUpdate(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return OperatorRecord{}, notFound(EntityOperator, id)
	}
	return r, err
}

// UpdateOperator changes an operator's details (not its type, number or
// status).
func (s *Service) UpdateOperator(ctx context.Context, id string, p OperatorPatch, actor audit.Actor) (Operator, error) {
	fields := patchedFields(p)
	if len(fields) == 0 {
		return Operator{}, s.refused(&core.FieldError{Field: "body", Reason: "names no field to change"})
	}
	var out Operator
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		r, err := s.operatorForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.Status == StatusRevoked {
			return errRevokedFinal
		}
		pii, err := s.openOperator(&r)
		if err != nil {
			return err
		}
		o, pii, err := applyOperatorPatch(r.Operator, pii, p, cs.at)
		if err != nil {
			return err
		}
		sealed, err := s.sealOperator(id, &pii)
		if err != nil {
			return err
		}
		r.Operator, r.Sealed = o, sealed
		r.RegistryVersion, r.UpdatedAt, r.UpdatedBy = cs.version, cs.at, actor.ID
		u, err := tx.UpdateOperator(ctx, r)
		if err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityOperator, EntityID: id, EventType: audit.EventOperatorUpdated,
			Payload: map[string]any{"fields": fields, "registry_version": cs.version},
		}); err != nil {
			return err
		}
		out = u.Operator
		return nil
	})
	return out, err
}

// SetOperatorStatus moves an operator along the status graph. Renewing
// an expired registration needs a valid_until in the future first.
func (s *Service) SetOperatorStatus(ctx context.Context, id string, to Status, reason string, actor audit.Actor) (Operator, error) {
	var out Operator
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		r, err := s.operatorForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		o, err := s.operatorTransition(ctx, tx, cs, &r, to, reason, actor, false)
		out = o
		return err
	})
	return out, err
}

func (s *Service) operatorTransition(ctx context.Context, tx Tx, cs *changeSet, r *OperatorRecord, to Status, reason string,
	actor audit.Actor, bySystem bool,
) (Operator, error) {
	if err := CheckTransition(r.Status, to, reason, bySystem); err != nil {
		return Operator{}, err
	}
	if to == StatusActive && !r.ValidUntil.After(cs.at) {
		return Operator{}, conflict("the registration's validity has ended",
			core.Fieldf("valid_until", "set a valid_until in the future before reinstating"))
	}
	u, err := tx.SetOperatorStatus(ctx, StatusUpdate{ID: r.ID, Status: to, Reason: reason, Version: cs.version, At: cs.at, By: actor.ID})
	if err != nil {
		return Operator{}, err
	}
	if err := s.feed(ctx, tx, EntityOperator, r.ID, r.RegistrationNumber, to, cs.at); err != nil {
		return Operator{}, err
	}
	if err := tx.Record(ctx, audit.Event{
		Actor: actor, EntityType: EntityOperator, EntityID: r.ID, EventType: audit.EventRegistryStatusChanged,
		Payload: map[string]any{"from": r.Status, "to": to, "reason": reason, "registration_number": r.RegistrationNumber, "registry_version": cs.version},
	}); err != nil {
		return Operator{}, err
	}
	return u.Operator, nil
}

// GetOperator reads one operator without personal data.
func (s *Service) GetOperator(ctx context.Context, id string) (Operator, error) {
	r, err := s.Store.Operator(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Operator{}, notFound(EntityOperator, id)
	}
	return r.Operator, err
}

// ListOperators reads one page; number filters on its compare key
// (regnum.CompareKey under the active pattern, G-04).
func (s *Service) ListOperators(ctx context.Context, number string, st Status, page Page) ([]Operator, error) {
	f := OperatorFilter{Status: st, Page: page}
	if number != "" {
		v, err := s.validator()
		if err != nil {
			return nil, err
		}
		f.Key = v.CompareKey(number)
	}
	rows, err := s.Store.Operators(ctx, f)
	if err != nil {
		return nil, err
	}
	out := make([]Operator, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].Operator)
	}
	return out, nil
}

// OperatorPersonalData reads an operator's personal data for purpose.
// The registry_pii_viewed event is written in the transaction that reads
// the row, before anything is opened or returned; no purpose, no read.
func (s *Service) OperatorPersonalData(ctx context.Context, id, purpose string, actor audit.Actor) (OperatorPII, error) {
	if err := checkPurpose(purpose); err != nil {
		return OperatorPII{}, s.refused(err)
	}
	var out OperatorPII
	err := s.Store.InTx(ctx, func(tx Tx) error {
		r, err := s.operatorForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, Purpose: purpose, EntityType: EntityOperator, EntityID: id, EventType: audit.EventRegistryPIIViewed,
			Payload: map[string]any{"registration_number": r.RegistrationNumber},
		}); err != nil {
			return err
		}
		out, err = s.openOperator(&r)
		return err
	})
	if err != nil {
		return OperatorPII{}, s.refused(err)
	}
	return out, nil
}

// ExpireDue marks expired every registration whose valid_until has
// passed, up to a batch per run, as the system. It runs under the
// expiry job lock and skips when another replica holds it.
func (s *Service) ExpireDue(ctx context.Context) (int, error) {
	n := 0
	actor := audit.SystemActor("registry_expiry")
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		ok, err := tx.TryLock(ctx, LockExpiryJob)
		if err != nil || !ok {
			return err
		}
		ids, err := tx.ExpiredOperatorIDs(ctx, cs.at, expiryBatch)
		if err != nil {
			return err
		}
		for _, id := range ids {
			r, err := tx.OperatorForUpdate(ctx, id)
			if err != nil {
				return err
			}
			if _, err := s.operatorTransition(ctx, tx, cs, &r, StatusExpired, "valid_until passed", actor, true); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		s.count(CounterExpiryFailed)
		return 0, err
	}
	for range n {
		s.count(CounterExpired)
	}
	return n, nil
}
