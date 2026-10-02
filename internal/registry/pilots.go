package registry

import (
	"context"
	"errors"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

const tablePilots = "remote_pilots"

// checkOperatorRef refuses an operator id that names no registered,
// unrevoked operator.
func checkOperatorRef(ctx context.Context, tx Tx, id string) error {
	if id == "" {
		return nil
	}
	op, err := tx.OperatorForUpdate(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return core.Fieldf("operator_id", "no operator %q is registered", id)
	}
	if err != nil {
		return err
	}
	if op.Status == StatusRevoked {
		return conflict("the operator's registration is revoked", core.Fieldf("operator_id", "operator %q is revoked", id))
	}
	return nil
}

// CreatePilot registers a remote pilot. The national id is kept only as
// a keyed hash and its last four characters; the name is sealed.
func (s *Service) CreatePilot(ctx context.Context, in NewPilot, actor audit.Actor) (Pilot, error) {
	if err := checkNewPilot(in); err != nil {
		return Pilot{}, s.refused(err)
	}
	id, err := newID()
	if err != nil {
		return Pilot{}, err
	}
	ref := normalPersonRef(in.PersonRef)
	hash := s.Hasher.PersonRef(ref)
	name, err := s.seal(tablePilots, id, "name", in.Name)
	if err != nil {
		return Pilot{}, err
	}
	dup := conflict("this person is registered as a remote pilot already", core.Fieldf("person_ref", "registered already"))
	var out Pilot
	err = s.change(ctx, func(tx Tx, cs *changeSet) error {
		if err := checkOperatorRef(ctx, tx, in.OperatorID); err != nil {
			return err
		}
		if _, err := tx.PilotByPersonRef(ctx, hash); err == nil {
			return dup
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		r, err := tx.InsertPilot(ctx, PilotRecord{
			Pilot: Pilot{
				ID: id, OperatorID: in.OperatorID, Status: StatusActive, RegistryVersion: cs.version,
				CreatedAt: cs.at, CreatedBy: actor.ID, UpdatedAt: cs.at, UpdatedBy: actor.ID,
			},
			PersonRefHash: hash, PersonRefLast4: last4(ref), KeyID: s.Sealer.KeyID(), NameSealed: name,
		})
		if errors.Is(err, ErrDuplicate) {
			return dup
		}
		if err != nil {
			return err
		}
		if err := s.feed(ctx, tx, EntityPilot, id, id, StatusActive, cs.at); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityPilot, EntityID: id, EventType: audit.EventPilotRegistered,
			Payload: map[string]any{"operator_id": in.OperatorID, "registry_version": cs.version},
		}); err != nil {
			return err
		}
		out = r.Pilot
		return nil
	})
	return out, err
}

func (s *Service) pilotForUpdate(ctx context.Context, tx Tx, id string) (PilotRecord, error) {
	r, err := tx.PilotForUpdate(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return PilotRecord{}, notFound(EntityPilot, id)
	}
	return r, err
}

// UpdatePilot changes a pilot's name or operator ("" detaches).
func (s *Service) UpdatePilot(ctx context.Context, id string, p PilotPatch, actor audit.Actor) (Pilot, error) {
	var fields []string
	var errs []error
	if p.Name != nil {
		fields = append(fields, "name")
		errs = append(errs, text("name", *p.Name, maxNameLen, true))
	}
	if p.OperatorID != nil {
		fields = append(fields, "operator_id")
		if *p.OperatorID != "" && !ValidID(*p.OperatorID) {
			errs = append(errs, core.Fieldf("operator_id", "not a registry id"))
		}
	}
	if len(fields) == 0 {
		errs = append(errs, &core.FieldError{Field: "body", Reason: "names no field to change"})
	}
	if err := errors.Join(errs...); err != nil {
		return Pilot{}, s.refused(err)
	}
	var out Pilot
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		r, err := s.pilotForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if r.Status == StatusRevoked {
			return errRevokedFinal
		}
		if p.OperatorID != nil {
			if err := checkOperatorRef(ctx, tx, *p.OperatorID); err != nil {
				return err
			}
			r.OperatorID = *p.OperatorID
		}
		if p.Name != nil {
			if r.NameSealed, err = s.seal(tablePilots, id, "name", *p.Name); err != nil {
				return err
			}
			r.KeyID = s.Sealer.KeyID()
		}
		r.RegistryVersion, r.UpdatedAt, r.UpdatedBy = cs.version, cs.at, actor.ID
		u, err := tx.UpdatePilot(ctx, r)
		if err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityPilot, EntityID: id, EventType: audit.EventPilotUpdated,
			Payload: map[string]any{"fields": fields, "registry_version": cs.version},
		}); err != nil {
			return err
		}
		out = u.Pilot
		return nil
	})
	return out, err
}

// SetPilotStatus moves a pilot along the status graph.
func (s *Service) SetPilotStatus(ctx context.Context, id string, to Status, reason string, actor audit.Actor) (Pilot, error) {
	var out Pilot
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		r, err := s.pilotForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := CheckTransition(r.Status, to, reason, false); err != nil {
			return err
		}
		u, err := tx.SetPilotStatus(ctx, StatusUpdate{ID: id, Status: to, Reason: reason, Version: cs.version, At: cs.at, By: actor.ID})
		if err != nil {
			return err
		}
		if err := s.feed(ctx, tx, EntityPilot, id, id, to, cs.at); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityPilot, EntityID: id, EventType: audit.EventRegistryStatusChanged,
			Payload: map[string]any{"from": r.Status, "to": to, "reason": reason, "registry_version": cs.version},
		}); err != nil {
			return err
		}
		out = u.Pilot
		return nil
	})
	return out, err
}

// RecordCompetency records or renews one competency of a pilot.
func (s *Service) RecordCompetency(ctx context.Context, pilotID string, c Competency, actor audit.Actor) (Pilot, error) {
	if err := checkCompetency(c); err != nil {
		return Pilot{}, s.refused(err)
	}
	var out Pilot
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		r, err := s.pilotForUpdate(ctx, tx, pilotID)
		if err != nil {
			return err
		}
		if r.Status == StatusRevoked {
			return errRevokedFinal
		}
		c.ValidUntil, c.RecordedAt, c.RecordedBy = c.ValidUntil.UTC(), cs.at, actor.ID
		if err := tx.UpsertCompetency(ctx, pilotID, c); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityPilot, EntityID: pilotID, EventType: audit.EventPilotCompetencyRecorded,
			Payload: map[string]any{"competency": c.Competency, "certificate_ref": c.CertificateRef, "valid_until": c.ValidUntil},
		}); err != nil {
			return err
		}
		r, err = tx.PilotForUpdate(ctx, pilotID)
		out = r.Pilot
		return err
	})
	return out, err
}

// GetPilot reads one pilot without personal data.
func (s *Service) GetPilot(ctx context.Context, id string) (Pilot, error) {
	r, err := s.Store.Pilot(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return Pilot{}, notFound(EntityPilot, id)
	}
	return r.Pilot, err
}

// ListPilots reads one page.
func (s *Service) ListPilots(ctx context.Context, operatorID string, st Status, page Page) ([]Pilot, error) {
	rows, err := s.Store.Pilots(ctx, PilotFilter{OperatorID: operatorID, Status: st, Page: page})
	if err != nil {
		return nil, err
	}
	out := make([]Pilot, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].Pilot)
	}
	return out, nil
}

// PilotPersonalData reads a pilot's personal data for purpose, recorded
// before anything is opened (registry_pii_viewed).
func (s *Service) PilotPersonalData(ctx context.Context, id, purpose string, actor audit.Actor) (PilotPII, error) {
	if err := checkPurpose(purpose); err != nil {
		return PilotPII{}, s.refused(err)
	}
	var out PilotPII
	err := s.Store.InTx(ctx, func(tx Tx) error {
		r, err := s.pilotForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, Purpose: purpose, EntityType: EntityPilot, EntityID: id, EventType: audit.EventRegistryPIIViewed,
			Payload: map[string]any{},
		}); err != nil {
			return err
		}
		name, err := s.open(r.KeyID, tablePilots, id, "name", r.NameSealed)
		out = PilotPII{Name: name, PersonRefLast4: r.PersonRefLast4}
		return err
	})
	if err != nil {
		return PilotPII{}, s.refused(err)
	}
	return out, nil
}
