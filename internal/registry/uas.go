package registry

import (
	"context"
	"errors"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/serial"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// foldConflict refuses a serial another aircraft holds, exactly or
// folded (G-05): an exact duplicate, or a second spelling that differs
// only by case and would make every folded lookup of both ambiguous.
func foldConflict(sn string, existing []UAS) error {
	for i := range existing {
		if existing[i].Serial == sn {
			return conflict("this serial is registered already",
				core.Fieldf("serial", "%q is registered already", sn))
		}
	}
	if len(existing) > 0 {
		return conflict("this serial differs only by case from a registered one",
			core.Fieldf("serial", "%q differs only by case from a registered serial; a lookup of either would be ambiguous (G-05)", sn))
	}
	return nil
}

// CreateUAS registers an aircraft of a registered operator. The serial
// is kept as given and validated for its class by uspace-core serial
// (G-05, G-06); the aircraft and its owner are projected with it.
func (s *Service) CreateUAS(ctx context.Context, in NewUAS, actor audit.Actor) (UAS, error) {
	u, err := checkNewUAS(in)
	if err != nil {
		return UAS{}, s.refused(err)
	}
	if u.ID, err = newID(); err != nil {
		return UAS{}, err
	}
	var out UAS
	err = s.change(ctx, func(tx Tx, cs *changeSet) error {
		op, err := tx.OperatorForUpdate(ctx, u.OperatorID)
		if errors.Is(err, ErrNotFound) {
			return core.Fieldf("operator_id", "no operator %q is registered", u.OperatorID)
		}
		if err != nil {
			return err
		}
		if op.Status == StatusRevoked {
			return conflict("the operator's registration is revoked", core.Fieldf("operator_id", "operator %q is revoked", op.ID))
		}
		existing, err := tx.UASByFold(ctx, u.SerialFold)
		if err != nil {
			return err
		}
		if err := foldConflict(u.Serial, existing); err != nil {
			return err
		}
		u.Status, u.RegisteredAt, u.RegistryVersion = StatusActive, cs.at, cs.version
		u.CreatedBy, u.UpdatedAt, u.UpdatedBy = actor.ID, cs.at, actor.ID
		r, err := tx.InsertUAS(ctx, u)
		if errors.Is(err, ErrDuplicate) {
			return conflict("this serial is registered already", core.Fieldf("serial", "%q is registered already", u.Serial))
		}
		if err != nil {
			return err
		}
		if err := s.feed(ctx, tx, EntityUAS, r.ID, r.Serial, StatusActive, cs.at); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityUAS, EntityID: r.ID, EventType: audit.EventUASRegistered,
			Payload: map[string]any{"serial": r.Serial, "operator_id": r.OperatorID, "class_label": r.ClassLabel, "registry_version": cs.version},
		}); err != nil {
			return err
		}
		// The owner is projected with its aircraft, so the aircraft never
		// reaches a resolver before its owner (identify's owner_unknown).
		cs.ops = append(cs.ops, projectOperator(&op.Operator))
		cs.uas = append(cs.uas, projectUAS(&r))
		out = r
		return nil
	})
	return out, err
}

func (s *Service) uasForUpdate(ctx context.Context, tx Tx, id string) (UAS, error) {
	u, err := tx.UASForUpdate(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return UAS{}, notFound(EntityUAS, id)
	}
	return u, err
}

func uasPatchedFields(p UASPatch) []string {
	var out []string
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"registration_mark", p.RegistrationMark != nil}, {"manufacturer", p.Manufacturer != nil}, {"model", p.Model != nil},
		{"owner_ref", p.OwnerRef != nil}, {"class_label", p.ClassLabel != nil}, {"mtom_g", p.MTOMG != nil},
		{"rid_capability", p.RIDCapability != nil},
	} {
		if f.set {
			out = append(out, f.name)
		}
	}
	return out
}

// UpdateUAS changes an aircraft's details; a class change re-validates
// the serial (G-06).
func (s *Service) UpdateUAS(ctx context.Context, id string, p UASPatch, actor audit.Actor) (UAS, error) {
	fields := uasPatchedFields(p)
	if len(fields) == 0 {
		return UAS{}, s.refused(&core.FieldError{Field: "body", Reason: "names no field to change"})
	}
	var out UAS
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		u, err := s.uasForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if u.Status == StatusRevoked {
			return errRevokedFinal
		}
		u, err = applyUASPatch(u, p)
		if err != nil {
			return err
		}
		u.RegistryVersion, u.UpdatedAt, u.UpdatedBy = cs.version, cs.at, actor.ID
		r, err := tx.UpdateUAS(ctx, u)
		if err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityUAS, EntityID: id, EventType: audit.EventUASUpdated,
			Payload: map[string]any{"fields": fields, "registry_version": cs.version},
		}); err != nil {
			return err
		}
		cs.uas = append(cs.uas, projectUAS(&r))
		out = r
		return nil
	})
	return out, err
}

// SetUASStatus moves an aircraft along the status graph.
func (s *Service) SetUASStatus(ctx context.Context, id string, to Status, reason string, actor audit.Actor) (UAS, error) {
	var out UAS
	err := s.change(ctx, func(tx Tx, cs *changeSet) error {
		u, err := s.uasForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := CheckTransition(u.Status, to, reason, false); err != nil {
			return err
		}
		r, err := tx.SetUASStatus(ctx, StatusUpdate{ID: id, Status: to, Reason: reason, Version: cs.version, At: cs.at, By: actor.ID})
		if err != nil {
			return err
		}
		if err := s.feed(ctx, tx, EntityUAS, id, r.Serial, to, cs.at); err != nil {
			return err
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: EntityUAS, EntityID: id, EventType: audit.EventRegistryStatusChanged,
			Payload: map[string]any{"from": u.Status, "to": to, "reason": reason, "serial": r.Serial, "registry_version": cs.version},
		}); err != nil {
			return err
		}
		cs.uas = append(cs.uas, projectUAS(&r))
		out = r
		return nil
	})
	return out, err
}

// GetUAS reads one aircraft.
func (s *Service) GetUAS(ctx context.Context, id string) (UAS, error) {
	u, err := s.Store.UAS(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return UAS{}, notFound(EntityUAS, id)
	}
	return u, err
}

// ListUAS reads one page; sn filters on its fold key (serial.FoldKey,
// G-05, G-12), which the registry keeps unique.
func (s *Service) ListUAS(ctx context.Context, sn, operatorID string, st Status, page Page) ([]UAS, error) {
	f := UASFilter{OperatorID: operatorID, Status: st, Page: page}
	if sn != "" {
		f.SerialFold = serial.FoldKey(sn)
	}
	return s.Store.UASList(ctx, f)
}
