package registry

import (
	"context"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/projector"
)

// StatusUnregistered is the projected status of an operator row the
// registry does not hold. identify does not recognise it, so such an
// owner is owner_unknown, never in good standing (G-08).
const StatusUnregistered = "unregistered"

// Projection is where the registry projection is written: the
// telemetry database's proj_registry_* tables (D2), or a fake in tests.
type Projection interface {
	Begin(ctx context.Context) (ProjectionTx, error)
}

// ProjectionTx is one projection write. A change's rows never replace a
// row with a newer registry_version; a repair's rows replace every row
// (the registry is the authority, and the advisory lock keeps a change
// from committing between the repair's read and its write).
type ProjectionTx interface {
	UpsertOperators(ctx context.Context, rows []ProjectedOperator, at time.Time, repair bool) error
	UpsertUAS(ctx context.Context, rows []ProjectedUAS, at time.Time, repair bool) error
	// MarkMissing marks the rows whose ids are not in the registry:
	// aircraft in_registry = false, operators StatusUnregistered. It
	// returns how many rows it marked.
	MarkMissing(ctx context.Context, operatorIDs, uasIDs []string, at time.Time) (int64, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context)
}

// TSProjection is Projection on the telemetry database, as
// authority_ts_projector.
type TSProjection struct {
	P *ts.Projector
}

// Begin opens a projection transaction.
func (p TSProjection) Begin(ctx context.Context) (ProjectionTx, error) {
	tx, err := p.P.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return tsProjectionTx{tx: tx}, nil
}

type tsProjectionTx struct{ tx *ts.ProjectorTx }

// UpsertOperators implements ProjectionTx.
func (t tsProjectionTx) UpsertOperators(ctx context.Context, rows []ProjectedOperator, at time.Time, repair bool) error {
	if len(rows) == 0 {
		return nil
	}
	p := projector.UpsertProjectedOperatorsParams{ProjectedAt: at, Repair: repair}
	for _, r := range rows {
		p.OperatorIds = append(p.OperatorIds, r.OperatorID)
		p.RegistrationNumbers = append(p.RegistrationNumbers, r.RegistrationNumber)
		p.Statuses = append(p.Statuses, r.Status)
		p.RegistryVersions = append(p.RegistryVersions, r.Version)
	}
	_, err := t.tx.Q.UpsertProjectedOperators(ctx, p)
	return err
}

// UpsertUAS implements ProjectionTx.
func (t tsProjectionTx) UpsertUAS(ctx context.Context, rows []ProjectedUAS, at time.Time, repair bool) error {
	if len(rows) == 0 {
		return nil
	}
	p := projector.UpsertProjectedUASParams{ProjectedAt: at, Repair: repair}
	for _, r := range rows {
		p.UasIds = append(p.UasIds, r.UASID)
		p.Labels = append(p.Labels, r.Label)
		p.Serials = append(p.Serials, r.Serial)
		p.SerialFolds = append(p.SerialFolds, r.SerialFold)
		p.Statuses = append(p.Statuses, r.Status)
		p.OperatorIds = append(p.OperatorIds, r.OperatorID)
		p.RegistryVersions = append(p.RegistryVersions, r.Version)
	}
	_, err := t.tx.Q.UpsertProjectedUAS(ctx, p)
	return err
}

// MarkMissing implements ProjectionTx.
func (t tsProjectionTx) MarkMissing(ctx context.Context, operatorIDs, uasIDs []string, at time.Time) (int64, error) {
	if operatorIDs == nil {
		operatorIDs = []string{}
	}
	if uasIDs == nil {
		uasIDs = []string{}
	}
	nu, err := t.tx.Q.MarkUASNotInRegistry(ctx, projector.MarkUASNotInRegistryParams{ProjectedAt: at, KnownIds: uasIDs})
	if err != nil {
		return 0, err
	}
	no, err := t.tx.Q.MarkOperatorsNotInRegistry(ctx, projector.MarkOperatorsNotInRegistryParams{ProjectedAt: at, KnownIds: operatorIDs})
	if err != nil {
		return 0, err
	}
	return nu + no, nil
}

// Commit implements ProjectionTx.
func (t tsProjectionTx) Commit(ctx context.Context) error { return t.tx.Commit(ctx) }

// Rollback implements ProjectionTx.
func (t tsProjectionTx) Rollback(ctx context.Context) { t.tx.Rollback(ctx) }

// projectOperator is the projection row of an operator.
func projectOperator(o *Operator) ProjectedOperator {
	return ProjectedOperator{OperatorID: o.ID, RegistrationNumber: o.RegistrationNumber, Status: string(o.Status), Version: o.RegistryVersion}
}

// projectUAS is the projection row of an aircraft. The label is the
// registration mark, else the model (as AllUASFacts derives it).
func projectUAS(u *UAS) ProjectedUAS {
	label := u.RegistrationMark
	if label == "" {
		label = u.Model
	}
	return ProjectedUAS{
		UASID: u.ID, Label: label, Serial: u.Serial, SerialFold: u.SerialFold, Status: string(u.Status),
		OperatorID: u.OperatorID, Version: u.RegistryVersion,
	}
}
