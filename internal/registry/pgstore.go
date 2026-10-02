package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// PG is Store on the relational database, recording events through the
// audit writer in the same transaction.
type PG struct {
	DB    *pg.DB
	Audit *audit.Writer
}

var _ Store = PG{}

// InTx runs fn in a relational transaction.
func (p PG) InTx(ctx context.Context, fn func(Tx) error) error {
	return p.DB.WithTx(ctx, func(q *gen.Queries) error { return fn(pgTx{q: q, audit: p.Audit}) })
}

// mapErr turns no-rows into ErrNotFound and a unique violation into
// ErrDuplicate, keeping the cause.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case store.IsNoRows(err):
		return ErrNotFound
	case store.SQLState(err) == store.StateUniqueViolation:
		return fmt.Errorf("%w: %w", ErrDuplicate, err)
	}
	return err
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func optInt(i *int) *int32 {
	if i == nil {
		return nil
	}
	v := int32(*i)
	return &v
}

func intPtr(i *int32) *int {
	if i == nil {
		return nil
	}
	v := int(*i)
	return &v
}

func authorisationsJSON(raw json.RawMessage) []byte {
	if raw == nil {
		return []byte("[]")
	}
	return raw
}

func operatorFromRow(r *gen.UasOperator) OperatorRecord {
	return OperatorRecord{
		Operator: Operator{
			ID: r.ID, OperatorType: r.OperatorType, RegistrationNumber: r.RegistrationNumberPublic,
			HasSecretPart: r.SecretPartHash != nil, CompetencyConfirmation: r.CompetencyConfirmation,
			Authorisations: json.RawMessage(r.Authorisations), Status: Status(r.Status), StatusReason: r.StatusReason,
			ValidFrom: r.ValidFrom, ValidUntil: r.ValidUntil, Source: r.Source, RegistryVersion: r.RegistryVersion,
			CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
		},
		Key: r.RegistrationNumberKey, SecretSalt: r.SecretPartSalt, SecretHash: str(r.SecretPartHash),
		Sealed: SealedOperator{
			KeyID: r.PiiKeyID, FullName: r.FullNameEnc, LegalName: r.LegalNameEnc, DateOfBirth: r.DateOfBirthEnc,
			LegalIdentificationNumber: r.LegalIdentificationNumberEnc, PostalAddress: r.PostalAddressEnc,
			ContactEmail: r.ContactEmailEnc, ContactPhone: r.ContactPhoneEnc, InsurancePolicyNumber: r.InsurancePolicyNumberEnc,
		},
	}
}

func uasFromRow(r *gen.UAS) UAS {
	return UAS{
		ID: r.ID, OperatorID: r.OperatorID, Serial: r.Serial, SerialFold: r.SerialFold, ManufacturerCode: r.ManufacturerCode,
		RegistrationMark: str(r.RegistrationMark), Manufacturer: r.Manufacturer, Model: r.Model, OwnerRef: str(r.OwnerRef),
		ClassLabel: str(r.ClassLabel), MTOMG: intPtr(r.MtomG), RIDCapability: r.RidCapability, Status: Status(r.Status),
		StatusReason: r.StatusReason, RegisteredAt: r.RegisteredAt, RegistryVersion: r.RegistryVersion,
		CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
	}
}

func pilotFromRow(r *gen.RemotePilot) PilotRecord {
	return PilotRecord{
		Pilot: Pilot{
			ID: r.ID, OperatorID: str(r.OperatorID), Status: Status(r.Status), StatusReason: r.StatusReason,
			Competencies: []Competency{}, RegistryVersion: r.RegistryVersion,
			CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
		},
		PersonRefHash: r.PersonRefHash, PersonRefLast4: r.PersonRefLast4, KeyID: r.PiiKeyID, NameSealed: r.NameEnc,
	}
}

func competencies(ctx context.Context, q *gen.Queries, p *PilotRecord) error {
	rows, err := q.CompetenciesOf(ctx, p.ID)
	if err != nil {
		return err
	}
	p.Competencies = make([]Competency, 0, len(rows))
	for _, c := range rows {
		p.Competencies = append(p.Competencies, Competency{
			Competency: c.Competency, CertificateRef: c.CertificateRef, ValidUntil: c.ValidUntil,
			RecordedAt: c.RecordedAt, RecordedBy: c.RecordedBy,
		})
	}
	return nil
}

func pilotWith(ctx context.Context, q *gen.Queries, r gen.RemotePilot, err error) (PilotRecord, error) {
	if err != nil {
		return PilotRecord{}, mapErr(err)
	}
	p := pilotFromRow(&r)
	err = competencies(ctx, q, &p)
	return p, err
}

func limitOf(p Page) int32 {
	if p.Limit <= 0 || p.Limit > MaxPageSize {
		return MaxPageSize
	}
	return int32(p.Limit)
}

func optStatus(s Status) *string { return optStr(string(s)) }

// Operator reads one operator.
func (p PG) Operator(ctx context.Context, id string) (OperatorRecord, error) {
	r, err := p.DB.Queries().OperatorByID(ctx, id)
	if err != nil {
		return OperatorRecord{}, mapErr(err)
	}
	return operatorFromRow(&r), nil
}

// OperatorByKey reads the operator with a compare key.
func (p PG) OperatorByKey(ctx context.Context, key string) (OperatorRecord, error) {
	r, err := p.DB.Queries().OperatorByKey(ctx, key)
	if err != nil {
		return OperatorRecord{}, mapErr(err)
	}
	return operatorFromRow(&r), nil
}

// Operators reads one page.
func (p PG) Operators(ctx context.Context, f OperatorFilter) ([]OperatorRecord, error) {
	rows, err := p.DB.Queries().ListOperators(ctx, gen.ListOperatorsParams{
		RegistrationNumberKey: optStr(f.Key), Status: optStatus(f.Status), AfterID: f.After, PageSize: limitOf(f.Page),
	})
	if err != nil {
		return nil, err
	}
	out := make([]OperatorRecord, 0, len(rows))
	for i := range rows {
		out = append(out, operatorFromRow(&rows[i]))
	}
	return out, nil
}

// UAS reads one aircraft.
func (p PG) UAS(ctx context.Context, id string) (UAS, error) {
	r, err := p.DB.Queries().UASByID(ctx, id)
	if err != nil {
		return UAS{}, mapErr(err)
	}
	return uasFromRow(&r), nil
}

func uasList(rows []gen.UAS) []UAS {
	out := make([]UAS, 0, len(rows))
	for i := range rows {
		out = append(out, uasFromRow(&rows[i]))
	}
	return out
}

// UASByFold reads the aircraft whose serial folds to fold.
func (p PG) UASByFold(ctx context.Context, fold string) ([]UAS, error) {
	rows, err := p.DB.Queries().UASBySerialFold(ctx, fold)
	if err != nil {
		return nil, err
	}
	return uasList(rows), nil
}

// UASList reads one page.
func (p PG) UASList(ctx context.Context, f UASFilter) ([]UAS, error) {
	rows, err := p.DB.Queries().ListUAS(ctx, gen.ListUASParams{
		SerialFold: optStr(f.SerialFold), OperatorID: optStr(f.OperatorID), Status: optStatus(f.Status),
		AfterID: f.After, PageSize: limitOf(f.Page),
	})
	if err != nil {
		return nil, err
	}
	return uasList(rows), nil
}

// Pilot reads one pilot with its competencies.
func (p PG) Pilot(ctx context.Context, id string) (PilotRecord, error) {
	q := p.DB.Queries()
	r, err := q.PilotByID(ctx, id)
	return pilotWith(ctx, q, r, err)
}

// Pilots reads one page, each with its competencies.
func (p PG) Pilots(ctx context.Context, f PilotFilter) ([]PilotRecord, error) {
	q := p.DB.Queries()
	rows, err := q.ListPilots(ctx, gen.ListPilotsParams{
		OperatorID: optStr(f.OperatorID), Status: optStatus(f.Status), AfterID: f.After, PageSize: limitOf(f.Page),
	})
	if err != nil {
		return nil, err
	}
	out := make([]PilotRecord, 0, len(rows))
	for i := range rows {
		pr, err := pilotWith(ctx, q, rows[i], nil)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, nil
}

// Changes reads the change feed after since.
func (p PG) Changes(ctx context.Context, since int64, limit int) ([]Change, error) {
	rows, err := p.DB.Queries().ListStatusChanges(ctx, gen.ListStatusChangesParams{Since: since, PageSize: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Change, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, Change{Seq: r.Seq, EntityType: r.EntityType, EntityID: r.EntityID, PublicKey: r.PublicKey, Status: Status(r.Status), At: r.At})
	}
	return out, nil
}

type pgTx struct {
	q     *gen.Queries
	audit *audit.Writer
}

// Lock implements Tx.
func (t pgTx) Lock(ctx context.Context, name string) error {
	return t.q.AdvisoryXactLock(ctx, pg.LockKey(name))
}

// TryLock implements Tx.
func (t pgTx) TryLock(ctx context.Context, name string) (bool, error) {
	return t.q.TryAdvisoryXactLock(ctx, pg.LockKey(name))
}

// Record implements Tx.
func (t pgTx) Record(ctx context.Context, ev audit.Event) error {
	_, err := t.audit.Record(ctx, t.q, ev)
	return err
}

// NextVersion implements Tx.
func (t pgTx) NextVersion(ctx context.Context) (int64, error) { return t.q.NextRegistryVersion(ctx) }

// InsertOperator implements Tx.
func (t pgTx) InsertOperator(ctx context.Context, r OperatorRecord) (OperatorRecord, error) {
	s := r.Sealed
	row, err := t.q.InsertOperator(ctx, gen.InsertOperatorParams{
		ID: r.ID, OperatorType: r.OperatorType, RegistrationNumberPublic: r.RegistrationNumber, RegistrationNumberKey: r.Key,
		SecretPartSalt: r.SecretSalt, SecretPartHash: optStr(r.SecretHash), PiiKeyID: s.KeyID,
		FullNameEnc: s.FullName, LegalNameEnc: s.LegalName, DateOfBirthEnc: s.DateOfBirth,
		LegalIdentificationNumberEnc: s.LegalIdentificationNumber, PostalAddressEnc: s.PostalAddress,
		ContactEmailEnc: s.ContactEmail, ContactPhoneEnc: s.ContactPhone, InsurancePolicyNumberEnc: s.InsurancePolicyNumber,
		CompetencyConfirmation: r.CompetencyConfirmation, Authorisations: authorisationsJSON(r.Authorisations),
		Status: string(r.Status), StatusReason: r.StatusReason, ValidFrom: r.ValidFrom, ValidUntil: r.ValidUntil,
		Source: r.Source, RegistryVersion: r.RegistryVersion, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
	})
	if err != nil {
		return OperatorRecord{}, mapErr(err)
	}
	return operatorFromRow(&row), nil
}

// OperatorForUpdate implements Tx.
func (t pgTx) OperatorForUpdate(ctx context.Context, id string) (OperatorRecord, error) {
	r, err := t.q.OperatorForUpdate(ctx, id)
	if err != nil {
		return OperatorRecord{}, mapErr(err)
	}
	return operatorFromRow(&r), nil
}

// OperatorByKey implements Tx.
func (t pgTx) OperatorByKey(ctx context.Context, key string) (OperatorRecord, error) {
	r, err := t.q.OperatorByKey(ctx, key)
	if err != nil {
		return OperatorRecord{}, mapErr(err)
	}
	return operatorFromRow(&r), nil
}

// UpdateOperator implements Tx.
func (t pgTx) UpdateOperator(ctx context.Context, r OperatorRecord) (OperatorRecord, error) {
	s := r.Sealed
	row, err := t.q.UpdateOperator(ctx, gen.UpdateOperatorParams{
		ID: r.ID, PiiKeyID: s.KeyID, FullNameEnc: s.FullName, LegalNameEnc: s.LegalName, DateOfBirthEnc: s.DateOfBirth,
		LegalIdentificationNumberEnc: s.LegalIdentificationNumber, PostalAddressEnc: s.PostalAddress,
		ContactEmailEnc: s.ContactEmail, ContactPhoneEnc: s.ContactPhone, InsurancePolicyNumberEnc: s.InsurancePolicyNumber,
		CompetencyConfirmation: r.CompetencyConfirmation, Authorisations: authorisationsJSON(r.Authorisations),
		ValidUntil: r.ValidUntil, RegistryVersion: r.RegistryVersion, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
	})
	if err != nil {
		return OperatorRecord{}, mapErr(err)
	}
	return operatorFromRow(&row), nil
}

// SetOperatorStatus implements Tx.
func (t pgTx) SetOperatorStatus(ctx context.Context, u StatusUpdate) (OperatorRecord, error) {
	row, err := t.q.SetOperatorStatus(ctx, gen.SetOperatorStatusParams{
		ID: u.ID, Status: string(u.Status), StatusReason: u.Reason, RegistryVersion: u.Version, UpdatedAt: u.At, UpdatedBy: u.By,
	})
	if err != nil {
		return OperatorRecord{}, mapErr(err)
	}
	return operatorFromRow(&row), nil
}

// ExpiredOperatorIDs implements Tx.
func (t pgTx) ExpiredOperatorIDs(ctx context.Context, now time.Time, limit int) ([]string, error) {
	return t.q.ExpiredOperatorIDs(ctx, gen.ExpiredOperatorIDsParams{Now: now, PageSize: int32(limit)})
}

// InsertUAS implements Tx.
func (t pgTx) InsertUAS(ctx context.Context, u UAS) (UAS, error) {
	row, err := t.q.InsertUAS(ctx, gen.InsertUASParams{
		ID: u.ID, OperatorID: u.OperatorID, Serial: u.Serial, SerialFold: u.SerialFold, ManufacturerCode: u.ManufacturerCode,
		RegistrationMark: optStr(u.RegistrationMark), Manufacturer: u.Manufacturer, Model: u.Model, OwnerRef: optStr(u.OwnerRef),
		ClassLabel: optStr(u.ClassLabel), MtomG: optInt(u.MTOMG), RidCapability: u.RIDCapability, Status: string(u.Status),
		StatusReason: u.StatusReason, RegisteredAt: u.RegisteredAt, RegistryVersion: u.RegistryVersion, CreatedBy: u.CreatedBy,
	})
	if err != nil {
		return UAS{}, mapErr(err)
	}
	return uasFromRow(&row), nil
}

// UASForUpdate implements Tx.
func (t pgTx) UASForUpdate(ctx context.Context, id string) (UAS, error) {
	r, err := t.q.UASForUpdate(ctx, id)
	if err != nil {
		return UAS{}, mapErr(err)
	}
	return uasFromRow(&r), nil
}

// UASByFold implements Tx.
func (t pgTx) UASByFold(ctx context.Context, fold string) ([]UAS, error) {
	rows, err := t.q.UASBySerialFold(ctx, fold)
	if err != nil {
		return nil, err
	}
	return uasList(rows), nil
}

// UpdateUAS implements Tx.
func (t pgTx) UpdateUAS(ctx context.Context, u UAS) (UAS, error) {
	row, err := t.q.UpdateUAS(ctx, gen.UpdateUASParams{
		ID: u.ID, RegistrationMark: optStr(u.RegistrationMark), Manufacturer: u.Manufacturer, Model: u.Model,
		OwnerRef: optStr(u.OwnerRef), ClassLabel: optStr(u.ClassLabel), MtomG: optInt(u.MTOMG), RidCapability: u.RIDCapability,
		RegistryVersion: u.RegistryVersion, UpdatedAt: u.UpdatedAt, UpdatedBy: u.UpdatedBy,
	})
	if err != nil {
		return UAS{}, mapErr(err)
	}
	return uasFromRow(&row), nil
}

// SetUASStatus implements Tx.
func (t pgTx) SetUASStatus(ctx context.Context, u StatusUpdate) (UAS, error) {
	row, err := t.q.SetUASStatus(ctx, gen.SetUASStatusParams{
		ID: u.ID, Status: string(u.Status), StatusReason: u.Reason, RegistryVersion: u.Version, UpdatedAt: u.At, UpdatedBy: u.By,
	})
	if err != nil {
		return UAS{}, mapErr(err)
	}
	return uasFromRow(&row), nil
}

// InsertPilot implements Tx.
func (t pgTx) InsertPilot(ctx context.Context, r PilotRecord) (PilotRecord, error) {
	row, err := t.q.InsertPilot(ctx, gen.InsertPilotParams{
		ID: r.ID, OperatorID: optStr(r.OperatorID), PersonRefHash: r.PersonRefHash, PersonRefLast4: r.PersonRefLast4,
		PiiKeyID: r.KeyID, NameEnc: r.NameSealed, Status: string(r.Status), StatusReason: r.StatusReason,
		RegistryVersion: r.RegistryVersion, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
	})
	return pilotWith(ctx, t.q, row, err)
}

// PilotForUpdate implements Tx.
func (t pgTx) PilotForUpdate(ctx context.Context, id string) (PilotRecord, error) {
	r, err := t.q.PilotForUpdate(ctx, id)
	return pilotWith(ctx, t.q, r, err)
}

// PilotByPersonRef implements Tx.
func (t pgTx) PilotByPersonRef(ctx context.Context, hash string) (PilotRecord, error) {
	r, err := t.q.PilotByPersonRef(ctx, hash)
	return pilotWith(ctx, t.q, r, err)
}

// UpdatePilot implements Tx.
func (t pgTx) UpdatePilot(ctx context.Context, r PilotRecord) (PilotRecord, error) {
	row, err := t.q.UpdatePilot(ctx, gen.UpdatePilotParams{
		ID: r.ID, OperatorID: optStr(r.OperatorID), PiiKeyID: r.KeyID, NameEnc: r.NameSealed,
		RegistryVersion: r.RegistryVersion, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
	})
	return pilotWith(ctx, t.q, row, err)
}

// SetPilotStatus implements Tx.
func (t pgTx) SetPilotStatus(ctx context.Context, u StatusUpdate) (PilotRecord, error) {
	row, err := t.q.SetPilotStatus(ctx, gen.SetPilotStatusParams{
		ID: u.ID, Status: string(u.Status), StatusReason: u.Reason, RegistryVersion: u.Version, UpdatedAt: u.At, UpdatedBy: u.By,
	})
	return pilotWith(ctx, t.q, row, err)
}

// UpsertCompetency implements Tx.
func (t pgTx) UpsertCompetency(ctx context.Context, pilotID string, c Competency) error {
	_, err := t.q.UpsertCompetency(ctx, gen.UpsertCompetencyParams{
		PilotID: pilotID, Competency: c.Competency, CertificateRef: c.CertificateRef, ValidUntil: c.ValidUntil,
		RecordedAt: c.RecordedAt, RecordedBy: c.RecordedBy,
	})
	return mapErr(err)
}

// InsertChange implements Tx.
func (t pgTx) InsertChange(ctx context.Context, c Change) (int64, error) {
	return t.q.InsertStatusChange(ctx, gen.InsertStatusChangeParams{
		EntityType: c.EntityType, EntityID: c.EntityID, PublicKey: c.PublicKey, Status: string(c.Status), At: c.At,
	})
}
