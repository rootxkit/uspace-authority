package zonesvc

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

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// row is the shape every version query returns (each generated row type
// converts to it).
type row = gen.ZoneVersionRow

func versionOf(r *row) Version {
	return Version{
		ID: r.ID, Dataset: Dataset(r.Dataset), Identifier: r.Identifier, ZoneVersion: int(r.ZoneVersion),
		State: State(r.State), Type: r.Type, Country: r.Country, Feature: json.RawMessage(r.Feature),
		ValidFrom: r.ValidFrom, ValidTo: r.ValidTo, WGS84Fields: r.Wgs84Fields, PublishedVersion: r.PublishedVersion,
		PublishedAt: r.PublishedAt, PublishedBy: str(r.PublishedBy), CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
		ApprovedAt: r.ApprovedAt, ApprovedBy: str(r.ApprovedBy),
	}
}

// withDesignations attaches the designation of every U-space version.
func withDesignations(ctx context.Context, q *gen.Queries, vs []Version) ([]Version, error) {
	var ids []int64
	for i := range vs {
		if vs[i].Dataset == DatasetUSpace {
			ids = append(ids, vs[i].ID)
		}
	}
	if len(ids) == 0 {
		return vs, nil
	}
	rows, err := q.USpaceDesignations(ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := make(map[int64]*Designation, len(rows))
	for i := range rows {
		r := &rows[i]
		byID[r.GeoZoneID] = &Designation{
			Name: r.Name, ServicesRequired: r.ServicesRequired, UASRequirements: r.UasRequirements,
			ServicePerformance: r.ServicePerformance, OperationalConditions: r.OperationalConditions,
			AirspaceConstraints: r.AirspaceConstraints, AdjacentIDs: r.AdjacentIds, RiskAssessmentRef: str(r.RiskAssessmentRef),
			InControlledAirspace: r.InControlledAirspace, ATSProviderID: str(r.AtsProviderID), CISPID: str(r.CispID),
			DesignationRef: str(r.DesignationRef), AIPRef: str(r.AipRef),
		}
	}
	for i := range vs {
		vs[i].Designation = byID[vs[i].ID]
	}
	return vs, nil
}

func one(ctx context.Context, q *gen.Queries, r row, err error) (Version, error) {
	if err != nil {
		return Version{}, mapErr(err)
	}
	vs, err := withDesignations(ctx, q, []Version{versionOf(&r)})
	if err != nil {
		return Version{}, err
	}
	return vs[0], nil
}

func many[T any](ctx context.Context, q *gen.Queries, rows []T, conv func(*T) row) ([]Version, error) {
	out := make([]Version, 0, len(rows))
	for i := range rows {
		r := conv(&rows[i])
		out = append(out, versionOf(&r))
	}
	return withDesignations(ctx, q, out)
}

// Now implements Store.
func (p PG) Now(ctx context.Context) (time.Time, error) { return p.DB.Queries().DBNow(ctx) }

// Latest implements Store.
func (p PG) Latest(ctx context.Context, identifier string) (Version, error) {
	q := p.DB.Queries()
	r, err := q.LatestZoneVersion(ctx, identifier)
	return one(ctx, q, row(r), err)
}

// Version implements Store.
func (p PG) Version(ctx context.Context, identifier string, zoneVersion int) (Version, error) {
	q := p.DB.Queries()
	r, err := q.ZoneVersion(ctx, gen.ZoneVersionParams{Identifier: identifier, ZoneVersion: int32(zoneVersion)})
	return one(ctx, q, r, err)
}

// Versions implements Store.
func (p PG) Versions(ctx context.Context, identifier string, before, limit int) ([]Version, error) {
	q := p.DB.Queries()
	rows, err := q.ZoneVersions(ctx, gen.ZoneVersionsParams{Identifier: identifier, BeforeVersion: int32(before), PageSize: int32(limit)})
	if err != nil {
		return nil, err
	}
	return many(ctx, q, rows, func(r *gen.ZoneVersionsRow) row { return row(*r) })
}

// List implements Store.
func (p PG) List(ctx context.Context, f ListFilter) ([]Version, error) {
	q := p.DB.Queries()
	var st *string
	if f.State != "" {
		s := string(f.State)
		st = &s
	}
	rows, err := q.ListLatestZoneVersions(ctx, gen.ListLatestZoneVersionsParams{
		Dataset: string(f.Dataset), AfterIdentifier: f.After, State: st, PageSize: int32(f.Limit),
	})
	if err != nil {
		return nil, err
	}
	return many(ctx, q, rows, func(r *gen.ListLatestZoneVersionsRow) row { return row(*r) })
}

// InForce implements Store.
func (p PG) InForce(ctx context.Context, ds Dataset, at time.Time) ([]Version, error) {
	return inForce(ctx, p.DB.Queries(), ds, at)
}

func inForce(ctx context.Context, q *gen.Queries, ds Dataset, at time.Time) ([]Version, error) {
	rows, err := q.ZonesInForce(ctx, gen.ZonesInForceParams{Dataset: string(ds), At: at})
	if err != nil {
		return nil, err
	}
	return many(ctx, q, rows, func(r *gen.ZonesInForceRow) row { return row(*r) })
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

// Now implements Tx.
func (t pgTx) Now(ctx context.Context) (time.Time, error) { return t.q.DBNow(ctx) }

// NextZonesVersion implements Tx.
func (t pgTx) NextZonesVersion(ctx context.Context) (int64, error) { return t.q.NextZonesVersion(ctx) }

// LatestForUpdate implements Tx.
func (t pgTx) LatestForUpdate(ctx context.Context, identifier string) (Version, error) {
	r, err := t.q.LatestZoneVersionForUpdate(ctx, identifier)
	return one(ctx, t.q, row(r), err)
}

func int32Ptr(i *int) *int32 {
	if i == nil {
		return nil
	}
	v := int32(*i)
	return &v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Insert implements Tx.
func (t pgTx) Insert(ctx context.Context, d *Draft, zoneVersion int, by string) (Version, error) {
	c := &d.Columns
	r, err := t.q.InsertZoneVersion(ctx, gen.InsertZoneVersionParams{
		Dataset: string(d.Dataset), Identifier: d.Identifier, ZoneVersion: int32(zoneVersion), Country: c.Country,
		Name: c.Name, Type: c.Type, Variant: c.Variant, Reason: nonNil(c.Reason), OtherReasonInfo: c.OtherReasonInfo,
		RestrictionConditions: c.RestrictionConditions, Region: int32Ptr(c.Region), RegulationExemption: c.RegulationExemption,
		Message: c.Message, GeometryType: c.GeometryType, GeometryGeojson: c.GeometryGeoJSON, CenterLonDeg: c.CenterLonDeg,
		CenterLatDeg: c.CenterLatDeg, RadiusM: c.RadiusM, LowerM: c.LowerM, LowerRef: c.LowerRef, UpperM: c.UpperM,
		UpperRef: c.UpperRef, Layers: c.Layers, Ed318Extra: c.ED318Extra, Wgs84Fields: nonNil(c.WGS84Fields),
		LimitedApplicability: c.Limited, ZoneAuthority: c.ZoneAuthority, DataSource: c.DataSource,
		ExtendedProperties: c.Extended, Feature: d.Feature, ValidFrom: d.ValidFrom, ValidTo: d.ValidTo, CreatedBy: by,
	})
	if err != nil {
		return Version{}, mapErr(err)
	}
	v := versionOf((*row)(&r))
	if des := d.Designation; des != nil {
		err := t.q.InsertUSpaceDesignation(ctx, gen.InsertUSpaceDesignationParams{
			GeoZoneID: r.ID, Identifier: d.Identifier, ZoneVersion: int32(zoneVersion), Name: des.Name,
			ServicesRequired: nonNil(des.ServicesRequired), UasRequirements: des.UASRequirements,
			ServicePerformance: des.ServicePerformance, OperationalConditions: des.OperationalConditions,
			AirspaceConstraints: des.AirspaceConstraints, AdjacentIds: nonNil(des.AdjacentIDs),
			RiskAssessmentRef: optional(des.RiskAssessmentRef), InControlledAirspace: des.InControlledAirspace,
			AtsProviderID: optional(des.ATSProviderID), CispID: optional(des.CISPID), DesignatedFrom: d.ValidFrom,
			DesignatedTo: d.ValidTo, DesignationRef: optional(des.DesignationRef), AipRef: optional(des.AIPRef),
		})
		if err != nil {
			return Version{}, mapErr(err)
		}
		v.Designation = des
	}
	return v, nil
}

// SupersedeUnpublished implements Tx.
func (t pgTx) SupersedeUnpublished(ctx context.Context, identifier string) error {
	_, err := t.q.SupersedeUnpublished(ctx, identifier)
	return err
}

// Approve implements Tx.
func (t pgTx) Approve(ctx context.Context, identifier string, zoneVersion int, by string) (Version, error) {
	r, err := t.q.ApproveZoneVersion(ctx, gen.ApproveZoneVersionParams{ApprovedBy: &by, Identifier: identifier, ZoneVersion: int32(zoneVersion)})
	return one(ctx, t.q, row(r), err)
}

// PublishApproved implements Tx.
func (t pgTx) PublishApproved(ctx context.Context, ds Dataset, version int64, by string) ([]Version, error) {
	rows, err := t.q.PublishApproved(ctx, gen.PublishApprovedParams{Version: &version, PublishedBy: &by, Dataset: string(ds)})
	if err != nil {
		return nil, err
	}
	return many(ctx, t.q, rows, func(r *gen.PublishApprovedRow) row { return row(*r) })
}

// SupersedeOlderPublished implements Tx.
func (t pgTx) SupersedeOlderPublished(ctx context.Context, identifier string, zoneVersion int) error {
	_, err := t.q.SupersedeOlderPublished(ctx, gen.SupersedeOlderPublishedParams{Identifier: identifier, ZoneVersion: int32(zoneVersion)})
	return err
}

// InForce implements Tx.
func (t pgTx) InForce(ctx context.Context, ds Dataset, at time.Time) ([]Version, error) {
	return inForce(ctx, t.q, ds, at)
}

// Projectable implements Tx.
func (t pgTx) Projectable(ctx context.Context, at time.Time) ([]Version, error) {
	rows, err := t.q.ZonesProjectable(ctx, at)
	if err != nil {
		return nil, err
	}
	return many(ctx, t.q, rows, func(r *gen.ZonesProjectableRow) row { return row(*r) })
}

// MaxPublishedVersion implements Tx.
func (t pgTx) MaxPublishedVersion(ctx context.Context) (int64, error) {
	return t.q.MaxPublishedZonesVersion(ctx)
}

// EnqueuePublication implements Tx.
func (t pgTx) EnqueuePublication(ctx context.Context, p PublicationInput) (Publication, error) {
	if _, err := t.q.SupersedePendingPublications(ctx, string(p.Dataset)); err != nil {
		return Publication{}, err
	}
	r, err := t.q.InsertPublication(ctx, gen.InsertPublicationParams{
		Dataset: string(p.Dataset), Version: p.Version, Payload: p.Payload, PayloadHash: p.PayloadHash,
		FeatureCount: int32(p.FeatureCount), CreatedBy: p.By,
	})
	if err != nil {
		return Publication{}, mapErr(err)
	}
	return Publication{
		ID: r.ID, Dataset: Dataset(r.Dataset), Version: r.Version, PayloadHash: r.PayloadHash,
		FeatureCount: int(r.FeatureCount), Signature: r.Signature, State: r.State, CreatedAt: r.CreatedAt,
	}, nil
}
