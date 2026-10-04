package occurrences

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	ostore "github.com/rootxkit/uspace-authority/internal/occurrences/store"
	"github.com/rootxkit/uspace-authority/internal/occurrences/store/gen"
	"github.com/rootxkit/uspace-authority/internal/store"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// PG is the Store on the occurrences pool (the authority_occurrences
// role); events rows are recorded by Audit on the same transaction.
type PG struct {
	DB    *ostore.DB
	Audit *audit.Writer
}

// WithTx implements Store.
func (p PG) WithTx(ctx context.Context, fn func(Tx) error) error {
	return p.DB.WithTx(ctx, func(q *gen.Queries, aq *pggen.Queries) error {
		return fn(pgTx{q: q, aq: aq, w: p.Audit})
	})
}

// Get implements Store.
func (p PG) Get(ctx context.Context, id string) (Report, error) {
	row, err := p.DB.Queries().GetReport(ctx, id)
	if err != nil {
		return Report{}, notFound(err)
	}
	return reportOf(&row)
}

// List implements Store.
func (p PG) List(ctx context.Context, f Filter) ([]Report, error) {
	q := gen.ListReportsParams{State: nonEmpty(f.State), Category: nonEmpty(f.Category), Channel: nonEmpty(f.Channel),
		ReceivedFrom: f.From, ReceivedTo: f.To, CursorReceived: f.CursorReceived, CursorID: nonEmpty(f.CursorID), Lim: int32(f.Limit)}
	rows, err := p.DB.Queries().ListReports(ctx, q)
	if err != nil {
		return nil, err
	}
	return reportsOf(rows)
}

type pgTx struct {
	q  *gen.Queries
	aq *pggen.Queries
	w  *audit.Writer
}

// Now implements Tx.
func (t pgTx) Now(ctx context.Context) (time.Time, error) { return t.q.Now(ctx) }

// Insert implements Tx.
func (t pgTx) Insert(ctx context.Context, r *NewReport) (Report, bool, error) {
	aircraft, err := json.Marshal(r.Aircraft)
	if err != nil {
		return Report{}, false, err
	}
	manned, err := json.Marshal(r.Manned)
	if err != nil {
		return Report{}, false, err
	}
	var sep []byte
	if r.MinSeparation != nil {
		if sep, err = json.Marshal(r.MinSeparation); err != nil {
			return Report{}, false, err
		}
	}
	row, err := t.q.InsertReport(ctx, gen.InsertReportParams{OccurrenceID: r.ID, ReporterOrg: r.ReporterOrg, ReportRef: r.ReportRef,
		Channel: r.Channel, Origin: r.Origin, ReporterPersonEnc: r.PersonSealed, ReporterKeyID: nonEmpty(r.PersonKeyID),
		OccurredAt: r.OccurredAt, BecameAwareAt: r.BecameAwareAt, ReportedAt: r.ReportedAt, ReportDeadlineS: int32(r.DeadlineS),
		Category: r.Category, Aircraft: aircraft, Manned: manned, IntentRefs: r.IntentRefs, MinSeparation: sep,
		Narrative: r.Narrative, EvidenceUrls: r.EvidenceURLs, ContentHash: r.ContentHash})
	if store.IsNoRows(err) {
		return Report{}, false, nil
	}
	if err != nil {
		return Report{}, false, err
	}
	rep, err := reportOf(&row)
	return rep, true, err
}

// ByKey implements Tx.
func (t pgTx) ByKey(ctx context.Context, org, ref string) (Report, error) {
	row, err := t.q.ReportByKey(ctx, gen.ReportByKeyParams{ReporterOrg: org, ReportRef: ref})
	if err != nil {
		return Report{}, notFound(err)
	}
	return reportOf(&row)
}

// Get implements Tx.
func (t pgTx) Get(ctx context.Context, id string) (Report, error) {
	row, err := t.q.GetReport(ctx, id)
	if err != nil {
		return Report{}, notFound(err)
	}
	return reportOf(&row)
}

// GetForUpdate implements Tx.
func (t pgTx) GetForUpdate(ctx context.Context, id string) (Report, error) {
	row, err := t.q.GetReportForUpdate(ctx, id)
	if err != nil {
		return Report{}, notFound(err)
	}
	return reportOf(&row)
}

// Classify implements Tx.
func (t pgTx) Classify(ctx context.Context, id, class, actor string) (Report, error) {
	row, err := t.q.ClassifyReport(ctx, gen.ClassifyReportParams{RiskClassification: &class, Actor: &actor, OccurrenceID: id})
	if err != nil {
		return Report{}, notFound(err)
	}
	return reportOf(&row)
}

// UpdateAnalysis implements Tx.
func (t pgTx) UpdateAnalysis(ctx context.Context, id, analysis, followUp, state, actor string) (Report, error) {
	row, err := t.q.UpdateAnalysis(ctx, gen.UpdateAnalysisParams{Analysis: analysis, FollowUp: followUp, State: state, Actor: &actor,
		OccurrenceID: id})
	if err != nil {
		return Report{}, notFound(err)
	}
	return reportOf(&row)
}

// Received implements Tx.
func (t pgTx) Received(ctx context.Context, from, to time.Time, limit int) ([]Report, error) {
	rows, err := t.q.ReportsReceived(ctx, gen.ReportsReceivedParams{ReceivedFrom: from, ReceivedTo: to, Lim: int32(limit)})
	if err != nil {
		return nil, err
	}
	return reportsOf(rows)
}

// InsertExport implements Tx.
func (t pgTx) InsertExport(ctx context.Context, e *Export) error {
	_, err := t.q.InsertExport(ctx, gen.InsertExportParams{ExportID: e.ID, CreatedAt: e.CreatedAt, CreatedBy: e.CreatedBy, Format: e.Format,
		ContentHash: e.ContentHash, SizeBytes: e.SizeBytes, RecordCount: int32(e.RecordCount), WindowFrom: e.From, WindowTo: e.To})
	return err
}

// Audit implements Tx.
func (t pgTx) Audit(ctx context.Context, ev audit.Event) error {
	_, err := t.w.Record(ctx, t.aq, ev)
	return err
}

func notFound(err error) error {
	if store.IsNoRows(err) {
		return ErrNotFound
	}
	return err
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func reportsOf(rows []gen.OccurrencesOccurrenceReport) ([]Report, error) {
	out := make([]Report, 0, len(rows))
	for i := range rows {
		r, err := reportOf(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func reportOf(row *gen.OccurrencesOccurrenceReport) (Report, error) {
	r := Report{ID: row.OccurrenceID, ReporterOrg: row.ReporterOrg, ReportRef: row.ReportRef, Channel: row.Channel, Origin: row.Origin,
		PersonSealed: row.ReporterPersonEnc, PersonKeyID: str(row.ReporterKeyID), OccurredAt: row.OccurredAt.UTC(),
		BecameAwareAt: row.BecameAwareAt.UTC(), ReceivedAt: row.ReceivedAt.UTC(), DeadlineS: int(row.ReportDeadlineS),
		Within72h: row.Within72h != nil && *row.Within72h, Category: row.Category, IntentRefs: row.IntentRefs, Narrative: row.Narrative,
		EvidenceURLs: row.EvidenceUrls, ContentHash: row.ContentHash, RiskClassification: str(row.RiskClassification),
		ClassifiedAt: utc(row.ClassifiedAt), ClassifiedBy: str(row.ClassifiedBy), Analysis: row.Analysis, FollowUp: row.FollowUp,
		State: row.State, ClosedAt: utc(row.ClosedAt), UpdatedAt: row.UpdatedAt.UTC(), UpdatedBy: str(row.UpdatedBy),
		ReportedAt: utc(row.ReportedAt), Aircraft: []Aircraft{}, Manned: []Manned{}}
	if err := json.Unmarshal(row.Aircraft, &r.Aircraft); err != nil {
		return Report{}, fmt.Errorf("occurrence %s: aircraft: %w", row.OccurrenceID, err)
	}
	if err := json.Unmarshal(row.Manned, &r.Manned); err != nil {
		return Report{}, fmt.Errorf("occurrence %s: manned: %w", row.OccurrenceID, err)
	}
	if len(row.MinSeparation) > 0 {
		r.MinSeparation = &Separation{}
		if err := json.Unmarshal(row.MinSeparation, r.MinSeparation); err != nil {
			return Report{}, fmt.Errorf("occurrence %s: min_separation: %w", row.OccurrenceID, err)
		}
	}
	if r.IntentRefs == nil {
		r.IntentRefs = []string{}
	}
	if r.EvidenceURLs == nil {
		r.EvidenceURLs = []string{}
	}
	return r, nil
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
