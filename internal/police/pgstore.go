package police

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// EntityType is the events entity of a police query.
const EntityType = "police_query"

// PG is the Ledger on the relational database, as the application role.
type PG struct {
	DB    *pg.DB
	Audit *audit.Writer
}

var _ Ledger = PG{}

func agencyLock(agency string) int64 { return pg.LockKey("police_budget:" + agency) }

// Record implements Ledger. The agency's advisory lock serialises the
// budget check and the insert across every replica, and the window is
// the database clock's, so neither a restart nor a second replica
// changes a budget.
func (p PG) Record(ctx context.Context, e Entry, b Budget) (time.Time, error) {
	q, err := json.Marshal(e.Query)
	if err != nil {
		return time.Time{}, fmt.Errorf("police query: %w", err)
	}
	if len(q) > MaxQueryBytes {
		return time.Time{}, fmt.Errorf("police query: %d bytes, at most %d", len(q), MaxQueryBytes)
	}
	var at time.Time
	err = p.DB.WithTx(ctx, func(tx *gen.Queries) error {
		if err := tx.AdvisoryXactLock(ctx, agencyLock(e.Caller.Agency)); err != nil {
			return err
		}
		used, err := tx.PoliceBudget(ctx, gen.PoliceBudgetParams{UserID: e.Caller.UserID, Agency: e.Caller.Agency, WindowS: b.Window.Seconds()})
		if err != nil {
			return err
		}
		if err := spentOf(used, b); err != nil {
			return err
		}
		if at, err = tx.InsertPoliceQuery(ctx, gen.InsertPoliceQueryParams{ID: e.ID, UserID: e.Caller.UserID, Agency: e.Caller.Agency,
			SessionJti: e.Caller.JTI, Kind: e.Kind, Purpose: e.Purpose, CaseRef: e.CaseRef, Query: q, ResultCount: int32(e.ResultCount),
			Pii: e.PII, RemoteIp: e.Caller.RemoteIP}); err != nil {
			return err
		}
		_, err = p.Audit.Record(ctx, tx, audit.Event{Actor: e.Caller.Actor, Purpose: e.Purpose, EntityType: EntityType, EntityID: e.ID,
			EventType: audit.EventPoliceQuery, Payload: map[string]any{
				"kind": e.Kind, "case_ref": e.CaseRef, "agency": e.Caller.Agency, "query": e.Query, "result_count": e.ResultCount,
				"pii": e.PII, "remote_ip": e.Caller.RemoteIP, "session": e.Caller.JTI,
			}})
		return err
	})
	return at, err
}

// CheckBudget implements Ledger: the budget query of Record, outside a
// transaction and without the lock.
func (p PG) CheckBudget(ctx context.Context, c Caller, b Budget) error {
	used, err := p.DB.Queries().PoliceBudget(ctx, gen.PoliceBudgetParams{UserID: c.UserID, Agency: c.Agency, WindowS: b.Window.Seconds()})
	if err != nil {
		return err
	}
	return spentOf(used, b)
}

// spentOf is the spent budget of used, or nil.
func spentOf(used gen.PoliceBudgetRow, b Budget) error {
	switch {
	case used.UserN >= int64(b.User):
		return &BudgetSpentError{Scope: "user", RetryAfter: frees(used.UserFreesInS)}
	case used.AgencyN >= int64(b.Agency):
		return &BudgetSpentError{Scope: "agency", RetryAfter: frees(used.AgencyFreesInS)}
	}
	return nil
}

// frees is a Retry-After: at least a second.
func frees(s float64) time.Duration {
	return time.Duration(math.Max(1, math.Ceil(s))) * time.Second
}

// Refused implements Ledger.
func (p PG) Refused(ctx context.Context, actor audit.Actor, reason string, payload map[string]any) error {
	payload["reason"] = reason
	return p.DB.WithTx(ctx, func(tx *gen.Queries) error {
		_, err := p.Audit.Record(ctx, tx, audit.Event{Actor: actor, EntityType: EntityType, EntityID: actor.ID,
			EventType: audit.EventPoliceQueryRefused, Payload: payload})
		return err
	})
}

// InsertExport implements Ledger.
func (p PG) InsertExport(ctx context.Context, x Export) error {
	return p.DB.Queries().InsertPoliceExport(ctx, gen.InsertPoliceExportParams{PackID: x.PackID, IncidentID: x.IncidentID,
		QueryID: x.QueryID, Agency: x.Agency, UserID: x.UserID})
}

// ExportByPack implements Ledger.
func (p PG) ExportByPack(ctx context.Context, packID string) (Export, bool, error) {
	r, err := p.DB.Queries().PoliceExportByPack(ctx, packID)
	if store.IsNoRows(err) {
		return Export{}, false, nil
	}
	if err != nil {
		return Export{}, false, err
	}
	return Export{PackID: r.PackID, IncidentID: r.IncidentID, QueryID: r.QueryID, Agency: r.Agency, UserID: r.UserID, CreatedAt: r.CreatedAt}, true, nil
}

// DPO implements Ledger: both lists read and the view recorded in one
// transaction, so the report and its dpo_report_viewed row commit
// together.
func (p PG) DPO(ctx context.Context, from, to time.Time, rows int, piiTypes []string, actor audit.Actor) (DPORecords, error) {
	var out DPORecords
	err := p.DB.WithTx(ctx, func(tx *gen.Queries) error {
		var err error
		if out.Queries, err = tx.PoliceQueriesInRange(ctx, gen.PoliceQueriesInRangeParams{FromTs: from, ToTs: to, RowLimit: int32(rows + 1)}); err != nil {
			return err
		}
		if out.Views, err = tx.PIIEventsInRange(ctx, gen.PIIEventsInRangeParams{FromTs: from, ToTs: to, EventTypes: piiTypes,
			RowLimit: int32(rows + 1)}); err != nil {
			return err
		}
		_, err = p.Audit.Record(ctx, tx, audit.Event{Actor: actor, EntityType: "events", EventType: audit.EventDPOReportViewed,
			Payload: map[string]any{"month": from.Format("2006-01"), "police_queries": min(len(out.Queries), rows),
				"pii_views": min(len(out.Views), rows), "truncated": len(out.Queries) > rows || len(out.Views) > rows}})
		return err
	})
	return out, err
}
