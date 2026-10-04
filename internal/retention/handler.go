package retention

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Handler serves /v1/retention/* (apiserver.RetentionHandler).
type Handler struct {
	Holds   *Holds
	Service *Service
}

var _ apiserver.RetentionHandler = Handler{}

func holdOut(r *pggen.LegalHold) gen.LegalHold {
	out := gen.LegalHold{HoldId: r.HoldID, CaseRef: r.CaseRef, Reason: r.Reason, WindowFrom: utcPtr(r.WindowFrom), WindowTo: utcPtr(r.WindowTo),
		TrackIds: nonNil(r.TrackIds), Serials: nonNil(r.Serials), ViolationIds: nonNil(r.ViolationIds), PlacedBy: r.PlacedBy,
		PlacedAt: r.PlacedAt.UTC(), Active: r.ReleasedAt == nil, ReleasedBy: r.ReleasedBy, ReleasedAt: utcPtr(r.ReleasedAt),
		ReleaseReason: r.ReleaseReason}
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func derefList(p *[]string) []string {
	if p == nil {
		return nil
	}
	return *p
}

// PlaceLegalHold places a hold.
func (h Handler) PlaceLegalHold(ctx context.Context, req gen.PlaceLegalHoldRequestObject) (gen.PlaceLegalHoldResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		b = &gen.LegalHoldInput{}
	}
	row, err := h.Holds.Place(ctx, actor, HoldInput{CaseRef: b.CaseRef, Reason: b.Reason, WindowFrom: b.WindowFrom, WindowTo: b.WindowTo,
		TrackIDs: derefList(b.TrackIds), Serials: derefList(b.Serials), ViolationIDs: derefList(b.ViolationIds)})
	if err != nil {
		return nil, err
	}
	return gen.PlaceLegalHold201JSONResponse(holdOut(&row)), nil
}

// ReleaseLegalHold releases a hold.
func (h Handler) ReleaseLegalHold(ctx context.Context, req gen.ReleaseLegalHoldRequestObject) (gen.ReleaseLegalHoldResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	reason := ""
	if req.Body != nil {
		reason = req.Body.Reason
	}
	row, err := h.Holds.Release(ctx, actor, req.HoldId, reason)
	if err != nil {
		return nil, err
	}
	return gen.ReleaseLegalHold200JSONResponse(holdOut(&row)), nil
}

// ListLegalHolds lists holds.
func (h Handler) ListLegalHolds(ctx context.Context, req gen.ListLegalHoldsRequestObject) (gen.ListLegalHoldsResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	include, limit := false, 100
	if req.Params.IncludeReleased != nil {
		include = *req.Params.IncludeReleased
	}
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	rows, truncated, err := h.Holds.List(ctx, actor, include, limit)
	if err != nil {
		return nil, err
	}
	out := gen.ListLegalHolds200JSONResponse{Holds: make([]gen.LegalHold, 0, len(rows)), Truncated: truncated}
	for i := range rows {
		out.Holds = append(out.Holds, holdOut(&rows[i]))
	}
	return out, nil
}

// Status is what GET /v1/retention/status answers.
type Status = gen.RetentionStatus

// GetRetentionStatus reads the status from the ledgers and records the
// read.
func (h Handler) GetRetentionStatus(ctx context.Context, _ gen.GetRetentionStatusRequestObject) (gen.GetRetentionStatusResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	st, err := h.Service.Status(ctx)
	if err != nil {
		return nil, err
	}
	err = h.Service.DB.WithTx(ctx, func(q *pggen.Queries) error {
		_, err := h.Service.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: "retention", EventType: audit.EventRetentionStatusViewed,
			Payload: map[string]any{"jobs": len(st.Jobs), "active_holds": st.ActiveHolds}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return gen.GetRetentionStatus200JSONResponse(st), nil
}

// Status reads the periods, the job ledger, the archive ledger, the
// active holds, the broken months and the missing USSP days.
func (s *Service) Status(ctx context.Context) (gen.RetentionStatus, error) {
	q := s.DB.Queries()
	store := ""
	if s.Store != nil {
		store = s.Store.Describe()
	}
	st := gen.RetentionStatus{
		Periods: gen.RetentionPeriods{OnlineDays: s.Periods.OnlineDays, ArchiveYears: s.Periods.ArchiveYears,
			ViolationsYears: s.Periods.ViolationsYears, AuditYears: s.Periods.AuditYears,
			Incidents: gen.RetentionPeriodsIncidents(s.Periods.Incidents), PendingGcaa: PendingGCAA, ArchiveStore: store},
		Jobs: []gen.RetentionJobRun{}, AuditBrokenMonths: []string{}, UsspMissingDays: []string{},
	}
	runs, err := q.LatestJobRuns(ctx)
	if err != nil {
		return st, fmt.Errorf("retention status: jobs: %w", err)
	}
	for _, r := range runs {
		jr := gen.RetentionJobRun{Job: r.Job, RunId: r.RunID, StartedAt: r.StartedAt.UTC(), FinishedAt: utcPtr(r.FinishedAt)}
		if r.Outcome != nil {
			o := gen.RetentionJobRunOutcome(*r.Outcome)
			jr.Outcome = &o
		}
		var sum map[string]any
		if json.Unmarshal(r.Summary, &sum) == nil {
			jr.Summary = &sum
		}
		st.Jobs = append(st.Jobs, jr)
	}
	if st.ActiveHolds, err = q.CountActiveLegalHolds(ctx); err != nil {
		return st, fmt.Errorf("retention status: holds: %w", err)
	}
	if s.TS != nil {
		c, err := s.TS.Counts(ctx)
		if err != nil {
			return st, fmt.Errorf("retention status: archive: %w", err)
		}
		st.Archive = gen.RetentionArchiveCounts{Exporting: c.Exporting, Archived: c.Archived, Dropped: c.Dropped, ObjectsDeleted: c.ObjectsDeleted}
	}
	ver, err := q.LatestChainVerifications(ctx, 1000)
	if err != nil {
		return st, fmt.Errorf("retention status: chain: %w", err)
	}
	for _, v := range ver {
		if !v.Intact {
			st.AuditBrokenMonths = append(st.AuditBrokenMonths, v.Month)
		}
	}
	slices.Sort(st.AuditBrokenMonths)
	days, err := q.MissingUSSPDays(ctx, 1000)
	if err != nil {
		return st, fmt.Errorf("retention status: USSP days: %w", err)
	}
	for i := range days {
		st.UsspMissingDays = append(st.UsspMissingDays, days[i].UsspCode+"/"+days[i].Day.UTC().Format(time.DateOnly))
	}
	return st, nil
}
