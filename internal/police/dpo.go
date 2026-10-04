package police

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// DPORecords are a month's rows as read, each list at most one above
// the bound.
type DPORecords struct {
	Queries []pggen.PoliceQuery
	Views   []pggen.PIIEventsInRangeRow
}

// ParseMonth reads YYYY-MM as the UTC calendar month [from, to).
func ParseMonth(raw string) (time.Time, time.Time, error) {
	from, err := time.Parse("2006-01", raw)
	if err != nil || len(raw) != 7 {
		return time.Time{}, time.Time{}, core.Fieldf("month", "a UTC calendar month, YYYY-MM")
	}
	return from, from.AddDate(0, 1, 0), nil
}

// dpoViewTypes are the personal-data read types the report lists from
// events: every PII view type of the catalogue but police_query, whose
// rows are the report's police_queries list.
func (s *Service) dpoViewTypes() []string {
	c := s.Catalogue
	if c == nil {
		c = audit.DefaultCatalogue()
	}
	return slices.DeleteFunc(c.PIIViewTypes(), func(t string) bool { return t == audit.EventPoliceQuery })
}

// DPOReport is the month's police queries and personal-data reads for
// the data protection officer; the read is a dpo_report_viewed row.
func (s *Service) DPOReport(ctx context.Context, actor audit.Actor, month string) (gen.DPOReport, error) {
	from, to, err := ParseMonth(month)
	if err != nil {
		return gen.DPOReport{}, err
	}
	limit := s.Limits.DPOMaxRows
	recs, err := s.Ledger.DPO(ctx, from, to, limit, s.dpoViewTypes(), actor)
	if err != nil {
		return gen.DPOReport{}, err
	}
	s.inc(CounterDPOReports)
	out := gen.DPOReport{Month: month, From: from, To: to, PoliceQueries: []gen.DPOPoliceQuery{}, PiiViews: []gen.DPOPIIView{}}
	qs, vs := recs.Queries, recs.Views
	if len(qs) > limit {
		qs, out.Truncated = qs[:limit], true
	}
	if len(vs) > limit {
		vs, out.Truncated = vs[:limit], true
	}
	for i := range qs {
		q := &qs[i]
		var query map[string]any
		if err := json.Unmarshal(q.Query, &query); err != nil {
			return gen.DPOReport{}, fmt.Errorf("police query %s: stored query is not an object: %w", q.ID, err)
		}
		out.PoliceQueries = append(out.PoliceQueries, gen.DPOPoliceQuery{Id: q.ID, At: q.At.UTC(), UserId: q.UserID, Agency: q.Agency,
			Kind: gen.DPOPoliceQueryKind(q.Kind), Purpose: q.Purpose, CaseRef: q.CaseRef, Query: query, ResultCount: int(q.ResultCount),
			Pii: q.Pii, RemoteIp: q.RemoteIp})
		if q.Pii {
			out.Totals.PoliceQueriesWithPii++
		}
	}
	for i := range vs {
		v := &vs[i]
		row := gen.DPOPIIView{EventId: v.ID, Ts: v.Ts.UTC(), EventType: v.EventType, ActorType: v.ActorType, ActorId: v.ActorID,
			Realm: v.Realm, Purpose: v.Purpose, EntityType: v.EntityType, EntityId: v.EntityID}
		var payload map[string]any
		if json.Unmarshal(v.Payload, &payload) == nil {
			for key, dst := range map[string]**string{"case_ref": &row.CaseRef, "agency": &row.Agency, "police_query_id": &row.PoliceQueryId} {
				if str, ok := payload[key].(string); ok && str != "" {
					*dst = &str
				}
			}
		}
		out.PiiViews = append(out.PiiViews, row)
	}
	out.Totals.PoliceQueries, out.Totals.PiiViews = len(out.PoliceQueries), len(out.PiiViews)
	return out, nil
}
