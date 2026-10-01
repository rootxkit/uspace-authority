package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Page sizes of Query.
const (
	DefaultQueryLimit = 100
	MaxQueryLimit     = 500
)

// Filter selects events for Query; every field is optional.
type Filter struct {
	EntityType, EntityID, ActorID, EventType string
	From, To                                 time.Time // [From, To)
	BeforeID                                 int64     // exclusive; 0 starts at the newest
	Limit                                    int       // 0 is DefaultQueryLimit
}

// Page is one page of Query, newest first.
type Page struct {
	Events []Row
	// NextBeforeID is the BeforeID of the next page; 0 on the last.
	NextBeforeID int64
}

// Query reads one page of the log with q (inside a transaction when the
// read is itself recorded).
func Query(ctx context.Context, q *gen.Queries, f Filter) (Page, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultQueryLimit
	}
	if limit < 1 || limit > MaxQueryLimit {
		return Page{}, core.Fieldf("limit", "must be between 1 and %d", MaxQueryLimit)
	}
	if !f.From.IsZero() && !f.To.IsZero() && !f.From.Before(f.To) {
		return Page{}, core.Fieldf("to", "must be after from")
	}
	p := gen.QueryEventsParams{
		EntityType: optional(f.EntityType), EntityID: optional(f.EntityID),
		ActorID: optional(f.ActorID), EventType: optional(f.EventType),
		PageSize: int32(limit + 1),
	}
	if !f.From.IsZero() {
		p.FromTs = &f.From
	}
	if !f.To.IsZero() {
		p.ToTs = &f.To
	}
	if f.BeforeID > 0 {
		p.BeforeID = &f.BeforeID
	}
	rows, err := q.QueryEvents(ctx, p)
	if err != nil {
		return Page{}, fmt.Errorf("audit query: %w", err)
	}
	out := Page{Events: make([]Row, 0, min(len(rows), limit))}
	for i := range rows {
		if i == limit {
			out.NextBeforeID = out.Events[limit-1].ID
			break
		}
		out.Events = append(out.Events, rowFrom(&rows[i]))
	}
	return out, nil
}
