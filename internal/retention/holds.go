package retention

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// EntityHold is the entity type of a hold's events rows.
const EntityHold = "legal_hold"

// Bounds of a hold (the migration's CHECKs, said before the database).
const (
	MaxHoldList    = 64
	MaxCaseRef     = 200
	MaxReason      = 2000
	MaxTrackIDLen  = 256
	MaxSerialLen   = 64
	MaxHoldsListed = 500
)

// SlugHoldReleased is the 409 of a release of a released hold.
const SlugHoldReleased = "hold_released"

var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// HoldInput is a hold to place.
type HoldInput struct {
	CaseRef      string
	Reason       string
	WindowFrom   *time.Time
	WindowTo     *time.Time
	TrackIDs     []string
	Serials      []string
	ViolationIDs []string
}

// Check validates in before any side effect, naming every field at
// fault.
func (in *HoldInput) Check() error {
	var errs []*core.FieldError
	add := func(field, format string, args ...any) { errs = append(errs, core.Fieldf(field, format, args...)) }
	in.CaseRef, in.Reason = strings.TrimSpace(in.CaseRef), strings.TrimSpace(in.Reason)
	if in.CaseRef == "" || len(in.CaseRef) > MaxCaseRef {
		add("case_ref", "1 to %d characters", MaxCaseRef)
	}
	if in.Reason == "" || len(in.Reason) > MaxReason {
		add("reason", "1 to %d characters", MaxReason)
	}
	switch {
	case (in.WindowFrom == nil) != (in.WindowTo == nil):
		add("window_to", "window_from and window_to come together, or neither")
	case in.WindowFrom != nil && !in.WindowTo.After(*in.WindowFrom):
		add("window_to", "must be after window_from")
	}
	for _, l := range []struct {
		field string
		vals  []string
		max   int
		re    *regexp.Regexp
	}{
		{"track_ids", in.TrackIDs, MaxTrackIDLen, nil},
		{"serials", in.Serials, MaxSerialLen, nil},
		{"violation_ids", in.ViolationIDs, 26, ulidPattern},
	} {
		if len(l.vals) > MaxHoldList {
			add(l.field, "at most %d entries", MaxHoldList)
		}
		for i, v := range l.vals {
			switch {
			case strings.TrimSpace(v) == "" || len(v) > l.max:
				add(l.field+"["+strconv.Itoa(i)+"]", "1 to %d characters", l.max)
			case l.re != nil && !l.re.MatchString(v):
				add(l.field+"["+strconv.Itoa(i)+"]", "%q is not a violation id", v)
			}
		}
	}
	if in.WindowFrom == nil && len(in.TrackIDs)+len(in.Serials)+len(in.ViolationIDs) == 0 {
		add("window_from", "a hold names a window, or at least one track, serial or violation")
	}
	if len(errs) > 0 {
		return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "the hold is not valid", errs...)
	}
	in.TrackIDs, in.Serials, in.ViolationIDs = dedupe(in.TrackIDs), dedupe(in.Serials), dedupe(in.ViolationIDs)
	return nil
}

func dedupe(v []string) []string {
	out := make([]string, 0, len(v))
	for _, s := range v {
		if s = strings.TrimSpace(s); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Holds places, releases and lists legal holds.
type Holds struct {
	DB    *pg.DB
	Audit *audit.Writer
	// NewID is the id generator; nil is a ULID of now.
	NewID func(time.Time) string
	// WriteTimeout bounds one hold transaction.
	WriteTimeout time.Duration
	Counters     *core.Counters
}

// Counters of the holds.
const (
	CounterHoldsPlaced   = "legal_holds_placed"
	CounterHoldsReleased = "legal_holds_released"
)

func (h *Holds) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if h.WriteTimeout > 0 {
		return context.WithTimeout(ctx, h.WriteTimeout)
	}
	return context.WithCancel(ctx)
}

func (h *Holds) inc(name string) {
	if h.Counters != nil {
		h.Counters.Inc(name)
	}
}

func holdPayload(r *gen.LegalHold) map[string]any {
	p := map[string]any{"case_ref": r.CaseRef, "reason": r.Reason, "track_ids": r.TrackIds, "serials": r.Serials,
		"violation_ids": r.ViolationIds}
	if r.WindowFrom != nil {
		p["window_from"], p["window_to"] = r.WindowFrom.UTC().Format(time.RFC3339Nano), r.WindowTo.UTC().Format(time.RFC3339Nano)
	}
	return p
}

// Place validates in and records the hold with its events row in one
// transaction. Inserting waits for a deletion batch holding the hold
// gate, so the next batch sees it.
func (h *Holds) Place(ctx context.Context, actor audit.Actor, in HoldInput) (gen.LegalHold, error) {
	if err := in.Check(); err != nil {
		return gen.LegalHold{}, err
	}
	ctx, cancel := h.bounded(ctx)
	defer cancel()
	id := bus.NewULID(time.Now())
	if h.NewID != nil {
		id = h.NewID(time.Now())
	}
	var row gen.LegalHold
	err := h.DB.WithTx(ctx, func(q *gen.Queries) error {
		var err error
		row, err = q.InsertLegalHold(ctx, gen.InsertLegalHoldParams{HoldID: id, CaseRef: in.CaseRef, Reason: in.Reason,
			WindowFrom: in.WindowFrom, WindowTo: in.WindowTo, TrackIds: in.TrackIDs, Serials: in.Serials,
			ViolationIds: in.ViolationIDs, PlacedBy: actor.ID})
		if err != nil {
			return err
		}
		_, err = h.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityHold, EntityID: id,
			EventType: audit.EventLegalHoldPlaced, Payload: holdPayload(&row)})
		return err
	})
	if err != nil {
		return gen.LegalHold{}, err
	}
	h.inc(CounterHoldsPlaced)
	return row, nil
}

// Release releases an active hold with its events row; 404 for no such
// hold, 409 when it is released already.
func (h *Holds) Release(ctx context.Context, actor audit.Actor, holdID, reason string) (gen.LegalHold, error) {
	reason = strings.TrimSpace(reason)
	if !ulidPattern.MatchString(holdID) {
		return gen.LegalHold{}, httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such hold",
			core.Fieldf("hold_id", "%q is not a hold", holdID))
	}
	if reason == "" || len(reason) > MaxReason {
		return gen.LegalHold{}, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "the release is not valid",
			core.Fieldf("reason", "1 to %d characters", MaxReason))
	}
	ctx, cancel := h.bounded(ctx)
	defer cancel()
	var row gen.LegalHold
	err := h.DB.WithTx(ctx, func(q *gen.Queries) error {
		var err error
		row, err = q.ReleaseLegalHold(ctx, gen.ReleaseLegalHoldParams{HoldID: holdID, ReleasedBy: &actor.ID, ReleaseReason: &reason})
		if store.IsNoRows(err) {
			if _, gerr := q.GetLegalHold(ctx, holdID); store.IsNoRows(gerr) {
				return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such hold", core.Fieldf("hold_id", "%q is not a hold", holdID))
			} else if gerr != nil {
				return gerr
			}
			return httpx.Refuse(http.StatusConflict, SlugHoldReleased, "the hold is released already")
		}
		if err != nil {
			return err
		}
		p := holdPayload(&row)
		p["release_reason"] = reason
		_, err = h.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityHold, EntityID: holdID,
			EventType: audit.EventLegalHoldReleased, Payload: p})
		return err
	})
	if err != nil {
		return gen.LegalHold{}, err
	}
	h.inc(CounterHoldsReleased)
	return row, nil
}

// List reads at most limit holds, newest first, and records the read.
func (h *Holds) List(ctx context.Context, actor audit.Actor, includeReleased bool, limit int) ([]gen.LegalHold, bool, error) {
	if limit < 1 || limit > MaxHoldsListed {
		return nil, false, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "limit is out of range",
			core.Fieldf("limit", "1 to %d", MaxHoldsListed))
	}
	var rows []gen.LegalHold
	err := h.DB.WithTx(ctx, func(q *gen.Queries) error {
		var err error
		rows, err = q.ListLegalHolds(ctx, gen.ListLegalHoldsParams{IncludeReleased: includeReleased, MaxRows: int32(limit + 1)})
		if err != nil {
			return err
		}
		_, err = h.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityHold, EventType: audit.EventLegalHoldsViewed,
			Payload: map[string]any{"include_released": includeReleased, "returned": min(len(rows), limit)}})
		return err
	})
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > limit
	if truncated {
		rows = rows[:limit]
	}
	return rows, truncated, nil
}
