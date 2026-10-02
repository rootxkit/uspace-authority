package assign

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Event and entity of a change (internal/audit catalogue).
const (
	EventChanged = audit.EventCellOwnershipChanged
	entityType   = "cells"
)

// Problem slugs and counters.
const (
	SlugStoreUnavailable   = "cell_store_unavailable"
	CounterStoreRefused    = "cell_store_write_refused"
	CounterOwnershipChange = "cell_ownership_changed"
)

// Service writes the map (api only).
type Service struct {
	DB       *pgstore.DB
	Audit    *audit.Writer
	Store    cell.Store
	Counters *core.Counters
	Logger   *slog.Logger
	Now      func() time.Time
}

// New returns a Service with its own counters.
func New(db *pgstore.DB, w *audit.Writer, store cell.Store, logger *slog.Logger) *Service {
	return &Service{DB: db, Audit: w, Store: store, Counters: &core.Counters{}, Logger: logger}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) unavailable(err error) error {
	s.Counters.Inc(CounterStoreRefused)
	logger := s.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	logging.Error(context.Background(), logger, "cell ownership map not written; change refused", err)
	return httpx.Refuse(http.StatusServiceUnavailable, SlugStoreUnavailable,
		"the ownership map cannot be written now; nothing was changed, retry later")
}

// Get reads the map; 404 when none was written.
func (s *Service) Get(ctx context.Context) (cell.Ownership, error) {
	o, _, have, err := s.Store.Get(ctx)
	if err != nil {
		return cell.Ownership{}, s.unavailable(err)
	}
	if !have {
		return cell.Ownership{}, httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no ownership map has been written yet")
	}
	return o, nil
}

// Put replaces the map with assignments: in one transaction under the
// advisory lock cell_ownership, the events row and then the KV write of
// the next version, compared against the revision read (no lost
// update). A KV failure rolls the row back (503).
func (s *Service) Put(ctx context.Context, actor audit.Actor, assignments map[string]string, reason string) (cell.Ownership, error) {
	if reason == "" || len(reason) > 500 {
		return cell.Ownership{}, core.Fieldf("reason", "1 to 500 characters")
	}
	if assignments == nil {
		assignments = map[string]string{}
	}
	if err := cell.ValidateAssignments(assignments); err != nil {
		return cell.Ownership{}, err
	}
	var out cell.Ownership
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, pgstore.LockKey("cell_ownership")); err != nil {
			return err
		}
		cur, rev, _, err := s.Store.Get(ctx)
		if err != nil {
			return s.unavailable(err)
		}
		out = cell.Ownership{Version: cur.Version + 1, Assignments: assignments, UpdatedBy: actor.ID, UpdatedAt: s.now()}
		if _, err := s.Store.Encode(out); err != nil {
			return core.Fieldf("assignments", "%v", err)
		}
		if _, err := s.Audit.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: entityType, EntityID: cell.OwnershipKey, EventType: EventChanged,
			Payload: map[string]any{"from_version": cur.Version, "to_version": out.Version, "reason": reason, "assignments": assignments},
		}); err != nil {
			return err
		}
		if err := s.Store.Put(ctx, out, rev); err != nil {
			if errors.Is(err, cell.ErrTooLarge) {
				return core.Fieldf("assignments", "%v", err)
			}
			return s.unavailable(err)
		}
		return nil
	})
	if err != nil {
		return cell.Ownership{}, err
	}
	s.Counters.Inc(CounterOwnershipChange)
	return out, nil
}

// Handler serves /v1/cells.
type Handler struct{ Service *Service }

func out(o cell.Ownership) gen.CellOwnership {
	return gen.CellOwnership{Version: int64(o.Version), Assignments: o.Assignments, UpdatedBy: o.UpdatedBy, UpdatedAt: o.UpdatedAt}
}

// GetCellOwnership answers the map.
func (h Handler) GetCellOwnership(ctx context.Context, _ gen.GetCellOwnershipRequestObject) (gen.GetCellOwnershipResponseObject, error) {
	o, err := h.Service.Get(ctx)
	if err != nil {
		return nil, err
	}
	return gen.GetCellOwnership200JSONResponse(out(o)), nil
}

// PutCellOwnership replaces the map.
func (h Handler) PutCellOwnership(ctx context.Context, req gen.PutCellOwnershipRequestObject) (gen.PutCellOwnershipResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	o, err := h.Service.Put(ctx, actor, req.Body.Assignments, req.Body.Reason)
	if err != nil {
		return nil, err
	}
	return gen.PutCellOwnership200JSONResponse(out(o)), nil
}
