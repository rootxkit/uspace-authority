package registry

import (
	"context"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Reprojected is what one full re-projection did.
type Reprojected struct {
	// Ran is false when another replica held the job lock.
	Ran       bool
	Operators int
	UAS       int
	// Marked counts projection rows the registry does not hold, marked
	// in_registry false or unregistered (never deleted).
	Marked int64
}

// Reproject rewrites the whole projection from the registry (G-08): it
// takes the job lock (skipping when another replica runs it), then
// LockProjection, reads every operator and aircraft, writes them over
// whatever the projection holds, marks the rows the registry does not
// hold, and commits the projection, all while holding LockProjection,
// so a change made meanwhile waits and is never overwritten by this
// run's older read (SC-17 steps 4 and 5). Writing over every row also
// undoes a projection left ahead of the registry by a change whose
// relational commit failed.
func (s *Service) Reproject(ctx context.Context) (Reprojected, error) {
	var out Reprojected
	err := s.Store.InTx(ctx, func(tx Tx) error {
		ok, err := tx.TryLock(ctx, LockReprojectJob)
		if err != nil || !ok {
			return err
		}
		if err := tx.Lock(ctx, LockProjection); err != nil {
			return err
		}
		f, err := tx.Facts(ctx)
		if err != nil {
			return err
		}
		at := s.now()
		ptx, err := s.Projection.Begin(ctx)
		if err != nil {
			return err
		}
		defer ptx.Rollback(ctx)
		if err := ptx.UpsertOperators(ctx, f.Operators, at, true); err != nil {
			return err
		}
		if err := ptx.UpsertUAS(ctx, f.UAS, at, true); err != nil {
			return err
		}
		opIDs := make([]string, 0, len(f.Operators))
		for _, o := range f.Operators {
			opIDs = append(opIDs, o.OperatorID)
		}
		uasIDs := make([]string, 0, len(f.UAS))
		for _, u := range f.UAS {
			uasIDs = append(uasIDs, u.UASID)
		}
		if out.Marked, err = ptx.MarkMissing(ctx, opIDs, uasIDs, at); err != nil {
			return err
		}
		if err := ptx.Commit(ctx); err != nil {
			return err
		}
		out.Ran, out.Operators, out.UAS = true, len(f.Operators), len(f.UAS)
		return nil
	})
	switch {
	case err != nil:
		s.count(CounterReprojectFailed)
		return Reprojected{}, err
	case !out.Ran:
		s.count(CounterReprojectSkipped)
	default:
		s.count(CounterReprojected)
		if s.Counters != nil && out.Marked > 0 {
			s.Counters.Add(CounterProjectionMarked, uint64(out.Marked))
		}
	}
	return out, nil
}

// RunJobs runs the registry's periodic work until ctx ends: a full
// re-projection at once and every reprojectEvery (and at once when a
// change asks for a repair), and the expiry of registrations every
// expiryEvery. A failed run is counted and logged; the next run repairs.
func (s *Service) RunJobs(ctx context.Context, reprojectEvery, expiryEvery time.Duration) {
	reproject := func(cause string) {
		r, err := s.Reproject(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				logging.Error(ctx, s.logger(), "registry re-projection failed; the next run repairs", err, slog.String("cause", cause))
			}
		case r.Ran:
			s.logger().Info("registry re-projected", slog.String("cause", cause), slog.Int("operators", r.Operators),
				slog.Int("uas", r.UAS), slog.Int64("rows_marked", r.Marked))
		}
	}
	expire := func() {
		n, err := s.ExpireDue(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				logging.Error(ctx, s.logger(), "registry expiry failed; the next run retries", err)
			}
		case n > 0:
			s.logger().Info("registrations expired", slog.Int("count", n))
		}
	}
	expire()
	reproject("startup")
	rt := time.NewTicker(reprojectEvery)
	defer rt.Stop()
	et := time.NewTicker(expiryEvery)
	defer et.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rt.C:
			reproject("periodic")
		case <-s.repairs():
			reproject("repair")
		case <-et.C:
			expire()
		}
	}
}
