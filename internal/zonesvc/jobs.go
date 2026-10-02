package zonesvc

import (
	"context"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Reprojected is what one full re-projection did.
type Reprojected struct {
	// Ran is false when another replica held the job lock.
	Ran  bool
	Rows int
	// ZonesVersion is the newest published version projected.
	ZonesVersion int64
}

// Reproject rewrites the whole zones projection from the relational
// state (G-08): under the job lock (skipping when another replica runs
// it) and LockProjection, held from the relational read to the
// projection commit, so a publication made meanwhile waits and is never
// overwritten by this run's older read. Rows whose period has ended,
// and rows the relational state does not hold (a publication whose
// relational commit failed after its projection commit), are deleted;
// a deleted row is restored.
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
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		version, err := tx.MaxPublishedVersion(ctx)
		if err != nil {
			return err
		}
		vs, err := tx.Projectable(ctx, now)
		if err != nil {
			return err
		}
		if err := s.writeProjection(ctx, vs, now, version); err != nil {
			return err
		}
		out = Reprojected{Ran: true, Rows: len(vs), ZonesVersion: version}
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
	}
	return out, nil
}

// RunJobs re-projects at once, every reprojectEvery and when a
// publication asks for a repair, until ctx ends. A failed run is
// counted, logged and retried after retryMin, doubling up to
// reprojectEvery.
func (s *Service) RunJobs(ctx context.Context, reprojectEvery, retryMin time.Duration) {
	var retry <-chan time.Time
	backoff := retryMin
	reproject := func(cause string) {
		r, err := s.Reproject(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				logging.Error(ctx, s.logger(), "zones re-projection failed; retrying", err, slog.String("cause", cause),
					slog.Float64("retry_in_s", backoff.Seconds()))
			}
			retry = time.After(backoff)
			backoff = min(2*backoff, reprojectEvery)
			return
		case r.Ran:
			s.logger().Info("zones re-projected", slog.String("cause", cause), slog.Int("rows", r.Rows),
				slog.Int64("zones_version", r.ZonesVersion))
		}
		retry, backoff = nil, retryMin
	}
	reproject("startup")
	t := time.NewTicker(reprojectEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			reproject("periodic")
		case <-s.repairs():
			reproject("repair")
		case <-retry:
			s.count(CounterReprojectRetried)
			reproject("retry")
		}
	}
}
