package retention

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// maxIncidentAircraft bounds the incident aircraft one check reads; past
// it everything checked is held (fail closed, counted).
const maxIncidentAircraft = 10000

// heldSet is what holds a time range: everything (All names why), or
// the rows of the listed aircraft.
type heldSet struct {
	All      string
	TrackIDs []string
	Serials  []string
	// Why names the holds and incidents that contributed aircraft.
	Why []string
}

func (h *heldSet) addTracks(why string, ids ...string) {
	added := false
	for _, id := range ids {
		if id != "" && !slices.Contains(h.TrackIDs, id) {
			h.TrackIDs = append(h.TrackIDs, id)
			added = true
		}
	}
	if added && !slices.Contains(h.Why, why) {
		h.Why = append(h.Why, why)
	}
}

func (h *heldSet) addSerials(why string, serials ...string) {
	added := false
	for _, s := range serials {
		if s != "" && !slices.Contains(h.Serials, s) {
			h.Serials = append(h.Serials, s)
			added = true
		}
	}
	if added && !slices.Contains(h.Why, why) {
		h.Why = append(h.Why, why)
	}
}

// matches reports whether an aircraft named by any of tracks or serials
// is held.
func (h *heldSet) matches(tracks, serials []string) bool {
	for _, t := range tracks {
		if slices.Contains(h.TrackIDs, t) {
			return true
		}
	}
	for _, s := range serials {
		if slices.Contains(h.Serials, s) {
			return true
		}
	}
	return false
}

func overlaps(aFrom, aTo, bFrom, bTo time.Time) bool { return aFrom.Before(bTo) && bFrom.Before(aTo) }

func (s *Service) maxHolds() int {
	if s.MaxHolds > 0 {
		return s.MaxHolds
	}
	return 1000
}

// holdsOver gathers what holds [from, to): the active legal holds, the
// violations they name (with their aircraft around them), and the open
// incidents' aircraft around when they occurred. Read inside the
// caller's transaction q, which holds the hold gate when it deletes.
func (s *Service) holdsOver(ctx context.Context, q *gen.Queries, from, to time.Time) (heldSet, error) {
	var h heldSet
	limit := s.maxHolds()
	holds, err := q.ActiveLegalHolds(ctx, int32(limit+1))
	if err != nil {
		return h, fmt.Errorf("holds: %w", err)
	}
	if len(holds) > limit {
		s.inc(CounterHoldsBound)
		h.All = fmt.Sprintf("more than %d active legal holds (RETENTION_MAX_HOLDS): everything is held", limit)
		return h, nil
	}
	margin := s.IncidentMargin
	for i := range holds {
		hd := &holds[i]
		why := "legal hold " + hd.HoldID + " (" + hd.CaseRef + ")"
		if hd.WindowFrom != nil {
			if !overlaps(*hd.WindowFrom, *hd.WindowTo, from, to) {
				continue
			}
			if len(hd.TrackIds)+len(hd.Serials)+len(hd.ViolationIds) == 0 {
				h.All = why + " covers the whole window"
				return h, nil
			}
		}
		h.addTracks(why, hd.TrackIds...)
		h.addSerials(why, hd.Serials...)
	}
	refs, err := q.HeldViolationRefs(ctx, int32(limit*MaxHoldList+1))
	if err != nil {
		return h, fmt.Errorf("held violations: %w", err)
	}
	if len(refs) > limit*MaxHoldList {
		s.inc(CounterHoldsBound)
		h.All = "more held violations than a check reads: everything is held"
		return h, nil
	}
	for _, r := range refs {
		end := time.Now().Add(margin)
		if r.ClosedAt != nil {
			end = r.ClosedAt.Add(margin)
		}
		if !overlaps(r.OpenedAt.Add(-margin), end, from, to) {
			continue
		}
		why := "held violation " + r.ViolationID
		h.addTracks(why, r.TrackID)
		if r.Serial != nil {
			h.addSerials(why, *r.Serial)
		}
	}
	open, err := q.OpenIncidentAircraft(ctx, maxIncidentAircraft+1)
	if err != nil {
		return h, fmt.Errorf("open incidents: %w", err)
	}
	if len(open) > maxIncidentAircraft {
		s.inc(CounterHoldsBound)
		h.All = "more open incident aircraft than a check reads: everything is held"
		return h, nil
	}
	for _, a := range open {
		if !overlaps(a.OccurredAt.Add(-margin), a.OccurredAt.Add(margin), from, to) {
			continue
		}
		why := "open incident " + a.IncidentID
		h.addTracks(why, a.TrackIds...)
		if a.Serial != nil {
			h.addSerials(why, *a.Serial)
		}
	}
	return h, nil
}

// exemptOver gathers the aircraft of the incidents (any status) that
// occurred within the margin of [from, to): their remote pilot positions
// are kept in the archive of that range (06 §5).
func (s *Service) exemptOver(ctx context.Context, q *gen.Queries, from, to time.Time) (heldSet, error) {
	var h heldSet
	rows, err := q.IncidentAircraftAround(ctx, gen.IncidentAircraftAroundParams{
		FromTs: from.Add(-s.IncidentMargin), ToTs: to.Add(s.IncidentMargin), MaxRows: maxIncidentAircraft + 1,
	})
	if err != nil {
		return h, fmt.Errorf("incident aircraft: %w", err)
	}
	if len(rows) > maxIncidentAircraft {
		// Fail towards keeping the evidence: every position of the range
		// is kept, and the run says so.
		s.inc(CounterHoldsBound)
		h.All = "more incident aircraft around the range than a check reads: no position is removed"
		return h, nil
	}
	for _, r := range rows {
		why := "incident " + r.IncidentID
		h.addTracks(why, r.TrackIds...)
		if r.Serial != nil {
			h.addSerials(why, *r.Serial)
		}
	}
	return h, nil
}
