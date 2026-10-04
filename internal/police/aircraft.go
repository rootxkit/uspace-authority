package police

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// freshnessHorizon is how far back the newest sample of the picture is
// looked for (a picture silent for longer reads as none).
const freshnessHorizon = 24 * time.Hour

// AircraftQuery is GET /v1/police/aircraft.
type AircraftQuery struct {
	BBox    string
	At      *time.Time
	Purpose string
	CaseRef string
}

// sighting is one track of an answer before identities are added.
type sighting struct {
	row       reader.PoliceAircraftRow
	positions []reader.PolicePositionsRow
	truncated bool
}

// readAircraft reads the tracks seen in box over w: at most limit, more
// reported by truncated; and per track the newest positions.
func (s *Service) readAircraft(ctx context.Context, box BBox, w Window, limit int, withPositions bool) ([]sighting, bool, error) {
	rows, err := s.Telemetry.PoliceAircraft(ctx, reader.PoliceAircraftParams{FromTs: w.From, ToTs: w.To, MinLat: box.MinLat,
		MaxLat: box.MaxLat, MinLon: box.MinLon, MaxLon: box.MaxLon, RowLimit: int32(limit + 1)})
	if err != nil {
		return nil, false, fmt.Errorf("read the picture: %w", err)
	}
	truncated := len(rows) > limit
	if truncated {
		rows = rows[:limit]
	}
	out := make([]sighting, len(rows))
	ids := make([]string, len(rows))
	for i := range rows {
		out[i].row, ids[i] = rows[i], rows[i].TrackID
	}
	if !withPositions || len(rows) == 0 {
		return out, truncated, nil
	}
	per := s.Limits.MaxPositions
	pos, err := s.Telemetry.PolicePositions(ctx, reader.PolicePositionsParams{TrackIds: ids, FromTs: w.From, ToTs: w.To,
		MinLat: box.MinLat, MaxLat: box.MaxLat, MinLon: box.MinLon, MaxLon: box.MaxLon, PerTrack: int32(per)})
	if err != nil {
		return nil, false, fmt.Errorf("read the positions: %w", err)
	}
	byTrack := map[string][]reader.PolicePositionsRow{}
	for _, p := range pos {
		byTrack[p.TrackID] = append(byTrack[p.TrackID], p)
	}
	for i := range out {
		ps := byTrack[out[i].row.TrackID]
		slices.Reverse(ps) // the query reads newest first
		out[i].positions = ps
		out[i].truncated = out[i].row.Samples > int64(len(ps))
	}
	return out, truncated, nil
}

// registration is the operator registration's public part a track was
// identified with: the registry's when it matched, else as broadcast.
func (s *Service) registration(r *reader.PoliceAircraftRow) string {
	for _, v := range []*string{r.RegisteredOperatorReg, r.OperatorReg} {
		if v != nil && *v != "" {
			if p := s.publicPart(*v); p != "" {
				return p
			}
		}
	}
	return ""
}

// QueryAircraft answers who is flying in a box now or was at an
// instant. The query is recorded before any personal data is opened;
// identities are added only for a purpose that releases them.
func (s *Service) QueryAircraft(ctx context.Context, q AircraftQuery) (gen.PoliceAircraftAnswer, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	c, err := s.caller(ctx)
	if err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}
	purpose, err := s.Purposes.Check(q.Purpose)
	if err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}
	caseRef, err := CheckCaseRef(q.CaseRef)
	if err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}
	box, err := ParseBBox("bbox", q.BBox, s.Limits.MaxBBoxDeg)
	if err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}
	if err := s.precheck(ctx, c, KindAircraft, purpose, caseRef); err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}
	clock, err := s.Telemetry.PoliceClock(ctx, freshnessHorizon.Seconds())
	if err != nil {
		return gen.PoliceAircraftAnswer{}, fmt.Errorf("read the telemetry clock: %w", err)
	}
	now := clock.DbNow.UTC()
	w, err := windowFor(q.At, now, s.Limits.LiveWindow, s.Limits.AtWindow, s.Limits.HistoryMax)
	if err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}
	seen, truncated, err := s.readAircraft(ctx, box, w, s.Limits.MaxAircraft, true)
	if err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}
	gaps, err := s.Telemetry.PoliceWriterGaps(ctx, reader.PoliceWriterGapsParams{FromTs: w.From, ToTs: w.To})
	if err != nil {
		return gen.PoliceAircraftAnswer{}, fmt.Errorf("read the writer gaps: %w", err)
	}
	pii := s.Purposes.AllowsPII(purpose)
	candidates := 0
	for i := range seen {
		if seen[i].row.RegistryUasID != nil || s.registration(&seen[i].row) != "" {
			candidates++
		}
	}
	query := map[string]any{"bbox": box.String(), "mode": "live", "window_from": w.From, "window_to": w.To}
	if !w.Live {
		query["mode"], query["at"] = "at", w.AsOf
	}
	e := Entry{Kind: KindAircraft, Purpose: purpose, CaseRef: caseRef, Query: query, ResultCount: len(seen),
		PII: pii && candidates > 0, Caller: c}
	if err := s.record(ctx, &e); err != nil {
		return gen.PoliceAircraftAnswer{}, err
	}

	out := gen.PoliceAircraftAnswer{QueryId: e.ID, Purpose: purpose, CaseRef: caseRef, Mode: gen.PoliceAircraftAnswerModeLive,
		AsOf: w.AsOf, WindowFrom: w.From, WindowTo: w.To, Aircraft: make([]gen.PoliceAircraft, 0, len(seen)), Truncated: truncated}
	if !w.Live {
		out.Mode = gen.PoliceAircraftAnswerModeAt
	}
	out.Sources = sourcesOf(clock, gaps, w, s.Limits.LiveWindow)
	pctx := piiContext(ctx, &e)
	identities := map[string]*gen.PoliceOperatorIdentity{}
	for i := range seen {
		a := aircraftOut(&seen[i], s.registration(&seen[i].row))
		if pii {
			id, reason := s.aircraftIdentity(pctx, &seen[i].row, purpose, c, identities)
			if id != nil {
				a.Operator, out.PiiReleased = id, true
			} else {
				a.OperatorUnresolved = &reason
				s.inc(CounterPIIUnresolved)
			}
		}
		out.Aircraft = append(out.Aircraft, a)
	}
	return out, nil
}

func sourcesOf(clock reader.PoliceClockRow, gaps reader.PoliceWriterGapsRow, w Window, live time.Duration) gen.PolicePictureSources {
	causes := gaps.Causes
	if causes == nil {
		causes = []string{}
	}
	src := gen.PolicePictureSources{WriterGaps: int(gaps.Gaps), WriterGapCauses: causes, Degraded: gaps.Gaps > 0}
	if clock.HasNewest {
		age := clock.NewestAgeS
		at := clock.DbNow.UTC().Add(-time.Duration(age * float64(time.Second)))
		src.NewestTrackAgeS, src.NewestTrackAt = &age, &at
		if w.Live && age > live.Seconds() {
			src.Degraded = true
		}
	} else if w.Live {
		src.Degraded = true
	}
	return src
}

func aircraftOut(s *sighting, reg string) gen.PoliceAircraft {
	r := &s.row
	a := gen.PoliceAircraft{TrackId: r.TrackID, Serial: r.Serial, IdentificationStatus: gen.PoliceAircraftIdentificationStatus(r.IdentStatus),
		IdentificationBasis: r.IdentBasis, Trust: r.Trust, Source: r.Source, FirstSeen: r.FirstSeen.UTC(), LastSeen: r.LastSeen.UTC(),
		Emergency: r.Emergency, Positions: make([]gen.PolicePosition, 0, len(s.positions)), PositionsTruncated: s.truncated}
	if r.IdentReason != "" {
		reason := r.IdentReason
		a.IdentificationReason = &reason
	}
	if reg != "" {
		a.RegistrationNumber = &reg
	}
	for _, p := range s.positions {
		a.Positions = append(a.Positions, gen.PolicePosition{At: p.CapturedAt.UTC(), LatDeg: p.LatDeg, LonDeg: p.LonDeg, AltAmslM: p.AltAmslM,
			AltSource: p.AltSource, HeightM: p.HeightM, HeightRef: p.HeightRef, SpeedMs: p.SpeedMs, TrackDeg: p.TrackDeg})
	}
	return a
}

// Reasons an aircraft's identity was not released for a personal-data
// purpose.
const (
	UnresolvedNotIdentified = "not_identified"
	UnresolvedNotRegistered = "not_in_registry"
	UnresolvedAmbiguous     = "ambiguous_registration"
	UnresolvedUnavailable   = "registry_unavailable"
)

// aircraftIdentity resolves the operator of a track: through the
// registry's aircraft when the identification matched one, else through
// the registration number as identified. One operator is read once per
// answer (seen).
func (s *Service) aircraftIdentity(ctx context.Context, r *reader.PoliceAircraftRow, purpose string, c Caller,
	seen map[string]*gen.PoliceOperatorIdentity) (*gen.PoliceOperatorIdentity, string) {
	var op registry.Operator
	switch {
	case r.RegistryUasID != nil && *r.RegistryUasID != "":
		u, err := s.Registry.GetUAS(ctx, *r.RegistryUasID)
		if err != nil {
			return nil, UnresolvedNotRegistered
		}
		if op, err = s.Registry.GetOperator(ctx, u.OperatorID); err != nil {
			return nil, UnresolvedNotRegistered
		}
	case s.registration(r) != "":
		found, ok, err := s.Registry.OperatorByNumber(ctx, s.registration(r))
		switch {
		case errors.Is(err, registry.ErrAmbiguous):
			return nil, UnresolvedAmbiguous
		case err != nil:
			return nil, UnresolvedUnavailable
		case !ok:
			return nil, UnresolvedNotRegistered
		}
		op = found
	default:
		return nil, UnresolvedNotIdentified
	}
	if id, ok := seen[op.ID]; ok {
		return id, ""
	}
	id, err := s.identity(ctx, op, purpose, c.Actor)
	if err != nil {
		return nil, UnresolvedUnavailable
	}
	out := identityOut(id)
	seen[op.ID] = &out
	return &out, ""
}

func identityOut(id Identity) gen.PoliceOperatorIdentity {
	opt := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	return gen.PoliceOperatorIdentity{OperatorId: id.OperatorID, OperatorType: id.OperatorType, FullName: opt(id.FullName),
		LegalName: opt(id.LegalName), PostalAddress: opt(id.PostalAddress), ContactEmail: opt(id.ContactEmail),
		ContactPhone: opt(id.ContactPhone)}
}
