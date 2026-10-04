package incidents

import (
	"context"
	"math"
	"slices"
	"time"

	"github.com/rootxkit/uspace-authority/api/gen"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// CauseGapsUnread labels a silence when the recorded writer gaps could
// not be read: whether something was recorded is not known, so the hole
// is never labelled CauseNone (C-12, E-04).
const CauseGapsUnread = "writer_gaps_unread"

// DefaultExcerptMaxGaps bounds the writer gaps read for one excerpt
// (E-10); a window holding more is cut with what was read, and its
// silences say the gaps were not read in full (CauseGapsUnread).
const DefaultExcerptMaxGaps = 1000

// ExcerptPolicy reads the active policy, whose max_gap_s cuts a track.
type ExcerptPolicy interface {
	PackActivePolicy(ctx context.Context) (pggen.PackActivePolicyRow, error)
}

// ExcerptGaps reads the writer gaps recorded in a window (the reader role).
type ExcerptGaps interface {
	EvidenceWriterGaps(ctx context.Context, arg reader.EvidenceWriterGapsParams) ([]reader.EvidenceWriterGapsRow, error)
}

// ExcerptCutter cuts a violation's evidence excerpt into segments and
// holes by the rule of the evidence packs (Cut, B-13), so the console
// draws holes as holes and judges nothing (WP-23). The violation keeps
// its samples as detected; this only reads them.
type ExcerptCutter struct {
	Policy  ExcerptPolicy
	Gaps    ExcerptGaps
	MaxGaps int
}

// ExcerptCutter is the cutter over this component's databases.
func (p *Parts) ExcerptCutter() ExcerptCutter {
	return ExcerptCutter{Policy: p.Service.DB.Queries(), Gaps: p.reader.Q, MaxGaps: DefaultExcerptMaxGaps}
}

// excerptPoint is one sample's placement, or why it has none.
func excerptPoint(i int, s map[string]any) (Point, bool) {
	raw, _ := s["captured_at"].(string)
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return Point{}, false
	}
	lat, latOK := s["lat"].(float64)
	lng, lngOK := s["lng"].(float64)
	positioned := latOK && lngOK && !math.IsNaN(lat) && !math.IsNaN(lng)
	return Point{At: at, Positioned: positioned, Index: i}, true
}

// Cut answers the excerpt's segments and holes. It never fails: a
// policy that cannot be read is the answer `unavailable` with the
// reason, and recorded gaps that cannot be read are said on every
// silence (CauseGapsUnread) and in writer_gaps_read.
func (c ExcerptCutter) Cut(ctx context.Context, excerpt []map[string]any) gen.ViolationExcerptSegmenting {
	out := gen.ViolationExcerptSegmenting{Segments: []gen.ViolationExcerptSegment{}, Holes: []gen.ViolationExcerptHole{}, Unplaced: []int{}}
	if c.Policy == nil {
		return unavailable(out, "the active policy is not read by this process")
	}
	pol, err := c.Policy.PackActivePolicy(ctx)
	if err != nil {
		return unavailable(out, "the active policy (max_gap_s cuts the excerpt) cannot be read: "+reason(err))
	}
	var points []Point
	for i, s := range excerpt {
		p, ok := excerptPoint(i, s)
		if !ok {
			out.Unplaced = append(out.Unplaced, i)
			continue
		}
		points = append(points, p)
	}
	var gaps []RecordedGap
	gapsRead := c.Gaps != nil
	if gapsRead && len(points) > 1 {
		from, to := points[0].At, points[0].At
		for _, p := range points {
			if p.At.Before(from) {
				from = p.At
			}
			if p.At.After(to) {
				to = p.At
			}
		}
		limit := c.MaxGaps
		if limit <= 0 {
			limit = DefaultExcerptMaxGaps
		}
		rows, err := c.Gaps.EvidenceWriterGaps(ctx, reader.EvidenceWriterGapsParams{FromTs: from, ToTs: to.Add(time.Nanosecond), RowLimit: int32(limit)})
		if err != nil || len(rows) >= limit {
			gapsRead = false
		}
		for i := range rows {
			gaps = append(gaps, RecordedGap{At: rows[i].At, Detail: gapDetail(&rows[i])})
		}
	}
	segments, holes := Cut(points, gaps, time.Duration(pol.MaxGapS*float64(time.Second)))
	for _, s := range segments {
		out.Segments = append(out.Segments, gen.ViolationExcerptSegment{From: s.From, To: s.To, SampleIndexes: s.Indexes})
	}
	for _, h := range holes {
		causes := h.Causes
		if !gapsRead {
			// Nothing is known of what was recorded: never "no recorded cause".
			causes = slices.DeleteFunc(slices.Clone(causes), func(c string) bool { return c == CauseNone })
			if slices.Contains(causes, CauseSilence) {
				causes = append(causes, CauseGapsUnread)
			}
		}
		out.Holes = append(out.Holes, gen.ViolationExcerptHole{From: h.From, To: h.To, DurationS: h.DurationS, Causes: causes, Recorded: h.Recorded})
	}
	maxGap, version := pol.MaxGapS, pol.Version
	out.State, out.MaxGapS, out.PolicyVersion, out.WriterGapsRead = gen.ViolationExcerptSegmentingStateCut, &maxGap, &version, &gapsRead
	return out
}

func unavailable(out gen.ViolationExcerptSegmenting, why string) gen.ViolationExcerptSegmenting {
	out.State = gen.ViolationExcerptSegmentingStateUnavailable
	out.Reason = &why
	return out
}
