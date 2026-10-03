package incidents

import (
	"slices"
	"sort"
	"time"
)

// Hole causes (LESSONS B-13: a hole is shown as a hole, labelled with
// what is known of it; nothing is interpolated across it).
const (
	// CauseSilence: no sample for longer than the policy's max_gap_s.
	CauseSilence = "silence"
	// CauseNoPosition: a sample of the aircraft arrived without a
	// position (a Location message whose position is unknown, R-01).
	CauseNoPosition = "sample_without_position"
	// CauseUndecodable: a frame of the aircraft's transmitter could not
	// be decoded (the raw frame is in the pack).
	CauseUndecodable = "frame_undecodable"
	// CauseWriterGap: tsdb-writer recorded a dropped or spilled batch of
	// the tracks or frames table inside the hole (writer_gaps, WP-9).
	CauseWriterGap = "writer_gap"
	// CauseNone labels a silence nothing recorded explains.
	CauseNone = "no recorded cause"
)

// Point is one sample of a track: placed in time, with or without a
// position. Index points back into the caller's rows.
type Point struct {
	At         time.Time
	Positioned bool
	// Cause is the hole cause a point without a position stands for
	// (CauseNoPosition or CauseUndecodable); empty for a positioned one.
	Cause string
	Index int
}

// RecordedGap is a hole recorded by the system itself (writer_gaps).
type RecordedGap struct {
	At     time.Time
	Detail string
}

// Segment is a run of positioned samples with no hole inside: the
// indexes of its points, oldest first.
type Segment struct {
	From, To time.Time
	Indexes  []int
}

// Hole is the interval between two segments (or before the first, or
// after the last, when samples without a position lie there), with
// every cause known of it. A hole of silence alone is labelled
// CauseNone besides CauseSilence.
type Hole struct {
	From, To  time.Time
	DurationS float64
	Causes    []string
	// Recorded are the details of the recorded gaps inside it.
	Recorded []string
}

// Cut cuts points into segments at every silence longer than maxGap,
// at every recorded gap and at every point without a position (B-13),
// and labels each hole with its causes. Points are sorted by time
// first (stable). A continuous track yields one segment and no hole.
func Cut(points []Point, gaps []RecordedGap, maxGap time.Duration) ([]Segment, []Hole) {
	pts := slices.Clone(points)
	sort.SliceStable(pts, func(i, j int) bool { return pts[i].At.Before(pts[j].At) })
	gs := slices.Clone(gaps)
	sort.SliceStable(gs, func(i, j int) bool { return gs[i].At.Before(gs[j].At) })

	var segments []Segment
	var holes []Hole
	var cur *Segment
	var pending []Point // points without a position since the last positioned one
	var last *Point

	for i := range pts {
		p := pts[i]
		if !p.Positioned {
			pending = append(pending, p)
			continue
		}
		if last == nil {
			// Points without a position before the first positioned one.
			if len(pending) > 0 {
				holes = append(holes, newHole(pending[0].At, p.At, pending, between(gs, pending[0].At, p.At), false))
			}
		} else {
			recorded := between(gs, last.At, p.At)
			silent := p.At.Sub(last.At) > maxGap
			if silent || len(pending) > 0 || len(recorded) > 0 {
				holes = append(holes, newHole(last.At, p.At, pending, recorded, silent))
				cur = nil
			}
		}
		pending = nil
		if cur == nil {
			segments = append(segments, Segment{From: p.At})
			cur = &segments[len(segments)-1]
		}
		cur.To = p.At
		cur.Indexes = append(cur.Indexes, p.Index)
		last = &pts[i]
	}
	if len(pending) > 0 {
		from := pending[0].At
		if last != nil {
			from = last.At
		}
		holes = append(holes, newHole(from, pending[len(pending)-1].At, pending, between(gs, from, pending[len(pending)-1].At), false))
	}
	return segments, holes
}

// between are the recorded gaps strictly inside (from, to).
func between(gs []RecordedGap, from, to time.Time) []RecordedGap {
	var out []RecordedGap
	for _, g := range gs {
		if g.At.After(from) && g.At.Before(to) {
			out = append(out, g)
		}
	}
	return out
}

func newHole(from, to time.Time, pending []Point, recorded []RecordedGap, silent bool) Hole {
	h := Hole{From: from, To: to, DurationS: to.Sub(from).Seconds(), Causes: []string{}, Recorded: []string{}}
	add := func(c string) {
		if !slices.Contains(h.Causes, c) {
			h.Causes = append(h.Causes, c)
		}
	}
	for _, p := range pending {
		if p.Cause == "" {
			add(CauseNoPosition)
		} else {
			add(p.Cause)
		}
	}
	for _, g := range recorded {
		add(CauseWriterGap)
		h.Recorded = append(h.Recorded, g.Detail)
	}
	if silent {
		add(CauseSilence)
		if len(h.Causes) == 1 {
			add(CauseNone)
		}
	}
	return h
}
