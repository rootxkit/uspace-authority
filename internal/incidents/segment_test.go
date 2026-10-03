package incidents

import (
	"slices"
	"testing"
	"time"
)

func positioned(ss ...float64) []Point {
	out := make([]Point, 0, len(ss))
	for i, s := range ss {
		out = append(out, Point{At: at(s), Positioned: true, Index: i})
	}
	return out
}

const gap3 = 3 * time.Second

// E-01: a continuous track yields one segment and no hole.
func TestCutContinuousTrackIsOneSegment(t *testing.T) {
	segs, holes := Cut(positioned(0, 1, 2, 3, 6, 9), nil, gap3)
	if len(segs) != 1 || len(holes) != 0 {
		t.Fatalf("segments %d holes %v", len(segs), holes)
	}
	if !slices.Equal(segs[0].Indexes, []int{0, 1, 2, 3, 4, 5}) || !segs[0].From.Equal(at(0)) || !segs[0].To.Equal(at(9)) {
		t.Fatalf("segment %+v", segs[0])
	}
}

// A silence longer than max_gap_s is a hole nothing explains; a silence
// of exactly max_gap_s is not.
func TestCutSilenceIsAHoleWithNoRecordedCause(t *testing.T) {
	segs, holes := Cut(positioned(0, 1, 4.5, 5.5), nil, gap3)
	if len(segs) != 2 || len(holes) != 1 {
		t.Fatalf("segments %d holes %d", len(segs), len(holes))
	}
	h := holes[0]
	if !slices.Equal(h.Causes, []string{CauseSilence, CauseNone}) || !h.From.Equal(at(1)) || !h.To.Equal(at(4.5)) || h.DurationS != 3.5 {
		t.Fatalf("hole %+v", h)
	}
	if !slices.Equal(segs[0].Indexes, []int{0, 1}) || !slices.Equal(segs[1].Indexes, []int{2, 3}) {
		t.Fatalf("segments %+v", segs)
	}
	if _, holes := Cut(positioned(0, 3), nil, gap3); len(holes) != 0 {
		t.Fatalf("a silence of exactly max_gap_s cut the track: %v", holes)
	}
}

// A sample without a position cuts the track even inside max_gap_s.
func TestCutSampleWithoutPositionIsAHole(t *testing.T) {
	pts := append(positioned(0, 1, 2), Point{At: at(1.5), Cause: CauseNoPosition, Index: -1})
	segs, holes := Cut(pts, nil, gap3)
	if len(segs) != 2 || len(holes) != 1 || !slices.Equal(holes[0].Causes, []string{CauseNoPosition}) {
		t.Fatalf("segments %d holes %+v", len(segs), holes)
	}
	// An unlabelled point without a position counts as one too.
	_, holes = Cut(append(positioned(0, 1), Point{At: at(0.5), Index: -1}), nil, gap3)
	if len(holes) != 1 || holes[0].Causes[0] != CauseNoPosition {
		t.Fatalf("holes %+v", holes)
	}
}

func TestCutUndecodableFrameIsAHole(t *testing.T) {
	pts := append(positioned(0, 1), Point{At: at(0.5), Cause: CauseUndecodable, Index: -1})
	_, holes := Cut(pts, nil, gap3)
	if len(holes) != 1 || !slices.Equal(holes[0].Causes, []string{CauseUndecodable}) {
		t.Fatalf("holes %+v", holes)
	}
}

// A recorded writer gap cuts the track and names itself; with a silence
// too, the silence is no longer "no recorded cause".
func TestCutRecordedGapIsAHoleWithItsCause(t *testing.T) {
	gaps := []RecordedGap{{At: at(1.5), Detail: "tracks dropped"}, {At: at(20), Detail: "outside"}}
	_, holes := Cut(positioned(0, 1, 2), gaps, gap3)
	if len(holes) != 1 || !slices.Equal(holes[0].Causes, []string{CauseWriterGap}) || !slices.Equal(holes[0].Recorded, []string{"tracks dropped"}) {
		t.Fatalf("holes %+v", holes)
	}
	_, holes = Cut(positioned(0, 1, 30), gaps, gap3)
	if len(holes) != 1 || !slices.Equal(holes[0].Causes, []string{CauseWriterGap, CauseSilence}) {
		t.Fatalf("holes %+v", holes)
	}
}

// Samples without a position before the first and after the last
// positioned sample are holes; a track of them alone has no segment.
func TestCutEdgesAndPositionlessOnly(t *testing.T) {
	pts := append(positioned(5, 6), Point{At: at(4), Cause: CauseNoPosition, Index: -1}, Point{At: at(8), Cause: CauseNoPosition, Index: -1})
	segs, holes := Cut(pts, nil, gap3)
	if len(segs) != 1 || len(holes) != 2 || !holes[0].From.Equal(at(4)) || !holes[0].To.Equal(at(5)) ||
		!holes[1].From.Equal(at(6)) || !holes[1].To.Equal(at(8)) {
		t.Fatalf("segments %d holes %+v", len(segs), holes)
	}
	segs, holes = Cut([]Point{{At: at(1), Cause: CauseNoPosition, Index: -1}}, nil, gap3)
	if len(segs) != 0 || len(holes) != 1 {
		t.Fatalf("segments %d holes %+v", len(segs), holes)
	}
	if segs, holes := Cut(nil, nil, gap3); len(segs) != 0 || len(holes) != 0 {
		t.Fatal("an empty track has segments or holes")
	}
}

// Input order does not matter.
func TestCutSortsByTime(t *testing.T) {
	pts := positioned(0, 1, 2)
	slices.Reverse(pts)
	segs, _ := Cut(pts, nil, gap3)
	if len(segs) != 1 || !slices.Equal(segs[0].Indexes, []int{0, 1, 2}) {
		t.Fatalf("segments %+v", segs)
	}
}

// Every positioned sample is in exactly one segment, whatever the input
// (no sample lost, none invented: nothing is interpolated).
func FuzzCut(f *testing.F) {
	f.Add([]byte{0, 1, 2, 10, 11, 200}, []byte{5}, uint8(3))
	f.Fuzz(func(t *testing.T, raw, gapRaw []byte, maxGap uint8) {
		var pts []Point
		want := 0
		for i, b := range raw {
			p := Point{At: at(float64(b) / 4), Positioned: b%5 != 0, Index: i}
			if !p.Positioned {
				p.Cause = CauseNoPosition
			} else {
				want++
			}
			pts = append(pts, p)
		}
		var gaps []RecordedGap
		for _, b := range gapRaw {
			gaps = append(gaps, RecordedGap{At: at(float64(b) / 4), Detail: "g"})
		}
		segs, holes := Cut(pts, gaps, time.Duration(maxGap)*time.Second)
		seen := map[int]bool{}
		for _, s := range segs {
			if len(s.Indexes) == 0 || s.To.Before(s.From) {
				t.Fatalf("segment %+v", s)
			}
			for _, ix := range s.Indexes {
				if seen[ix] || !pts[ix].Positioned {
					t.Fatalf("index %d twice or not positioned", ix)
				}
				seen[ix] = true
			}
		}
		if len(seen) != want {
			t.Fatalf("%d positioned samples in segments, want %d", len(seen), want)
		}
		for _, h := range holes {
			if len(h.Causes) == 0 || h.To.Before(h.From) {
				t.Fatalf("hole %+v", h)
			}
		}
	})
}
