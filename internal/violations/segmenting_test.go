package violations

import (
	"context"
	"testing"

	"github.com/rootxkit/uspace-authority/api/gen"
)

// Without a cutter the answer says the excerpt is not cut, never an
// empty cut that would read as "no hole" (E-01 with the test below).
func TestSegmentingWithoutCutterIsUnavailable(t *testing.T) {
	got := (&Service{}).Segmenting(t.Context(), []map[string]any{{"captured_at": "2026-10-03T12:00:00Z"}})
	if got.State != gen.ViolationExcerptSegmentingStateUnavailable || got.Reason == nil || *got.Reason == "" {
		t.Fatalf("got %+v, want unavailable with a reason", got)
	}
	if got.Segments == nil || got.Holes == nil || got.Unplaced == nil {
		t.Fatal("the arrays must be present, empty")
	}
}

func TestSegmentingWithCutterIsTheCuttersAnswer(t *testing.T) {
	var seen int
	s := &Service{CutExcerpt: func(_ context.Context, ex []map[string]any) gen.ViolationExcerptSegmenting {
		seen = len(ex)
		return gen.ViolationExcerptSegmenting{State: gen.ViolationExcerptSegmentingStateCut, Holes: []gen.ViolationExcerptHole{{Causes: []string{"silence"}}}}
	}}
	got := s.Segmenting(t.Context(), []map[string]any{{}, {}})
	if seen != 2 || got.State != gen.ViolationExcerptSegmentingStateCut || len(got.Holes) != 1 {
		t.Fatalf("got %+v after %d samples", got, seen)
	}
}
