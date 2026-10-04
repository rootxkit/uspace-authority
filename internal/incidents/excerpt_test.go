package incidents

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/api/gen"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

type fakeExcerptPolicy struct {
	row pggen.PackActivePolicyRow
	err error
}

func (f fakeExcerptPolicy) PackActivePolicy(context.Context) (pggen.PackActivePolicyRow, error) {
	return f.row, f.err
}

type fakeExcerptGaps struct {
	rows  []reader.EvidenceWriterGapsRow
	err   error
	asked *reader.EvidenceWriterGapsParams
}

func (f *fakeExcerptGaps) EvidenceWriterGaps(_ context.Context, arg reader.EvidenceWriterGapsParams) ([]reader.EvidenceWriterGapsRow, error) {
	f.asked = &arg
	if f.err != nil {
		return nil, f.err
	}
	n := min(len(f.rows), int(arg.RowLimit))
	return f.rows[:n], nil
}

var excerptT0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func sampleAt(offsetS float64) map[string]any {
	return map[string]any{
		"captured_at": excerptT0.Add(time.Duration(offsetS * float64(time.Second))).Format(time.RFC3339Nano),
		"lat":         41.7, "lng": 44.8,
	}
}

func policy3s() fakeExcerptPolicy {
	return fakeExcerptPolicy{row: pggen.PackActivePolicyRow{Version: 4, MaxGapS: 3}}
}

func TestExcerptContinuousIsOneSegmentAndNoHole(t *testing.T) {
	gaps := &fakeExcerptGaps{}
	got := ExcerptCutter{Policy: policy3s(), Gaps: gaps}.Cut(t.Context(), []map[string]any{sampleAt(0), sampleAt(1), sampleAt(2)})
	if got.State != gen.ViolationExcerptSegmentingStateCut || len(got.Segments) != 1 || len(got.Holes) != 0 {
		t.Fatalf("got %+v, want one segment and no hole", got)
	}
	if got.Segments[0].SampleIndexes[0] != 0 || len(got.Segments[0].SampleIndexes) != 3 {
		t.Fatalf("segment indexes %v", got.Segments[0].SampleIndexes)
	}
	if *got.MaxGapS != 3 || *got.PolicyVersion != 4 || !*got.WriterGapsRead {
		t.Fatalf("segmenting facts %+v", got)
	}
	if gaps.asked == nil || !gaps.asked.FromTs.Equal(excerptT0) || !gaps.asked.ToTs.After(excerptT0.Add(2*time.Second)) {
		t.Fatalf("writer gaps asked for %+v, want the excerpt's window", gaps.asked)
	}
}

// The pair of the above (E-01): a silence past max_gap_s is a hole with
// its causes, and the samples on either side are two segments.
func TestExcerptSilenceIsALabelledHole(t *testing.T) {
	got := ExcerptCutter{Policy: policy3s(), Gaps: &fakeExcerptGaps{}}.Cut(t.Context(),
		[]map[string]any{sampleAt(0), sampleAt(1), sampleAt(9), sampleAt(10)})
	if len(got.Segments) != 2 || len(got.Holes) != 1 {
		t.Fatalf("got %d segments, %d holes; want 2 and 1", len(got.Segments), len(got.Holes))
	}
	h := got.Holes[0]
	if h.DurationS != 8 || len(h.Causes) != 2 || h.Causes[0] != CauseSilence || h.Causes[1] != CauseNone {
		t.Fatalf("hole %+v, want 8 s of silence with no recorded cause", h)
	}
}

func TestExcerptRecordedGapIsAWriterGapHole(t *testing.T) {
	gaps := &fakeExcerptGaps{rows: []reader.EvidenceWriterGapsRow{{TableName: "tracks", Cause: "spilled", Count: 3, CountUnit: "rows",
		Stream: "TRK", FromSeq: 10, ToSeq: 12, At: excerptT0.Add(1500 * time.Millisecond)}}}
	got := ExcerptCutter{Policy: policy3s(), Gaps: gaps}.Cut(t.Context(), []map[string]any{sampleAt(0), sampleAt(1), sampleAt(2)})
	if len(got.Holes) != 1 || got.Holes[0].Causes[0] != CauseWriterGap || len(got.Holes[0].Recorded) != 1 {
		t.Fatalf("holes %+v, want one writer_gap hole with its recorded line", got.Holes)
	}
}

// Gaps that cannot be read never become "no recorded cause" (C-12).
func TestExcerptGapsUnreadAreSaid(t *testing.T) {
	got := ExcerptCutter{Policy: policy3s(), Gaps: &fakeExcerptGaps{err: errors.New("connection refused")}}.Cut(t.Context(),
		[]map[string]any{sampleAt(0), sampleAt(9)})
	if *got.WriterGapsRead || len(got.Holes) != 1 {
		t.Fatalf("got %+v", got)
	}
	causes := got.Holes[0].Causes
	if len(causes) != 2 || causes[0] != CauseSilence || causes[1] != CauseGapsUnread {
		t.Fatalf("causes %v, want silence and writer_gaps_unread", causes)
	}
}

// A window holding more gaps than the bound is cut with what was read,
// and says the gaps were not read in full (E-10).
func TestExcerptGapsPastTheBoundAreNotReadInFull(t *testing.T) {
	var rows []reader.EvidenceWriterGapsRow
	for i := range 3 {
		rows = append(rows, reader.EvidenceWriterGapsRow{TableName: "tracks", At: excerptT0.Add(time.Duration(i+1) * time.Second)})
	}
	got := ExcerptCutter{Policy: policy3s(), Gaps: &fakeExcerptGaps{rows: rows}, MaxGaps: 2}.Cut(t.Context(),
		[]map[string]any{sampleAt(0), sampleAt(10)})
	if *got.WriterGapsRead {
		t.Fatal("writer gaps past the bound reported as read in full")
	}
	if len(got.Holes) != 1 || got.Holes[0].Causes[0] != CauseWriterGap || len(got.Holes[0].Recorded) != 2 {
		t.Fatalf("holes %+v", got.Holes)
	}
}

func TestExcerptWithoutPolicyIsUnavailable(t *testing.T) {
	got := ExcerptCutter{Policy: fakeExcerptPolicy{err: errors.New("no rows")}, Gaps: &fakeExcerptGaps{}}.Cut(t.Context(),
		[]map[string]any{sampleAt(0)})
	if got.State != gen.ViolationExcerptSegmentingStateUnavailable || got.Reason == nil || len(got.Segments) != 0 {
		t.Fatalf("got %+v, want unavailable with a reason", got)
	}
	if got := (ExcerptCutter{}).Cut(t.Context(), nil); got.State != gen.ViolationExcerptSegmentingStateUnavailable {
		t.Fatalf("no policy reader: %+v", got)
	}
}

func TestExcerptUnplacedAndUnpositionedSamples(t *testing.T) {
	noPos := map[string]any{"captured_at": excerptT0.Add(time.Second).Format(time.RFC3339Nano)}
	bad := map[string]any{"captured_at": "yesterday", "lat": 41.7, "lng": 44.8}
	got := ExcerptCutter{Policy: policy3s(), Gaps: &fakeExcerptGaps{}}.Cut(t.Context(),
		[]map[string]any{sampleAt(0), noPos, bad, sampleAt(2)})
	if len(got.Unplaced) != 1 || got.Unplaced[0] != 2 {
		t.Fatalf("unplaced %v, want [2]", got.Unplaced)
	}
	if len(got.Holes) != 1 || got.Holes[0].Causes[0] != CauseNoPosition {
		t.Fatalf("holes %+v, want one sample_without_position hole", got.Holes)
	}
}
