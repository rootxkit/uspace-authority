package violations

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/violation"
)

// The bbox filter: four finite WGS84 degrees, min below max; anything
// else is refused naming bbox (E-01: each refusal beside an acceptance).
func TestParseBBoxRefusesWhatItCannotJudge(t *testing.T) {
	if a, b, c, d, err := ParseBBox("44.7, 41.6,44.9,41.8"); err != nil || a != 44.7 || b != 41.6 || c != 44.9 || d != 41.8 {
		t.Fatalf("%v %v %v %v %v", a, b, c, d, err)
	}
	for _, bad := range []string{"", "1,2,3", "a,1,2,3", "NaN,1,2,3", "1,2,Inf,4", "-181,0,1,1", "0,-91,1,1", "1,0,0,1", "0,1,1,1"} {
		if _, _, _, _, err := ParseBBox(bad); err == nil || !strings.Contains(err.Error(), "bbox") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// A cursor round-trips; a forged one is refused naming cursor.
func TestCursorRoundTripsAndRefusesForgeries(t *testing.T) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 123456789, time.UTC)
	got, id, err := DecodeCursor(EncodeCursor(at, "01KAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil || !got.Equal(at) || id != "01KAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("%v %v %v", got, id, err)
	}
	for _, bad := range []string{"%%%", "bm90LWEtY3Vyc29y", EncodeCursor(at, "")[:4]} {
		if _, _, err := DecodeCursor(bad); err == nil || !strings.Contains(err.Error(), "cursor") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// E-10: the stored excerpt stops at its bound and says so; within the
// bound nothing is left out.
func TestMergeExcerptIsBounded(t *testing.T) {
	add := []violation.Sample{{MsgID: "1"}, {MsgID: "2"}, {MsgID: "3"}}
	out, truncated, err := mergeExcerpt(nil, add, 3)
	if err != nil || truncated || len(out) != 3 {
		t.Fatalf("within: %d %v %v", len(out), truncated, err)
	}
	out, truncated, err = mergeExcerpt(out, []violation.Sample{{MsgID: "4"}}, 3)
	if err != nil || !truncated || len(out) != 3 {
		t.Fatalf("past: %d %v %v", len(out), truncated, err)
	}
	var first violation.Sample
	if err := json.Unmarshal(out[0], &first); err != nil || first.MsgID != "1" {
		t.Fatalf("the samples at detection were not kept first: %+v", first)
	}
	if ids := trackIDs([]violation.EvidenceRef{{Type: violation.RefTrack, ID: "A"}, {Type: violation.RefZone, ID: "GEO/Z"}}); len(ids) != 1 || ids[0] != "A" {
		t.Fatalf("%v", ids)
	}
}

// occurrenceRef finds a name of the occurrences schema or table in SQL
// or Go code, outside comments.
var occurrenceRef = regexp.MustCompile(`(?i)occurrence`)

func codeLines(src string) []string {
	var out []string
	for line := range strings.SplitSeq(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "--") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func mentions(src string) bool {
	for _, l := range codeLines(src) {
		if occurrenceRef.MatchString(l) {
			return true
		}
	}
	return false
}

// 376/2014 Art. 15-16, CLAUDE.md rule 6: violations never read
// occurrence reports. No query and no code line of this package, and no
// statement of the violations migration, names them. The scanner finds
// such a line when there is one (E-01).
func TestNoPathToOccurrenceReports(t *testing.T) {
	if !mentions("SELECT * FROM occurrences.occurrence_reports;") || mentions("-- occurrences are never read") {
		t.Fatal("the scanner does not tell code from comments")
	}
	files := []string{"../store/pg/queries/violations.sql", "../../migrations/relational/00015_violations.sql"}
	gos, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range gos {
		if !strings.HasSuffix(f, "_test.go") {
			files = append(files, f)
		}
	}
	if len(files) < 6 {
		t.Fatalf("scanned only %v", files)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if mentions(string(raw)) {
			t.Errorf("%s names occurrence reports", f)
		}
	}
}
