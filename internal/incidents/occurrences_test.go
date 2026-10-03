package incidents

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// occurrenceRef finds a name of the occurrences schema or table in SQL
// or Go code, outside comments.
var occurrenceRef = regexp.MustCompile(`(?i)occurrence`)

func mentionsOccurrences(src string) bool {
	for line := range strings.SplitSeq(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "--") {
			continue
		}
		if occurrenceRef.MatchString(line) {
			return true
		}
	}
	return false
}

// 376/2014 Art. 15-16, CLAUDE.md rule 6: an incident is never opened
// from an occurrence report and a pack never reads one. No query, no
// code line of this package and no statement of the incidents migration
// names them; the scanner finds such a line when there is one (E-01).
func TestNoPathToOccurrenceReports(t *testing.T) {
	if !mentionsOccurrences("SELECT * FROM occurrences.occurrence_reports;") || mentionsOccurrences("-- occurrences are never read") {
		t.Fatal("the scanner does not tell code from comments")
	}
	files := []string{"../store/pg/queries/incidents.sql", "../store/ts/queries/reader/evidence.sql",
		"../../migrations/relational/00017_incidents.sql"}
	gos, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range gos {
		if !strings.HasSuffix(f, "_test.go") {
			files = append(files, f)
		}
	}
	if len(files) < 10 {
		t.Fatalf("scanned only %v", files)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if mentionsOccurrences(string(raw)) {
			t.Errorf("%s names occurrence reports", f)
		}
	}
}
