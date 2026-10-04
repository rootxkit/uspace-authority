package police

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// occurrenceRef finds a name of the occurrence reports in code, outside
// comments.
var occurrenceRef = regexp.MustCompile(`(?i)\boccurrences?\b|\boccurrence_\w+|internal/occurrences`)

func codeMentionsOccurrences(src string) []string {
	var hits []string
	for line := range strings.SplitSeq(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "--") {
			continue
		}
		if code, _, ok := strings.Cut(line, " -- "); ok {
			line = code
		}
		if code, _, ok := strings.Cut(line, " // "); ok {
			line = code
		}
		if occurrenceRef.MatchString(line) {
			hits = append(hits, trimmed)
		}
	}
	return hits
}

// 376/2014 Art. 15(2), 16, CLAUDE.md rule 6: no line of this package's
// code, of its queries or of its migration statements names an
// occurrence report, so no path of the police realm reads one;
// internal/layout holds the imports to the same rule and the
// integration test holds the database role to it.
func TestNoPathFromThePoliceRealmToOccurrences(t *testing.T) {
	if codeMentionsOccurrences("SELECT * FROM occurrences.occurrence_reports;") == nil ||
		codeMentionsOccurrences("-- never an occurrence report") != nil || codeMentionsOccurrences("x := 1 // not occurrences") != nil {
		t.Fatal("the scanner does not tell code from comments")
	}
	files := []string{"../store/pg/queries/police.sql", "../store/ts/queries/reader/police.sql", "../../migrations/relational/00021_police.sql"}
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
		for _, h := range codeMentionsOccurrences(string(raw)) {
			t.Errorf("%s names an occurrence report: %s", f, h)
		}
	}
}
