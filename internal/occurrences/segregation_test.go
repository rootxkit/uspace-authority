package occurrences

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// enforcementRef finds a name of the enforcement records (violations,
// incidents, evidence packs) in SQL or Go code, outside comments.
var enforcementRef = regexp.MustCompile(`(?i)\bviolations?\b|\bviolation_\w+|\bincidents?\b|\bincident_\w+|\bevidence_packs?\b|internal/violations|internal/incidents`)

func codeMentionsEnforcement(src string) []string {
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
		if enforcementRef.MatchString(line) {
			hits = append(hits, trimmed)
		}
	}
	return hits
}

// 376/2014 Art. 15-16, CLAUDE.md rule 6: no line of this package's code,
// of its queries or of its migration statements names a violation, an
// incident or an evidence pack, so no query path can join a report to
// them; internal/incidents holds itself to the reverse
// (TestNoPathToOccurrenceReports). The live catalogue is checked by
// TestIntegrationNoPathJoinsAnOccurrenceToAViolation.
func TestNoPathFromOccurrencesToEnforcement(t *testing.T) {
	if codeMentionsEnforcement("SELECT * FROM violations;") == nil || codeMentionsEnforcement("-- never joined to violations") != nil ||
		codeMentionsEnforcement("x := 1 // not incidents") != nil {
		t.Fatal("the scanner does not tell code from comments")
	}
	files := []string{"store/queries/occurrences.sql", "../../migrations/relational/00020_occurrences.sql"}
	for _, pattern := range []string{"*.go", "store/*.go"} {
		gos, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range gos {
			if !strings.HasSuffix(f, "_test.go") {
				files = append(files, f)
			}
		}
	}
	if len(files) < 9 {
		t.Fatalf("scanned only %v", files)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range codeMentionsEnforcement(string(raw)) {
			t.Errorf("%s names an enforcement record: %s", f, h)
		}
	}
}

// The migration creates no column naming a violation or an incident in
// the occurrences schema; the incidents migration none naming an
// occurrence (the live catalogue says the same in the integration test).
func TestNoLinkColumnInEitherMigration(t *testing.T) {
	occ, err := os.ReadFile("../../migrations/relational/00020_occurrences.sql")
	if err != nil {
		t.Fatal(err)
	}
	inc, err := os.ReadFile("../../migrations/relational/00017_incidents.sql")
	if err != nil {
		t.Fatal(err)
	}
	column := func(src, pattern string) bool {
		re := regexp.MustCompile(`(?im)^\s+(` + pattern + `)\s+(text|bigint|integer|uuid)`)
		return re.MatchString(src)
	}
	if column(string(occ), `violation_id|incident_id`) {
		t.Error("the occurrences schema has a violation_id or incident_id column")
	}
	if column(string(inc), `occurrence_id`) {
		t.Error("the incidents schema has an occurrence_id column")
	}
	// E-01: the check finds a column where there is one.
	if !column("CREATE TABLE x (\n    violation_id text NOT NULL\n);", `violation_id|incident_id`) || !column(string(occ), `occurrence_id`) {
		t.Fatal("the column check is blind")
	}
}
