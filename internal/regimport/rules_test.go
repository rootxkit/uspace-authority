package regimport

import (
	"os"
	"strings"
	"testing"
	"time"
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.ReplaceAll(string(b), "\r\n", "\n"))
}

func testRules(t *testing.T) *Rules {
	t.Helper()
	r, err := ParseRules(readFile(t, "rules.json"))
	if err != nil {
		t.Fatalf("the synthetic rules file does not check: %v", err)
	}
	return r
}

func TestLoadRulesReadsTheSyntheticFile(t *testing.T) {
	r, err := LoadRules("testdata/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	if r.RulesVersion != "synthetic-1" || r.offset == nil || len(r.layouts) != 3 || r.pattern == nil || r.MTOMUnit != "kg" {
		t.Fatalf("%+v", r)
	}
	if _, err := LoadRules("testdata/absent.json"); err == nil || !strings.Contains(err.Error(), "REGISTRY_IMPORT_RULES_FILE") {
		t.Fatalf("absent file: %v", err)
	}
}

// Every rule the file can break is named by its path; the accepted file
// above is the twin of each.
func TestParseRulesNamesEveryFault(t *testing.T) {
	good := string(readFile(t, "rules.json"))
	cases := []struct {
		name, from, to, field string
	}{
		{"version", `"synthetic-1"`, `"bad version!"`, "rules.rules_version"},
		{"format", `"format": "csv"`, `"format": "xml"`, "rules.format"},
		{"delimiter", `"delimiter": ";"`, `"delimiter": ";;"`, "rules.csv.delimiter"},
		{"pattern", `"GEOTEST[0-9]{8}"`, `"GEO(["`, "rules.registration_number_pattern"},
		{"date format token", `"DD.MM.YYYY"`, `"DD.MON.YYYY"`, "rules.date_formats[0]"},
		{"date format parts", `"DD.MM.YYYY"`, `"DD.MM"`, "rules.date_formats[0]"},
		{"offset", `"+04:00"`, `"Asia/Tbilisi"`, "rules.utc_offset"},
		{"unit", `"mtom_unit": "kg"`, `"mtom_unit": "lb"`, "rules.mtom_unit"},
		{"unknown field", `"full_name": "Name"`, `"nickname": "Name"`, "rules.operators.columns.nickname"},
		{"required column", `"source_id": "Record ID",
      "registration_number"`, `"registration_number"`, "rules.operators.columns.source_id"},
		{"default for an id", `"defaults": {"status": "active"}`, `"defaults": {"source_id": "x"}`, "rules.operators.defaults.source_id"},
		{"default value", `"defaults": {"rid_capability": "none"`, `"defaults": {"rid_capability": "radio"`, "rules.uas.defaults.rid_capability"},
		{"mapped target", `"Cancelled": "revoked"}`, `"Cancelled": "expired"}`, "rules.operators.values.status.Cancelled"},
		{"duplicate value", `"Physical person": "natural",`, `"Physical person": "natural", "physical PERSON ": "natural",`, "rules.operators.values.operator_type"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(good, c.from) {
				t.Fatalf("the synthetic file has no %q", c.from)
			}
			_, err := ParseRules([]byte(strings.Replace(good, c.from, c.to, 1)))
			if err == nil || !strings.Contains(err.Error(), c.field) {
				t.Fatalf("want a fault on %s, got %v", c.field, err)
			}
		})
	}
	if _, err := ParseRules([]byte(good + "{}")); err == nil {
		t.Fatal("a second object was accepted")
	}
	if _, err := ParseRules([]byte(strings.Replace(good, `"format": "csv",`, `"format": "csv", "extra": 1,`, 1))); err == nil {
		t.Fatal("an unknown member was accepted")
	}
}

func TestLayouts(t *testing.T) {
	l, err := parseLayout("YYYY-MM-DDThh:mm:ss")
	if err != nil || l.goLayout != "2006-01-02T15:04:05" || !l.hasTime {
		t.Fatalf("%+v %v", l, err)
	}
	if l, err := parseLayout("DD/MM/YYYY"); err != nil || l.hasTime || l.goLayout != "02/01/2006" {
		t.Fatalf("%+v %v", l, err)
	}
	for _, bad := range []string{"", "YYYY-MM", "Jan 2 2006", strings.Repeat("Y", 33)} {
		if _, err := parseLayout(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	loc, err := parseOffset("-03:30")
	if err != nil {
		t.Fatal(err)
	}
	if _, off := time.Date(2026, 1, 1, 0, 0, 0, 0, loc).Zone(); off != -(3*3600 + 1800) {
		t.Fatalf("offset %d", off)
	}
	for _, bad := range []string{"", "+4", "+15:00", "+04:60", "UTC"} {
		if _, err := parseOffset(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFoldKeyFoldsASCIIOnly(t *testing.T) {
	if foldKey("  Active ") != "ACTIVE" {
		t.Fatal(foldKey("  Active "))
	}
	// G-12: a long s is not an s.
	if foldKey("ſuspended") == foldKey("suspended") {
		t.Fatal("a Unicode fold")
	}
}
