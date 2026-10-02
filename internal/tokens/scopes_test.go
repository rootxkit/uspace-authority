package tokens

import (
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	backticked = regexp.MustCompile("`([^`]+)`")
	scopeName  = regexp.MustCompile(`^[a-z]+\.[a-z_:]+$`)
)

// tableB reads normative table B from the brief: the backticked scope
// names of the Scopes column of every row. The brief is the one place
// the catalogue is written; this test refuses any difference.
func tableB(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/WORKPACKAGES/WP-2.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	start := strings.Index(doc, "### B. The scope catalogue")
	if start < 0 {
		t.Fatal("table B not found in docs/WORKPACKAGES/WP-2.md")
	}
	var out []string
	inTable := false
	for line := range strings.SplitSeq(doc[start:], "\n") {
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cols := strings.Split(line, "|")
		if len(cols) < 4 || strings.Contains(cols[1], "Family") || strings.HasPrefix(strings.TrimSpace(cols[1]), "---") {
			continue
		}
		for _, m := range backticked.FindAllStringSubmatch(cols[2], -1) {
			if scopeName.MatchString(m[1]) {
				out = append(out, m[1])
			}
		}
	}
	return out
}

func catalogueNames() []string {
	out := make([]string, 0, len(catalogue))
	for _, s := range catalogue {
		out = append(out, s.Name)
	}
	return out
}

func TestCatalogueIsTableBOfTheBrief(t *testing.T) {
	doc := tableB(t)
	if len(doc) == 0 {
		t.Fatal("no scope read from table B")
	}
	if got := catalogueNames(); !slices.Equal(got, doc) {
		t.Fatalf("catalogue differs from WP-2 table B:\ncode %v\nbrief %v", got, doc)
	}
}

// The contract restates the catalogue (ecosystemToken); it must name
// every scope and nothing else that looks like one.
func TestContractRestatesTheCatalogue(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "Table B, the whole catalogue:")
	if i < 0 {
		t.Fatal("api/openapi.yaml does not restate table B")
	}
	j := strings.Index(s[i:], "receiverKey:")
	var got []string
	for _, m := range backticked.FindAllStringSubmatch(s[i:i+j], -1) {
		got = append(got, m[1])
	}
	if !slices.Equal(got, catalogueNames()) {
		t.Fatalf("contract %v\ncode %v", got, catalogueNames())
	}
}

func TestRunbookRestatesTheCatalogue(t *testing.T) {
	raw, err := os.ReadFile("../../docs/runbooks/token-service.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range catalogueNames() {
		if !strings.Contains(string(raw), "`"+name+"`") {
			t.Errorf("docs/runbooks/token-service.md does not name %s", name)
		}
	}
	if strings.Contains(string(raw), "`rid.observe`") && !strings.Contains(string(raw), "not a scope") {
		t.Error("the runbook names rid.observe without saying it is not a scope")
	}
}

// E-01: every grantable row is accepted, beside each refusal.
func TestCheckGrantableAcceptsEveryRowAndRefusesTheRest(t *testing.T) {
	for _, s := range catalogue {
		err := CheckGrantable(s.Name, LabClientID)
		var se *ScopeError
		switch {
		case s.Reserved:
			if !errors.As(err, &se) || se.Reason != ReasonScopeReserved {
				t.Errorf("%s: %v", s.Name, err)
			}
		case s.ForeignIssuer:
			if !errors.As(err, &se) || se.Reason != ReasonScopeForeign {
				t.Errorf("%s: %v", s.Name, err)
			}
		default:
			if err != nil {
				t.Errorf("%s refused for lab-01: %v", s.Name, err)
			}
		}
		if s.LabOnly {
			if err := CheckGrantable(s.Name, "cisp-01"); !errors.As(err, &se) || se.Reason != ReasonScopeLabOnly {
				t.Errorf("%s for cisp-01: %v", s.Name, err)
			}
		}
	}
	for _, unknown := range []string{"rid.observe", "session", "admin", "CIS.READ", "cis.read ", "utm.*"} {
		var se *ScopeError
		if err := CheckGrantable(unknown, LabClientID); !errors.As(err, &se) || se.Reason != ReasonScopeUnknown {
			t.Errorf("%q: %v", unknown, err)
		}
	}
	// Every reason renders a message naming the scope.
	for _, r := range []string{ReasonScopeUnknown, ReasonScopeReserved, ReasonScopeForeign, ReasonScopeLabOnly, ReasonScopeNotAllowed, "other"} {
		if msg := (&ScopeError{Scope: "x.y", Reason: r}).Error(); !strings.Contains(msg, `"x.y"`) {
			t.Errorf("%s: %q", r, msg)
		}
	}
}

func TestIssuedHereLeavesOutReservedAndForeign(t *testing.T) {
	got := IssuedHere()
	for _, s := range catalogue {
		if in := slices.Contains(got, s.Name); in == (s.Reserved || s.ForeignIssuer) {
			t.Errorf("%s: in scopes_supported %v", s.Name, in)
		}
	}
}

func TestStandardScopesAreTheF3548AndF3411Rows(t *testing.T) {
	for _, s := range catalogue {
		std := strings.HasPrefix(s.Name, "utm.") || strings.HasPrefix(s.Name, "rid.")
		if s.Standard != std {
			t.Errorf("%s: standard %v", s.Name, s.Standard)
		}
	}
	if HasNational([]string{"utm.strategic_coordination", "rid.display_provider"}) {
		t.Error("standard scopes counted as national")
	}
	if !HasNational([]string{"rid.display_provider", "cis.read"}) || !HasNational([]string{"unknown"}) {
		t.Error("a national or unknown scope not counted as national")
	}
	if _, ok := LookupScope("rid.observe"); ok {
		t.Error("rid.observe is retired (M23)")
	}
}

func TestParseScopeParam(t *testing.T) {
	got, err := ParseScopeParam("  cis.read  cis.read registry.validate ")
	if err != nil || !slices.Equal(got, []string{"cis.read", "registry.validate"}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"a\"b", "a\\b", "é", "a\tb", strings.Repeat("x", 2049), strings.Repeat("s ", 40) + strings.Join(func() []string {
		var o []string
		for i := range 40 {
			o = append(o, "s"+strings.Repeat("x", i))
		}
		return o
	}(), " ")} {
		if _, err := ParseScopeParam(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := ParseScopeParam(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}

func FuzzParseScopeParam(f *testing.F) {
	f.Add("cis.read registry.validate")
	f.Add("\x00 \xff")
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := ParseScopeParam(raw)
		if err != nil {
			return
		}
		if len(got) > MaxScopes {
			t.Fatalf("%d scopes", len(got))
		}
		for _, s := range got {
			if s == "" || strings.ContainsAny(s, " \"\\") {
				t.Fatalf("scope %q", s)
			}
			_ = CheckGrantable(s, "lab-01")
		}
	})
}

func TestQuoteIsBounded(t *testing.T) {
	if q := quote(strings.Repeat("a", 200)); len(q) > 80 || !strings.HasSuffix(q, "...") {
		t.Fatalf("%q", q)
	}
	if q := quote("a\nb"); q != `"a\nb"` {
		t.Fatalf("%q", q)
	}
}
