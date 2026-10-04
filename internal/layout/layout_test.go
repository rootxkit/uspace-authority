package layout

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/rootxkit/uspace-authority"

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found from %s", root)
	}
	return root
}

// goList returns, for every package matching pattern, its non-test
// dependencies (or direct imports when deps is false).
func goList(t *testing.T, root, pattern string, deps bool) map[string][]string {
	t.Helper()
	field := "Imports"
	if deps {
		field = "Deps"
	}
	cmd := exec.Command("go", "list", "-f", `{{.ImportPath}} {{join .`+field+` " "}}`, pattern)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v: %s", pattern, err, stderr.String())
	}
	m := map[string][]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Fields(line)
		if len(parts) > 0 {
			m[parts[0]] = parts[1:]
		}
	}
	return m
}

// linksTestOnly reports which binaries link a test-only package.
func linksTestOnly(deps map[string][]string, testOnly string) []string {
	var bad []string
	for pkg, ds := range deps {
		for _, d := range ds {
			if d == testOnly || strings.HasPrefix(d, testOnly+"/") {
				bad = append(bad, pkg+" links "+d)
			}
		}
	}
	return bad
}

// Plan §3 and spec 06 T11: internal/ltest (the test harness) is never
// linked into a binary. The Dockerfile runs the same check.
func TestNoBinaryLinksTheTestHarness(t *testing.T) {
	root := repoRoot(t)
	for _, b := range linksTestOnly(goList(t, root, "./cmd/...", true), module+"/internal/ltest") {
		t.Error(b)
	}
}

func TestTestHarnessCheckCatchesALink(t *testing.T) {
	deps := map[string][]string{module + "/cmd/api": {"fmt", module + "/internal/ltest/fixtures"}}
	if got := linksTestOnly(deps, module+"/internal/ltest"); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}

// foreignImports lists imports of a cmd package that are neither the
// standard library nor this module's internal packages.
func foreignImports(imports map[string][]string) []string {
	var bad []string
	for pkg, imps := range imports {
		for _, imp := range imps {
			first, _, _ := strings.Cut(imp, "/")
			std := !strings.Contains(first, ".")
			if std || strings.HasPrefix(imp, module+"/internal/") {
				continue
			}
			bad = append(bad, pkg+" imports "+imp)
		}
	}
	return bad
}

// Plan §3: cmd/* imports internal/* (and the standard library) only.
func TestCommandsImportInternalOnly(t *testing.T) {
	root := repoRoot(t)
	for _, b := range foreignImports(goList(t, root, "./cmd/...", false)) {
		t.Error(b)
	}
}

func TestForeignImportCheckCatchesAnImport(t *testing.T) {
	got := foreignImports(map[string][]string{module + "/cmd/api": {"net/http", module + "/internal/proc", "github.com/jackc/pgx/v5", module + "/api/gen"}})
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

// stagingHost is assembled so this file does not itself match.
var stagingHost = "chikox" + ".net"

// hostnameHits walks root and lists files naming the staging host
// outside deploy/staging/ (spec 06 §4). docs/ is exempt: the plan and
// the briefs name the predecessor's hosts that A-M5 retires.
func hostnameHits(t *testing.T, root string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch rel {
			case ".git", "deploy/staging", "docs", "node_modules", "web/node_modules", "web/.next":
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(stagingHost)) {
			hits = append(hits, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func TestNoStagingHostnameOutsideDeployStaging(t *testing.T) {
	for _, h := range hostnameHits(t, repoRoot(t)) {
		t.Errorf("%s names the staging host; it belongs under deploy/staging/ only", h)
	}
}

func TestHostnameCheckCatchesAHost(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("deploy/staging/Caddyfile", "uspace-authority."+stagingHost)
	write("docs/PLAN.md", "utm."+stagingHost)
	write("internal/x/x.go", "const host = \"api."+stagingHost+"\"")
	if got := hostnameHits(t, dir); len(got) != 1 || got[0] != "internal/x/x.go" {
		t.Fatalf("got %v", got)
	}
}

// reaches lists the packages of deps (imports or dependencies by
// package) that reach target or a package below it, other than those
// allowed admits.
func reaches(deps map[string][]string, target string, allowed func(pkg string) bool) []string {
	var bad []string
	for pkg, ds := range deps {
		if allowed(pkg) {
			continue
		}
		for _, d := range ds {
			if d == target || strings.HasPrefix(d, target+"/") {
				bad = append(bad, pkg+" reaches "+d)
			}
		}
	}
	return bad
}

const occurrencesPkg = module + "/internal/occurrences"

// ownOccurrences admits internal/occurrences and its own packages.
func ownOccurrences(pkg string) bool {
	return pkg == occurrencesPkg || strings.HasPrefix(pkg, occurrencesPkg+"/")
}

// WP-18: the occurrences schema's pool and queries (the
// authority_occurrences role) are imported by internal/occurrences only.
func TestOnlyOccurrencesImportsItsStore(t *testing.T) {
	for _, b := range reaches(goList(t, repoRoot(t), "./...", false), occurrencesPkg+"/store", ownOccurrences) {
		t.Error(b)
	}
}

// enforcement are the packages whose records an occurrence report must
// never reach (376/2014 Art. 15-16, CLAUDE.md rule 6), and the police
// realm, which never returns one (376/2014 Art. 15(2), 16; WP-19).
var enforcement = []string{module + "/internal/violations", module + "/internal/incidents", module + "/internal/violation",
	module + "/internal/detectsvc", module + "/internal/police"}

// WP-18: violations, incidents and detection never depend on the
// occurrence reports, directly or through another package.
func TestEnforcementNeverDependsOnOccurrences(t *testing.T) {
	root := repoRoot(t)
	for _, pkg := range enforcement {
		deps := goList(t, root, "./"+strings.TrimPrefix(pkg, module+"/"), true)
		if len(deps) != 1 {
			t.Fatalf("go list %s: %v", pkg, deps)
		}
		for _, b := range reaches(deps, occurrencesPkg, func(string) bool { return false }) {
			t.Error(b)
		}
	}
}

// E-01: both checks see an import when there is one.
func TestOccurrenceImportChecksCatchAnImport(t *testing.T) {
	imports := map[string][]string{
		module + "/internal/registry":      {occurrencesPkg + "/store/gen"},
		occurrencesPkg:                     {occurrencesPkg + "/store"},
		module + "/internal/occurrences/x": {occurrencesPkg + "/store"},
		module + "/cmd/api":                {occurrencesPkg},
	}
	if got := reaches(imports, occurrencesPkg+"/store", ownOccurrences); len(got) != 1 || !strings.HasPrefix(got[0], module+"/internal/registry ") {
		t.Fatalf("store check: %v", got)
	}
	deps := map[string][]string{module + "/internal/incidents": {"fmt", occurrencesPkg + "/store"}}
	if got := reaches(deps, occurrencesPkg, func(string) bool { return false }); len(got) != 1 {
		t.Fatalf("dependency check: %v", got)
	}
}
