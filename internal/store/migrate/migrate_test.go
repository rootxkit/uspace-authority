package migrate

import (
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func sqlFiles(t *testing.T, tree Tree) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(tree.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return err
		}
		b, err := fs.ReadFile(tree.FS(), path)
		out[path] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTreesAreSeparateWithTheirOwnVersionTables(t *testing.T) {
	if Relational.VersionTable != "goose_db_version_relational" || Timeseries.VersionTable != "goose_db_version_timeseries" {
		t.Fatalf("version tables: %s, %s", Relational.VersionTable, Timeseries.VersionTable)
	}
	if Relational.LockID == Timeseries.LockID {
		t.Fatal("the trees share an advisory lock id")
	}
	for _, tree := range Trees() {
		files := sqlFiles(t, tree)
		if len(files) == 0 {
			t.Fatalf("%s: no migrations embedded", tree.Name)
		}
		for name, body := range files {
			if !strings.Contains(body, "-- +goose Up") || !strings.Contains(body, "-- +goose Down") {
				t.Errorf("%s/%s: every migration has an Up and a Down", tree.Name, name)
			}
		}
	}
}

var createdTable = regexp.MustCompile(`(?i)create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?("?[a-z_][a-z0-9_."]*)`)

func tablesOf(files map[string]string) map[string]bool {
	out := map[string]bool{}
	for _, body := range files {
		for _, m := range createdTable.FindAllStringSubmatch(body, -1) {
			name := strings.ReplaceAll(m[1], `"`, "")
			if i := strings.LastIndex(name, "."); i >= 0 {
				name = name[i+1:]
			}
			out[strings.ToLower(name)] = true
		}
	}
	return out
}

// crossReferences lists, for each file of one tree, the tables of the
// other tree it names.
func crossReferences(own, other map[string]string) []string {
	var hits []string
	for table := range tablesOf(other) {
		word := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(table) + `\b`)
		for name, body := range own {
			if word.MatchString(body) {
				hits = append(hits, name+" names "+table)
			}
		}
	}
	return hits
}

// CLAUDE.md rule 10: no file of one tree names a table of the other.
func TestNoFileNamesATableOfTheOtherTree(t *testing.T) {
	rel, ts := sqlFiles(t, Relational), sqlFiles(t, Timeseries)
	for _, h := range append(crossReferences(rel, ts), crossReferences(ts, rel)...) {
		t.Errorf("cross-tree reference: %s", h)
	}
}

// E-01: the check above must be able to fail.
func TestCrossTreeCheckCatchesAReference(t *testing.T) {
	rel := map[string]string{"00002_events.sql": "CREATE TABLE IF NOT EXISTS events (id bigserial);"}
	ts := map[string]string{"00002_tracks.sql": "CREATE TABLE tracks (id bigint); INSERT INTO tracks SELECT id FROM events;"}
	hits := crossReferences(ts, rel)
	if len(hits) != 1 || hits[0] != "00002_tracks.sql names events" {
		t.Fatalf("got %v", hits)
	}
	if got := tablesOf(map[string]string{"x": `create unlogged table "occurrences".occurrence_reports (x int)`}); !got["occurrence_reports"] {
		t.Fatalf("schema-qualified table not found: %v", got)
	}
}

func TestLatestIsTheNewestEmbeddedMigration(t *testing.T) {
	tree := Tree{Name: "fixture", fsys: fstest.MapFS{
		"00001_init.sql": {}, "00003_c.sql": {}, "00002_b.sql": {}, "notes.txt": {},
	}}
	if got, err := Latest(tree); err != nil || got != 3 {
		t.Fatalf("got %d %v, want 3", got, err)
	}
	for _, tree := range Trees() {
		files := sqlFiles(t, tree)
		got, err := Latest(tree)
		if err != nil || got < 1 || got > int64(len(files)) {
			t.Errorf("%s: latest %d of %d files: %v", tree.Name, got, len(files), err)
		}
	}
}

func TestLatestRefusesAFileWithoutAVersion(t *testing.T) {
	bad := Tree{Name: "bad", fsys: fstest.MapFS{"00001_init.sql": {}, "init.sql": {}}}
	if _, err := Latest(bad); err == nil || !strings.Contains(err.Error(), "init.sql") {
		t.Fatalf("got %v", err)
	}
	empty := Tree{Name: "empty", fsys: fstest.MapFS{"README": {}}}
	if _, err := Latest(empty); err == nil {
		t.Fatal("an empty tree has a latest version")
	}
}

// TestEachVersionIsOneFileWithNoGap holds every tree to versions 1..n,
// each named by exactly one file: two branches that each took the next
// number (WP-26 and WP-27 both wrote relational 00024) meet as a
// duplicate goose refuses, and a gap leaves a version that lands later
// unapplied on a database already past it.
func TestEachVersionIsOneFileWithNoGap(t *testing.T) {
	for _, tree := range Trees() {
		byVersion := map[int64][]string{}
		for path := range sqlFiles(t, tree) {
			digits, _, _ := strings.Cut(path, "_")
			v, err := strconv.ParseInt(digits, 10, 64)
			if err != nil {
				t.Fatalf("%s: %s: %v", tree.Name, path, err)
			}
			byVersion[v] = append(byVersion[v], path)
		}
		for v := int64(1); v <= int64(len(byVersion)); v++ {
			if n := len(byVersion[v]); n != 1 {
				t.Errorf("%s: version %d named by %d files: %v", tree.Name, v, n, byVersion[v])
			}
		}
		if latest, err := Latest(tree); err != nil || latest != int64(len(byVersion)) {
			t.Errorf("%s: latest %d with %d versions: %v", tree.Name, latest, len(byVersion), err)
		}
	}
}
