package regimport

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

type itest struct {
	imp     *Parts
	reg     *registry.Parts
	pgAdmin *sql.DB
	tsAdmin *sql.DB
	db      *pg.DB
}

func writeKey(t *testing.T, dir, name string) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(k[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newIntegration is the import on the real databases: the relational
// one as authority_app, the projection as authority_ts_projector, both
// migrated from scratch, and the synthetic rules file.
func newIntegration(t *testing.T, url string) *itest {
	t.Helper()
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	db, err := pg.Open(ctx, store.PoolOptions{URL: pgURL, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	dir := t.TempDir()
	reg, err := registry.Assemble(ctx, registry.Setup{
		DB: db, Audit: audit.NewWriter(db), PIIKeyID: "pii-test", PIIKeyFile: writeKey(t, dir, "pii.key"),
		HashKeyFile: writeKey(t, dir, "hash.key"), TSURL: tsURL, TSMaxConns: 2,
		Pattern: func() (string, bool) { return regnum.DefaultPattern, true }, MTOMBandsG: []int{250, 900, 4000, 25000},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	imp, err := Assemble(Setup{DB: db, Registry: reg.Service, RulesFile: "testdata/rules.json", URL: url, Timeout: 5 * time.Second,
		MaxBytes: 1 << 20, MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	if imp.Job != nil {
		imp.Job.Fetcher.Client = NewClient(5 * time.Second)
	}
	return &itest{imp: imp, reg: reg, pgAdmin: storetest.Open(t, pgURL), tsAdmin: storetest.Open(t, tsURL), db: db}
}

func (it *itest) count(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (it *itest) run(t *testing.T, kind, file string, dry bool) Report {
	t.Helper()
	rep, err := it.imp.Service.Run(context.Background(), Request{Kind: kind, Format: FormatCSV, Body: readFile(t, file), DryRun: dry, Origin: OriginUpload},
		audit.Actor{Type: audit.ActorUser, ID: "registrar-1", Realm: audit.RealmConsole})
	if err != nil {
		t.Fatalf("%s %s: %v", kind, file, err)
	}
	return rep
}

// The brief's integration: a synthetic export (GEOTEST numbers, TEST
// serials) imported under the rules file; the dry run changes nothing;
// the import writes the registry, the change feed, the projection and
// the ledger; a re-import is idempotent; every import is audited and
// the chain still verifies.
func TestIntegrationImportSyntheticExport(t *testing.T) {
	it := newIntegration(t, "")
	dry := it.run(t, "operators", "operators.csv", true)
	if !dry.DryRun || dry.Created != 2 || len(dry.Problems) != 0 {
		t.Fatalf("dry run: %+v", dry)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM uas_operators`); n != 0 {
		t.Fatalf("a dry run wrote %d operators", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_imports`); n != 0 {
		t.Fatalf("a dry run wrote %d ledger rows", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE event_type = 'registry_import_dry_run'`); n != 1 {
		t.Fatalf("dry run events %d", n)
	}

	ops := it.run(t, "operators", "operators.csv", false)
	uas := it.run(t, "uas", "uas.csv", false)
	if !ops.Applied() || ops.Created != 2 || !uas.Applied() || uas.Created != 2 {
		t.Fatalf("import: %+v / %+v", ops, uas)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM uas_operators WHERE source = 'uas_gov_ge_import' AND source_ref LIKE 'TEST-OP-%'`); n != 2 {
		t.Fatalf("operators %d", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM uas WHERE source = 'uas_gov_ge_import' AND source_ref LIKE 'TEST-UAS-%'`); n != 2 {
		t.Fatalf("aircraft %d", n)
	}
	// The secret suffix of record 1 is stored as the registry's hash only.
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM uas_operators WHERE registration_number_public = 'GEOTEST00000001' AND secret_part_hash IS NOT NULL`); n != 1 {
		t.Fatalf("secret part %d", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM uas_operators WHERE registration_number_public LIKE '%-%'`); n != 0 {
		t.Fatal("a secret part was registered")
	}
	if n := it.count(t, it.tsAdmin, `SELECT count(*) FROM proj_registry_uas WHERE in_registry`); n != 2 {
		t.Fatalf("projected aircraft %d", n)
	}
	if n := it.count(t, it.tsAdmin, `SELECT count(*) FROM proj_registry_operators WHERE status = 'suspended'`); n != 1 {
		t.Fatalf("projected suspended operators %d", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_status_changes`); n != 4 {
		t.Fatalf("change feed %d", n)
	}

	// Idempotent: the same files again change nothing.
	again := it.run(t, "operators", "operators.csv", false)
	againUAS := it.run(t, "uas", "uas.csv", false)
	if again.Unchanged != 2 || againUAS.Unchanged != 2 || again.Created+again.Updated+againUAS.Created+againUAS.Updated != 0 {
		t.Fatalf("re-import: %+v / %+v", again, againUAS)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM uas_operators`); n != 2 {
		t.Fatalf("operators after the re-import %d", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_status_changes`); n != 4 {
		t.Fatalf("change feed after the re-import %d", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_imports WHERE outcome = 'applied'`); n != 4 {
		t.Fatalf("ledger %d", n)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE event_type = 'registry_imported'`); n != 4 {
		t.Fatalf("import events %d", n)
	}
	// Nothing personal in clear in the events of the import.
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM events WHERE payload::text LIKE '%example.test%' OR payload::text LIKE '%Test Person%'`); n != 0 {
		t.Fatalf("%d events hold personal data", n)
	}

	// A refused import writes nothing and is in the ledger as refused.
	bad := strings.Replace(string(readFile(t, "operators.csv")), "Test Person", "", 1)
	rep, err := it.imp.Service.Run(context.Background(), Request{Kind: "operators", Format: FormatCSV, Body: []byte(bad), Origin: OriginUpload},
		audit.Actor{Type: audit.ActorUser, ID: "registrar-1", Realm: audit.RealmConsole})
	if err != nil || rep.Applied() || len(rep.Problems) == 0 || rep.Problems[0].Field != "records[1].full_name" {
		t.Fatalf("refused: %+v %v", rep, err)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_imports WHERE outcome = 'refused' AND problems > 0`); n != 1 {
		t.Fatalf("refused ledger %d", n)
	}
	verifyChain(t, it)
}

// verifyChain checks the audit hash chain over everything written.
func verifyChain(t *testing.T, it *itest) {
	t.Helper()
	rep, err := audit.NewWriter(it.db).Verify(context.Background(), time.Now().UTC())
	if err != nil {
		t.Fatalf("chain: %v", err)
	}
	if rep.Broken != nil || rep.Rows == 0 {
		t.Fatalf("chain: %+v %+v", rep, rep.Broken)
	}
}

// The re-import from the agreed URL imports the export once and skips
// it while it does not change, also from a second instance (the ledger
// is in the database).
func TestIntegrationReimportJob(t *testing.T) {
	srv := &exportServer{body: map[string]string{}}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	it := newIntegration(t, ts.URL+"/export/{kind}.csv")
	srv.body["operators"] = string(readFile(t, "operators.csv"))
	srv.body["uas"] = string(readFile(t, "uas.csv"))
	out, err := it.imp.Job.RunOnce(context.Background())
	if err != nil || !out[0].Applied || !out[1].Applied {
		t.Fatalf("first: %+v %v", out, err)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM uas`); n != 2 {
		t.Fatalf("aircraft %d", n)
	}
	// A second instance on the same database: nothing to run.
	second, err := Assemble(Setup{DB: it.db, Registry: it.reg.Service, RulesFile: "testdata/rules.json", URL: ts.URL + "/export/{kind}.csv",
		Timeout: 5 * time.Second, MaxBytes: 1 << 20, MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	out, err = second.Job.RunOnce(context.Background())
	if err != nil || !out[0].Unchanged || !out[1].Unchanged {
		t.Fatalf("second instance: %+v %v", out, err)
	}
	if n := it.count(t, it.pgAdmin, `SELECT count(*) FROM registry_imports WHERE origin = 'fetch'`); n != 2 {
		t.Fatalf("fetch ledger %d", n)
	}
	srv.code = http.StatusServiceUnavailable
	out, _ = second.Job.RunOnce(context.Background())
	if out[0].Err == nil || second.Counters.Get(CounterFetchFailed) != 2 {
		t.Fatalf("failure: %+v", out)
	}
}
