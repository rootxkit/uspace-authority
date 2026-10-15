package overview

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// rig is a migrated relational database, the superuser handle that
// seeds it, and the overview served from it as api's role.
type rig struct {
	sql *sql.DB
	db  *pgstore.DB
}

func newRig(t *testing.T) *rig {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(context.Background(), store.PoolOptions{URL: u, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &rig{sql: storetest.Open(t, u), db: db}
}

func (r *rig) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if _, err := r.sql.Exec(q, args...); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func hex32(prefix string, i int) string { return fmt.Sprintf("%s%0*d", prefix, 32-len(prefix), i) }

// seedRegistry writes operators, UAS and pilots with the statuses given;
// the encrypted columns hold placeholder bytes (nothing reads them here).
func (r *rig) seedRegistry(t *testing.T, operators, uas, pilots []string) {
	t.Helper()
	opID := ""
	for i, s := range operators {
		id := hex32("a", i)
		if opID == "" {
			opID = id
		}
		r.exec(t, `INSERT INTO uas_operators (id, operator_type, registration_number_public, registration_number_key, pii_key_id,
			legal_name_enc, legal_identification_number_enc, postal_address_enc, contact_email_enc, contact_phone_enc,
			status, valid_from, valid_until, source, registry_version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, 'legal', $2, $2, 'test-key', '\x00', '\x00', '\x00', '\x00', '\x00',
			$3, now() - interval '1 day', now() + interval '1 year', 'manual', $4, now(), 'test', now(), 'test')`,
			id, fmt.Sprintf("GEOTEST%08d", i), s, i+1)
	}
	for i, s := range uas {
		r.exec(t, `INSERT INTO uas (id, operator_id, serial, serial_fold, manufacturer_code, rid_capability, status,
			registered_at, registry_version, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $3, 'TEST', 'direct', $4, now(), $5, 'test', now(), 'test')`,
			hex32("b", i), opID, fmt.Sprintf("TEST%08d", i), s, 100+i)
	}
	for i, s := range pilots {
		r.exec(t, `INSERT INTO remote_pilots (id, person_ref_hash, person_ref_last4, pii_key_id, name_enc, status,
			registry_version, created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, '0000', 'test-key', '\x00', $3, $4, now(), 'test', now(), 'test')`,
			hex32("c", i), strings.Repeat("0", 63)+fmt.Sprint(i), s, 200+i)
	}
}

// zone writes one version of a geo-zone of dataset with state.
func (r *rig) zone(t *testing.T, dataset, identifier string, version int, state string) {
	t.Helper()
	var published any
	if state == "published" {
		published = version
	}
	r.exec(t, `INSERT INTO geo_zones (dataset, identifier, zone_version, state, country, type, variant, geometry_type,
		layers, zone_authority, feature, valid_from, valid_to, published_version, created_by)
		VALUES ($1, $2, $3, $4, 'GEO', CASE WHEN $1 = 'uspace_airspace' THEN 'USPACE' ELSE 'PROHIBITED' END, 'COMMON', 'Polygon',
		'[]', '{}', '{}', now(), now() + interval '1 year', $5, 'test')`,
		dataset, identifier, version, state, published)
}

// certificate writes a USSP certificate with its client; how sets the
// facts its status is derived from.
func (r *rig) certificate(t *testing.T, code, how string) {
	t.Helper()
	client := "ussp-" + code + "-01"
	r.exec(t, `INSERT INTO oauth_clients (client_id, system, scopes, auth_method, secret_hash, created_at, created_by, updated_at, updated_by)
		VALUES ($1, 'ussp', '{registry.validate}', 'client_secret_post', 'x', now(), 'test', now(), 'test')`, client)
	operations, started, suspended, ended := "not_started", "NULL", "false", "NULL"
	switch how {
	case "operating":
		operations, started = "operating", "now()"
	case "suspended":
		operations, started, suspended = "operating", "now()", "true"
	case "revoked":
		ended = "'revoked'"
	}
	r.exec(t, fmt.Sprintf(`INSERT INTO certificates (id, holder, holder_name, code, client_id, base_url, terms_url, services,
		issued_at, valid_until, operations, operations_started_at, suspended, ended, ended_at,
		status_changed_at, status_changed_by, lapse_unused_after_months, lapse_ceased_after_months, row_version,
		created_at, created_by, updated_at, updated_by)
		VALUES ($1, 'ussp', 'USSP ' || $2, $2, $3, 'https://ussp.example.test', 'https://ussp.example.test/terms', '{network_identification}',
		now(), now() + interval '2 years', '%s', %s, %s, %s, CASE WHEN %s IS NULL THEN NULL ELSE now() END,
		now(), 'test', 6, 12, 1, now(), 'test', now(), 'test')`, operations, started, suspended, ended, ended),
		hex32("d", len(code)*100+int(code[len(code)-1])), code, client)
}

// event writes one events row at now() + offset (a placeholder chain:
// nothing verifies it here).
func (r *rig) event(t *testing.T, offset string) {
	t.Helper()
	r.exec(t, `SELECT events_ensure_partition(now() + $1::interval)`, offset)
	r.exec(t, `INSERT INTO events (ts, actor_type, actor_id, entity_type, event_type, prev_hash, hash)
		VALUES (now() + $1::interval, 'system', 'test', 'test', 'test_event', repeat('0', 64), repeat('0', 64))`, offset)
}

// The four figures from a real database through api's role, behind the
// real access rules: an admitted role reads the counts the rows give,
// a role outside the domain is 403 and no session is 401.
func TestIntegrationOverviewCountsWhatTheDatabaseHolds(t *testing.T) {
	r := newRig(t)
	srv := server(t, PG{DB: r.db})

	// Before anything is written every figure is a counted zero (the pair below).
	_, empty := get(t, srv, "viewer", "/v1/overview/registry")
	if num(t, empty, "operators", "total") != 0 || num(t, empty, "uas", "total") != 0 || num(t, empty, "pilots", "total") != 0 {
		t.Fatalf("empty registry: %v", empty)
	}

	r.seedRegistry(t,
		[]string{"active", "active", "active", "suspended", "revoked", "expired"},
		[]string{"active", "active", "suspended"},
		[]string{"active", "expired"})
	// Airspace U1 has a published v1 and a newer draft v2: its newest is the draft.
	r.zone(t, "uspace_airspace", "U1", 1, "published")
	r.zone(t, "uspace_airspace", "U1", 2, "draft")
	r.zone(t, "uspace_airspace", "U2", 1, "published")
	r.zone(t, "uspace_airspace", "U3", 1, "approved")
	// A geo-zone is not a U-space airspace.
	r.zone(t, "zones", "Z1", 1, "published")
	r.certificate(t, "TSTA", "issued")
	r.certificate(t, "TSTB", "operating")
	r.certificate(t, "TSTC", "suspended")
	r.certificate(t, "TSTD", "revoked")
	// Two rows inside the window; one a day and an hour old and one from
	// the future (another clock) outside it.
	r.event(t, "-1 hour")
	r.event(t, "-23 hours")
	r.event(t, "-25 hours")
	r.event(t, "1 hour")

	code, reg := get(t, srv, "registrar", "/v1/overview/registry")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, reg)
	}
	for _, c := range []struct {
		entity, status string
		n              float64
	}{
		{"operators", "active", 3}, {"operators", "suspended", 1}, {"operators", "revoked", 1}, {"operators", "expired", 1}, {"operators", "total", 6},
		{"uas", "active", 2}, {"uas", "suspended", 1}, {"uas", "revoked", 0}, {"uas", "total", 3},
		{"pilots", "active", 1}, {"pilots", "expired", 1}, {"pilots", "total", 2},
	} {
		if got := num(t, reg, c.entity, c.status); got != c.n {
			t.Errorf("%s.%s = %v, want %v", c.entity, c.status, got, c.n)
		}
	}

	_, usp := get(t, srv, "admin", "/v1/overview/uspace")
	for k, v := range map[string]float64{"draft": 1, "approved": 1, "published": 1, "superseded": 0, "total": 3} {
		if got := num(t, usp, k); got != v {
			t.Errorf("uspace.%s = %v, want %v", k, got, v)
		}
	}
	_, crt := get(t, srv, "admin", "/v1/overview/certificates")
	for k, v := range map[string]float64{"issued": 1, "operating": 1, "suspended": 1, "revoked": 1, "lapsed": 0, "total": 4} {
		if got := num(t, crt, k); got != v {
			t.Errorf("certificates.%s = %v, want %v", k, got, v)
		}
	}
	_, aud := get(t, srv, "auditor", "/v1/overview/audit")
	if num(t, aud, "events") != 2 || aud["more"] != false || num(t, aud, "window_s") != 86400 {
		t.Errorf("audit: %v", aud)
	}

	// The access rules on the real store: outside the domain 403, no session 401.
	for path, as := range map[string]string{
		"/v1/overview/registry":     "admin",
		"/v1/overview/uspace":       "viewer",
		"/v1/overview/certificates": "auditor",
		"/v1/overview/audit":        "inspector",
	} {
		if code, body := get(t, srv, as, path); code != http.StatusForbidden {
			t.Errorf("%s as %s: %d %v", path, as, code, body)
		}
		if code, body := get(t, srv, "police", path); code != http.StatusForbidden {
			t.Errorf("%s as police: %d %v", path, code, body)
		}
		if code, body := get(t, srv, "", path); code != http.StatusUnauthorized {
			t.Errorf("%s without a session: %d %v", path, code, body)
		}
	}
	// Reading a figure wrote no events row: the count is still two.
	if _, aud := get(t, srv, "admin", "/v1/overview/audit"); num(t, aud, "events") != 2 {
		t.Errorf("audit after the reads: %v", aud)
	}
}

// E-10: the audit count over its bound stops at AuditMaxRows and says
// more; its pair (more false below the bound) is the test above.
func TestIntegrationAuditCountStopsAtItsBound(t *testing.T) {
	r := newRig(t)
	srv := server(t, PG{DB: r.db})
	r.exec(t, `SELECT events_ensure_partition(now()), events_ensure_partition(now() - interval '1 hour')`)
	r.exec(t, `INSERT INTO events (ts, actor_type, actor_id, entity_type, event_type, prev_hash, hash)
		SELECT now() - interval '1 hour' + g * interval '1 millisecond', 'system', 'test', 'test', 'test_event', repeat('0', 64), repeat('0', 64)
		FROM generate_series(1, $1::int) g`, AuditMaxRows+10)
	_, aud := get(t, srv, "admin", "/v1/overview/audit")
	if num(t, aud, "events") != AuditMaxRows || aud["more"] != true {
		t.Fatalf("over the bound: %v", aud)
	}
}

// The audit count is index-backed: with the planner kept off sequential
// scans it reads events_ts_idx's partitions, so the count never needs a
// scan of a month of the hot table (migration 00027).
func TestIntegrationAuditCountUsesTheTimeIndex(t *testing.T) {
	r := newRig(t)
	r.event(t, "-1 hour")
	tx, err := r.sql.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := tx.Query(`EXPLAIN SELECT count(*) FROM (SELECT 1 FROM events
		WHERE ts > now() - make_interval(secs => 86400) AND ts <= now() LIMIT 100000) recent`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	p := plan.String()
	// A partition's copy of events_ts_idx is named events_<YYYY>_<MM>_ts_idx;
	// events_<YYYY>_<MM>_actor_id_ts_idx leads with actor_id and is a scan
	// of the whole index.
	if strings.Contains(p, "Seq Scan") || !regexp.MustCompile(`using events_[0-9]{4}_[0-9]{2}_ts_idx `).MatchString(p) {
		t.Fatalf("the window is not read through events_ts_idx:\n%s", p)
	}
}
