package cisp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakecisp"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// Audit A-S2, E-01: after a 412 conflict the dataset stops for an
// operator. A publication queued automatically (a certificate change,
// the list repair) is not sent, however often one is queued; the
// operator's publication is the decision, sent against the version the
// conflict showed, and it survives being superseded by an automatic
// one queued before it was sent; once acknowledged, automatic
// publications are sent again.
func TestIntegrationConflictBlocksAutomaticPublications(t *testing.T) {
	ctx := context.Background()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pg.Open(ctx, store.PoolOptions{URL: u, Role: pg.AppRole, ApplicationName: "uspace-authority-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	admin := storetest.Open(t, u)
	authority, _ := rings(t)
	fake, err := fakecisp.New(auth.IssuerConfig{Keys: authority.JWKS()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	client, err := NewClient(ClientConfig{BaseURL: fake.URL(), Tokens: scopeTokens{}, HTTPClient: fake.Client()})
	if err != nil {
		t.Fatal(err)
	}
	st := PG{DB: db, Audit: audit.NewWriter(db)}
	outbox := NewOutbox(schemas(t), authority, st, nil)
	sender := &Sender{Store: st, CISP: client, Signer: authority, Counters: outbox.Counters}
	sys := audit.SystemActor("certificates")
	operator := audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}

	queue := func(byOperator bool, features ...string) int64 {
		t.Helper()
		p, err := outbox.Prepare(DatasetZones, zoneCollection(features...))
		if err != nil {
			t.Fatal(err)
		}
		actor := sys
		if byOperator {
			p.ResolvesConflict, actor = true, operator
		}
		r, err := st.Enqueue(ctx, p, 0, actor)
		if err != nil {
			t.Fatal(err)
		}
		return r.ID
	}
	run := func() {
		t.Helper()
		if _, err := sender.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	state := func(id int64) string {
		t.Helper()
		var s string
		if err := admin.QueryRowContext(ctx, `SELECT state FROM publications WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	puts := func() int {
		n := 0
		for _, r := range fake.Requests() {
			if r.Method == http.MethodPut {
				n++
			}
		}
		return n
	}

	// Another publisher's version is current at the CISP: a conflict.
	if _, err := fake.Publish("zones", []json.RawMessage{json.RawMessage(zoneFeature("OTH001", "SENSITIVE"))},
		zoneCollection(zoneFeature("OTH001", "SENSITIVE")), nil, "publication"); err != nil {
		t.Fatal(err)
	}
	first := queue(false, zoneFeature("TST001", "SENSITIVE"))
	run()
	if state(first) != StateConflict {
		t.Fatalf("first row %s", state(first))
	}
	// Automatic rows after it are not sent.
	sent := puts()
	auto := queue(false, zoneFeature("TST002", "SENSITIVE"))
	run()
	auto2 := queue(false, zoneFeature("TST003", "SENSITIVE"))
	run()
	if puts() != sent || state(auto) != StateSuperseded || state(auto2) != StatePending {
		t.Fatalf("an automatic publication overwrote the CISP's version: %d puts, %s %s", puts()-sent, state(auto), state(auto2))
	}
	if v := fake.Current("zones"); v.Number != 1 || v.Order[0] != "OTH001" {
		t.Fatal("the CISP's version was overwritten")
	}
	// The operator decides; an automatic row queued before the send
	// supersedes it and carries the decision.
	op := queue(true, zoneFeature("TST004", "SENSITIVE"))
	carried := queue(false, zoneFeature("TST005", "SENSITIVE"))
	run()
	if state(op) != StateSuperseded || state(carried) != StateAcknowledged {
		t.Fatalf("the operator's decision was lost: %s %s", state(op), state(carried))
	}
	if v := fake.Current("zones"); v.Number != 2 || v.Order[0] != "TST005" {
		t.Fatalf("CISP %+v", v)
	}
	// Resolved: automatic publications flow again.
	after := queue(false, zoneFeature("TST006", "SENSITIVE"))
	run()
	if state(after) != StateAcknowledged {
		t.Fatalf("after the resolution an automatic row is %s", state(after))
	}
}
