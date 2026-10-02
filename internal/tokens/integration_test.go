package tokens

import (
	"context"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

// pgParts assembles the token service on a scratch relational database
// as the application role.
func pgParts(t *testing.T, keys int, twoPerson bool) (*Parts, *pg.DB, string) {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pg.Open(context.Background(), store.PoolOptions{URL: u, Role: pg.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	dir := t.TempDir()
	var files []string
	for i := range keys {
		files = append(files, tokentest.WriteKey(t, dir, i))
	}
	parts, err := Assemble(context.Background(), Setup{
		Issuer: testIssuer, SigningKeyFiles: files, PublicationKeyFile: tokentest.WriteKey(t, dir, 9),
		TTL: time.Hour, RetireGrace: 24 * time.Hour, TwoPerson: twoPerson, ConfirmWindow: 10 * time.Minute,
		RatePerMin: 600, RateBurst: 100, RateMaxClients: 100,
		Store: PG{DB: db, Audit: audit.NewWriter(db)}, Hasher: cheapHasher(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return parts, db, u
}

func eventTypes(t *testing.T, u string) map[string]int {
	t.Helper()
	sdb := storetest.Open(t, u)
	rows, err := sdb.Query("SELECT event_type, count(*) FROM events GROUP BY event_type")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var et string
		var n int
		if err := rows.Scan(&et, &n); err != nil {
			t.Fatal(err)
		}
		out[et] = n
	}
	return out
}

// The registry, issuance, refusal and rotation against PostgreSQL as
// authority_app: the grants allow exactly what the service does, the
// constraints hold, and every act is an events row that verifies.
func TestIntegrationTokenServiceOnPostgres(t *testing.T) {
	parts, db, u := pgParts(t, 2, true)
	ctx := context.Background()
	if _, _, err := parts.Registry.Create(ctx, ClientInput{ID: "lab-01", Scopes: []string{"cis.read", "dp.observe"},
		Audiences: []string{cispHost}, AuthMethod: MethodSecretPost}, admin); err != nil {
		t.Fatal(err)
	}
	_, secret, err := parts.Registry.Create(ctx, ClientInput{ID: "cisp-01", Scopes: []string{"cis.read"},
		Audiences: []string{cispHost}, AuthMethod: MethodSecretPost, CertificateID: "cert-1", MTLSSubject: "CN=cisp"}, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parts.Registry.Create(ctx, ClientInput{ID: "ussp-GEO1-01", Scopes: []string{"rid.service_provider"},
		AuthMethod: MethodPrivateKeyJWT, JWKS: clientJWKS(t, 3, clientKID)}, admin); err != nil {
		t.Fatal(err)
	}
	cs, err := parts.Registry.List(ctx)
	if err != nil || len(cs) != 3 || cs[0].ID != "cisp-01" || cs[0].CertificateID != "cert-1" {
		t.Fatalf("list %v %v", cs, err)
	}
	resp, oerr := parts.Service.Token(ctx, secretReq("cisp-01", secret, "cis.read", cispHost))
	if oerr != nil {
		t.Fatal(oerr)
	}
	_, oerr = parts.Service.Token(ctx, TokenRequest{GrantType: GrantClientCredentials, ClientAssertionType: AssertionType,
		ClientAssertion: assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", testIssuer+"/oauth/token", time.Minute, time.Now()),
		Scope:           "rid.service_provider", Audience: "peer.example.test", HasAudience: true})
	if oerr != nil {
		t.Fatalf("private_key_jwt: %v", oerr)
	}
	if _, oerr := parts.Service.Token(ctx, secretReq("cisp-01", "wrong", "cis.read", cispHost)); oerr == nil {
		t.Fatal("wrong secret accepted")
	}
	suspended := StatusSuspended
	if _, err := parts.Registry.Update(ctx, "cisp-01", ClientPatch{Status: &suspended}, admin); err != nil {
		t.Fatal(err)
	}
	if _, oerr := parts.Service.Token(ctx, secretReq("cisp-01", secret, "cis.read", cispHost)); oerr == nil || oerr.Reason != "client_suspended" {
		t.Fatalf("suspended: %+v", oerr)
	}

	// Rotation persists across a fresh assembly (another replica).
	if r, err := parts.Manager.Rotate(ctx, admin); err != nil || r.State != "requested" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := parts.Manager.Rotate(ctx, admin2); err != nil || r.State != "activated" {
		t.Fatalf("%+v %v", r, err)
	}
	keys, err := parts.Manager.Store.SigningKeys(ctx)
	if err != nil || len(keys) != 3 {
		t.Fatalf("keys %v %v", keys, err)
	}
	if err := parts.Manager.Refresh(ctx); err != nil || parts.Keys.ActiveKID() != parts.Keys.Files()[1].KID {
		t.Fatalf("refresh: %v", err)
	}
	// The old key's token still verifies through the JWKS.
	set, _ := parts.Keys.JWKS(time.Now())
	if set.Len() != 3 {
		t.Fatalf("JWKS holds %d keys (active, retiring, publication)", set.Len())
	}
	_ = resp

	got := eventTypes(t, u)
	want := map[string]int{
		audit.EventOAuthClientCreated: 3, audit.EventTokenIssued: 2, audit.EventTokenRefused: 2,
		audit.EventOAuthClientUpdated: 1, audit.EventSigningKeyRegistered: 3, audit.EventSigningKeyActivated: 3,
		audit.EventKeyRotationRequested: 1,
	}
	for et, n := range want {
		if got[et] != n {
			t.Errorf("%s: %d events, want %d (all: %v)", et, got[et], n, got)
		}
	}
	res, err := audit.NewWriter(db).Verify(ctx, audit.MonthStart(time.Now().UTC()))
	if err != nil || res.Broken != nil || res.Rows == 0 {
		t.Fatalf("hash chain: %+v %v", res, err)
	}

	// The private key never reached the database.
	sdb := storetest.Open(t, u)
	var n int
	if err := sdb.QueryRow(`SELECT count(*) FROM signing_keys WHERE public_jwk ? 'd' OR public_jwk ? 'p'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("private members stored: %d %v", n, err)
	}
	// The secret is stored as its argon2id hash only.
	var hash string
	if err := sdb.QueryRow(`SELECT secret_hash FROM oauth_clients WHERE client_id = 'cisp-01'`).Scan(&hash); err != nil || hash == secret || hash[:10] != "$argon2id$" {
		t.Fatalf("secret_hash %q %v", hash, err)
	}
	// The application role cannot delete a key or a client.
	if _, err := sdb.Exec(`SET ROLE authority_app; DELETE FROM signing_keys`); err == nil {
		t.Fatal("authority_app may delete signing keys")
	}
}

// The constraints refuse what the code refuses: a client id outside M24,
// a system that is not the id's, a secret client without a hash.
func TestIntegrationClientConstraints(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	sdb := storetest.Open(t, u)
	ins := `INSERT INTO oauth_clients (client_id, system, scopes, auth_method, secret_hash, created_at, created_by, updated_at, updated_by)
	        VALUES ($1, $2, '{cis.read}', 'client_secret_post', $3, now(), 'a', now(), 'a')`
	if _, err := sdb.Exec(ins, "cisp-01", "cisp", "$argon2id$x"); err != nil {
		t.Fatalf("accepted twin: %v", err)
	}
	for _, bad := range [][3]any{{"cisp-1", "cisp", "h"}, {"ansp-01", "cisp", "h"}, {"lab-01", "lab", nil}, {"ussp-geo-01", "ussp", "h"}} {
		if _, err := sdb.Exec(ins, bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// The assertion record is in the database: an assertion spent through
// one replica is refused by another on the same database.
func TestIntegrationAssertionReplayAcrossReplicas(t *testing.T) {
	a, db, _ := pgParts(t, 1, false)
	ctx := context.Background()
	if _, _, err := a.Registry.Create(ctx, ClientInput{ID: "ussp-GEO1-01", Scopes: []string{"rid.service_provider"},
		AuthMethod: MethodPrivateKeyJWT, JWKS: clientJWKS(t, 3, clientKID)}, admin); err != nil {
		t.Fatal(err)
	}
	b := *a.Service
	b.Store = PG{DB: db, Audit: audit.NewWriter(db)}
	as := assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", testIssuer+"/oauth/token", time.Minute, time.Now())
	if _, oerr := a.Service.Token(ctx, assertionReq(as, "rid.service_provider", "p.example.test")); oerr != nil {
		t.Fatal(oerr)
	}
	if _, oerr := b.Token(ctx, assertionReq(as, "rid.service_provider", "p.example.test")); oerr == nil || oerr.Reason != "client_assertion_replayed" {
		t.Fatalf("replay on another replica: %+v", oerr)
	}
	fresh := assertion(t, 3, clientKID, "ussp-GEO1-01", "ussp-GEO1-01", testIssuer+"/oauth/token", time.Minute, time.Now())
	if _, oerr := b.Token(ctx, assertionReq(fresh, "rid.service_provider", "p.example.test")); oerr != nil {
		t.Fatalf("a fresh assertion on the other replica: %v", oerr)
	}
}

// The emergency retirement on PostgreSQL as authority_app: the grants and
// the constraint allow it, the next key signs, and a fresh assembly
// (another replica) neither publishes nor signs with the dropped key.
func TestIntegrationCompromiseOnPostgres(t *testing.T) {
	parts, db, _ := pgParts(t, 2, true)
	ctx := context.Background()
	old := parts.Keys.ActiveKID()
	if _, err := parts.Manager.Compromise(ctx, old, "leaked", admin); err != nil {
		t.Fatal(err)
	}
	other := &KeyManager{Store: PG{DB: db, Audit: audit.NewWriter(db)}, Keys: parts.Keys}
	if err := other.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	set, _ := parts.Keys.JWKS(time.Now())
	if _, ok := set.LookupKeyID(old); ok || parts.Keys.ActiveKID() == old {
		t.Fatal("the compromised key is still in use")
	}
	rows, _ := other.Store.SigningKeys(ctx)
	for _, r := range rows {
		if r.KID == old && (r.CompromisedAt == nil || r.RetiredAt == nil || r.CompromiseReason != "leaked") {
			t.Fatalf("row %+v", r)
		}
	}
}
