package authz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// The accounts on PostgreSQL as authority_app: every query, grant and
// constraint the service relies on, through a whole sign-in, the admin
// changes, the session limit and the sweep; the events chain verifies.
func TestIntegrationAccountsOnPostgres(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pg.Open(context.Background(), store.PoolOptions{URL: u, Role: pg.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()
	f := newFixture(t, fxOpts{maxSessions: 2})
	f.svc.Store = PG{DB: db, Audit: audit.NewWriter(db)}
	f.clk.t = time.Now().UTC().Truncate(time.Second)
	admin, err := f.svc.CreateUser(ctx, NewUser{Username: "admin", Password: adminPW, Realm: "console", Roles: []string{"admin"}}, adminActor)
	if err != nil {
		t.Fatal(err)
	}
	f.admin = admin
	if _, err := f.svc.CreateUser(ctx, NewUser{Username: "ADMIN", Password: adminPW, Realm: "console"}, adminActor); err == nil {
		t.Fatal("a duplicate username in another case")
	}
	if _, err := f.svc.Login(ctx, "admin", "wrong password!", ri); err == nil {
		t.Fatal("wrong password accepted")
	}
	first := f.signIn(t, "admin", adminPW)
	id, err := f.identify(first.Token)
	if err != nil || id.Subject != admin.ID {
		t.Fatalf("identify: %+v %v", id, err)
	}
	f.clk.Advance(2 * time.Minute)
	if _, err := f.identify(first.Token); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if s, _ := f.svc.Store.Session(ctx, first.Session.JTI); !s.LastSeenAt.Equal(f.clk.Now()) {
		t.Fatalf("last_seen_at %s, want %s", s.LastSeenAt, f.clk.Now())
	}
	// Session limit 2: the third sign-in ends the first.
	f.signIn(t, "admin", adminPW)
	third := f.signIn(t, "admin", adminPW)
	if _, err := f.identify(first.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("limit: %v", err)
	}
	// Recovery code, MFA reset, roles, status, revocation.
	lr, _ := f.svc.Login(ctx, "admin", adminPW, ri)
	if _, err := f.svc.VerifyMFA(ctx, lr.Token, "", first.RecoveryCodes[0], ri); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	second, _ := f.svc.CreateUser(ctx, NewUser{Username: "second", Password: adminPW, Realm: "console", Roles: []string{"admin"}}, adminActor)
	if _, err := f.svc.SetRoles(ctx, second.ID, []string{"viewer"}, adminActor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetStatus(ctx, second.ID, StatusDisabled, adminActor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetStatus(ctx, admin.ID, StatusDisabled, adminActor); err == nil {
		t.Fatal("the last admin was disabled")
	}
	if n, err := f.svc.RevokeSessions(ctx, admin.ID, adminActor); err != nil || n != 2 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if _, err := f.identify(third.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatalf("revoked: %v", err)
	}
	if _, err := f.svc.ResetMFA(ctx, admin.ID, adminActor); err != nil {
		t.Fatal(err)
	}
	lr, _ = f.svc.Login(ctx, "admin", adminPW, ri)
	if lr.EnrolSecret == "" {
		t.Fatal("no new enrolment after a reset")
	}
	f.clk.Advance(TOTPPeriod)
	code, _ := totp.GenerateCode(lr.EnrolSecret, f.clk.Now())
	if _, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", ri); err != nil {
		t.Fatalf("re-enrolment: %v", err)
	}
	us, enrolled, err := f.svc.ListUsers(ctx)
	if err != nil || len(us) != 2 || !enrolled[0] {
		t.Fatalf("list %v %v %v", us, enrolled, err)
	}
	// Bootstrap refused: accounts exist.
	if created, err := f.svc.Bootstrap(ctx, "root", writeTemp(t, adminPW)); err != nil || created {
		t.Fatalf("bootstrap: %v %v", created, err)
	}
	// Sweep after everything expired.
	f.clk.Advance(13*time.Hour + SweepRetention)
	s, c, err := f.svc.Sweep(ctx)
	if err != nil || s < 5 || c < 5 {
		t.Fatalf("sweep %d %d %v", s, c, err)
	}
	res, err := audit.NewWriter(db).Verify(ctx, audit.MonthStart(time.Now().UTC()))
	if err != nil || res.Broken != nil || res.Rows < 15 {
		t.Fatalf("chain %+v %v", res, err)
	}
	// The TOTP secret is stored sealed.
	sdb := storetest.Open(t, u)
	var plain int
	if err := sdb.QueryRow(`SELECT count(*) FROM user_mfa WHERE position(convert_to($1, 'UTF8') in secret_enc) > 0`, lr.EnrolSecret).Scan(&plain); err != nil || plain != 0 {
		t.Fatalf("plaintext secret stored: %d %v", plain, err)
	}
	// authority_app cannot delete an account.
	if _, err := sdb.Exec(`SET ROLE authority_app; DELETE FROM users`); err == nil {
		t.Fatal("authority_app may delete users")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
