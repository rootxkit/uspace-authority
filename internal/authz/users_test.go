package authz

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

func fieldNames(err error) []string {
	var out []string
	var walk func(error)
	walk = func(e error) {
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range j.Unwrap() {
				walk(x)
			}
			return
		}
		var fe *core.FieldError
		if errors.As(e, &fe) {
			out = append(out, fe.Field)
		}
	}
	if err != nil {
		walk(err)
	}
	return out
}

func TestCreateUserValidatesEveryField(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	_, err := f.svc.CreateUser(ctx, NewUser{Username: "x", Password: "short", Realm: "portal", Roles: []string{"root", "viewer", "viewer"},
		DisplayName: strings.Repeat("n", MaxDisplayName+1)}, adminActor)
	got := fieldNames(err)
	for _, want := range []string{"username", "password", "realm", "roles[0]", "roles[2]", "display_name"} {
		if !slices.Contains(got, want) {
			t.Errorf("no error on %s: %v", want, got)
		}
	}
	if _, err := f.svc.CreateUser(ctx, NewUser{Username: "x2y", Password: strings.Repeat("p", 1025), Realm: "console"}, adminActor); !slices.Contains(fieldNames(err), "password") {
		t.Fatalf("overlong password: %v", err)
	}
	if _, err := f.svc.CreateUser(ctx, NewUser{Username: "Admin", Password: adminPW, Realm: "console"}, adminActor); problemOf(t, err).Status != http.StatusConflict {
		t.Fatalf("taken username: %v", err)
	}
	u, err := f.svc.CreateUser(ctx, NewUser{Username: " Officer.One@Example ", Password: adminPW, Realm: "police",
		Agency: "TEST-POLICE", IPAllow: []string{"192.0.2.0/24"}}, adminActor)
	if err != nil || u.Username != "officer.one@example" || u.Roles == nil || u.Realm != "police" {
		t.Fatalf("accepted twin: %+v %v", u, err)
	}
	if ev := f.st.eventsOf(audit.EventUserCreated); len(ev) != 2 {
		t.Fatalf("%d creation events", len(ev))
	}
	if strings.Contains(f.st.passwords[u.ID], adminPW) || !strings.HasPrefix(f.st.passwords[u.ID], "$argon2id$") {
		t.Fatal("the password is not stored as an argon2id hash")
	}
}

// Role change, disable, enable, MFA reset: each ends the sessions, is an
// event, and the last active admin is protected; each refusal beside its
// acceptance.
func TestAdminChangesEndSessionsAndGuardTheLastAdmin(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	if _, err := f.svc.SetRoles(ctx, f.admin.ID, []string{"viewer"}, adminActor); problemOf(t, err).Status != http.StatusConflict {
		t.Fatalf("demoting the last admin: %v", err)
	}
	if _, err := f.svc.SetStatus(ctx, f.admin.ID, StatusDisabled, adminActor); problemOf(t, err).Status != http.StatusConflict {
		t.Fatalf("disabling the last admin: %v", err)
	}
	second, _ := f.svc.CreateUser(ctx, NewUser{Username: "second", Password: adminPW, Realm: "console", Roles: []string{"admin"}}, adminActor)
	res := f.signIn(t, "admin", adminPW)
	u, err := f.svc.SetRoles(ctx, f.admin.ID, []string{"viewer", "auditor"}, adminActor)
	if err != nil || !slices.Equal(u.Roles, []string{"viewer", "auditor"}) {
		t.Fatalf("demote with a second admin: %+v %v", u, err)
	}
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatal("a session kept its old roles after a role change")
	}
	ev := f.st.eventsOf(audit.EventUserRolesChanged)
	if p := ev[0].Payload.(map[string]any); len(p["sessions_revoked"].([]string)) != 1 {
		t.Fatalf("event %v", p)
	}
	res = f.signIn(t, "admin", adminPW)
	if id, _ := f.identify(res.Token); !slices.Equal(id.Roles, []string{"viewer", "auditor"}) {
		t.Fatalf("new roles not applied: %v", id.Roles)
	}
	if _, err := f.svc.SetStatus(ctx, second.ID, StatusDisabled, adminActor); problemOf(t, err).Status != http.StatusConflict {
		t.Fatalf("now second is the last admin: %v", err)
	}
	if _, err := f.svc.SetStatus(ctx, f.admin.ID, StatusDisabled, adminActor); err != nil {
		t.Fatalf("disable a non-admin: %v", err)
	}
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatal("a disabled account kept its session")
	}
	if _, err := f.svc.Login(ctx, "admin", adminPW, ri); problemOf(t, err).Slug() != SlugInvalidCredentials {
		t.Fatal("a disabled account signed in")
	}
	if _, err := f.svc.SetStatus(ctx, f.admin.ID, StatusActive, adminActor); err != nil {
		t.Fatal(err)
	}
	f.signIn(t, "admin", adminPW)
	if _, err := f.svc.ResetMFA(ctx, f.admin.ID, adminActor); err != nil {
		t.Fatal(err)
	}
	if _, enrolled, _ := f.svc.GetUser(ctx, f.admin.ID); enrolled {
		t.Fatal("still enrolled after a reset")
	}
	for _, et := range []string{audit.EventUserDisabled, audit.EventUserEnabled, audit.EventUserMFAReset} {
		if len(f.st.eventsOf(et)) != 1 {
			t.Errorf("%s: %d events", et, len(f.st.eventsOf(et)))
		}
	}
	for name, err := range map[string]error{
		"roles of nobody":  second2(f.svc.SetRoles(ctx, "nobody", nil, adminActor)),
		"status of nobody": second2(f.svc.SetStatus(ctx, "nobody", StatusActive, adminActor)),
		"reset of nobody":  second2(f.svc.ResetMFA(ctx, "nobody", adminActor)),
		"revoke of nobody": second2(f.svc.RevokeSessions(ctx, "nobody", adminActor)),
		"get nobody":       third3(f.svc.GetUser(ctx, "nobody")),
		"an unknown role":  second2(f.svc.SetRoles(ctx, second.ID, []string{"root"}, adminActor)),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	us, enrolled, err := f.svc.ListUsers(ctx)
	if err != nil || len(us) != 2 || us[0].Username != "admin" || len(enrolled) != 2 {
		t.Fatalf("list %v %v %v", us, enrolled, err)
	}
}

func second2[T any](_ T, err error) error        { return err }
func third3[T, U any](_ T, _ U, err error) error { return err }

// The one-shot bootstrap: created on an empty table, refused (and
// recorded) when accounts exist; a missing password file is named.
func TestBootstrap(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	_ = os.WriteFile(pw, []byte(adminPW+"\r\n"), 0o600)
	if created, err := f.svc.Bootstrap(ctx, "root-admin", pw); err != nil || created {
		t.Fatalf("with accounts: %v %v", created, err)
	}
	if len(f.st.eventsOf(audit.EventUserBootstrapRefused)) != 1 || f.svc.Counters.Get(CounterBootstrapRefused) != 1 {
		t.Fatal("refusal not recorded")
	}
	empty := newFixture(t, fxOpts{})
	delete(empty.st.users, empty.admin.ID)
	created, err := empty.svc.Bootstrap(ctx, "Root-Admin", pw)
	if err != nil || !created {
		t.Fatalf("on an empty table: %v %v", created, err)
	}
	u, _ := empty.st.UserByUsername(ctx, "root-admin")
	if !slices.Equal(u.Roles, []string{"admin"}) || u.CreatedBy != "bootstrap" {
		t.Fatalf("bootstrapped %+v", u)
	}
	// The trailing newline of the file is not part of the password.
	if _, err := empty.svc.Login(ctx, "root-admin", adminPW, ri); err != nil {
		t.Fatalf("bootstrapped admin cannot sign in: %v", err)
	}
	if c, err := empty.svc.Bootstrap(ctx, "", ""); c || err != nil {
		t.Fatal("bootstrap without a username did something")
	}
	if _, err := empty.svc.Bootstrap(ctx, "x-admin", filepath.Join(dir, "absent")); !slices.Contains(fieldNames(err), "BOOTSTRAP_ADMIN_PASSWORD_FILE") {
		t.Fatalf("missing file: %v", err)
	}
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("short"), 0o600)
	if _, err := empty.svc.Bootstrap(ctx, "x-admin", short); err == nil {
		t.Fatal("a short bootstrap password accepted")
	}
}

func TestTOTPAndRecoveryHelpers(t *testing.T) {
	secret, uri, err := NewTOTPSecret("uspace-authority", "admin")
	if err != nil || len(secret) != 32 || !strings.Contains(uri, "secret="+secret) {
		t.Fatalf("%q %q %v", secret, uri, err)
	}
	if again, err := TOTPURI("uspace-authority", "admin", secret); err != nil || !strings.Contains(again, secret) {
		t.Fatalf("uri again %q %v", again, err)
	}
	if _, err := TOTPURI("x", "y", "not base32!"); err == nil {
		t.Fatal("a bad secret rendered")
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	code, _ := totp.GenerateCode(secret, now)
	step, ok := VerifyTOTP(secret, code, now, 0)
	if !ok || step != now.Unix()/30 {
		t.Fatalf("current code: %d %v", step, ok)
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(30*time.Second), 0); !ok {
		t.Fatal("one step of skew refused")
	}
	if _, ok := VerifyTOTP(secret, code, now.Add(90*time.Second), 0); ok {
		t.Fatal("three steps late accepted")
	}
	if _, ok := VerifyTOTP(secret, code, now, step); ok {
		t.Fatal("a used step accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456"} {
		if _, ok := VerifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	codes, hashes, err := NewRecoveryCodes(3)
	if err != nil || len(codes) != 3 || len(codes[0]) != 19 {
		t.Fatalf("%v %v", codes, err)
	}
	if MatchRecoveryCode(strings.ToUpper(strings.ReplaceAll(codes[1], "-", " ")), hashes) != 1 {
		t.Fatal("a recovery code in another form did not match")
	}
	if MatchRecoveryCode("aaaa-bbbb-cccc-dddd", hashes) != -1 || MatchRecoveryCode(strings.Repeat("a", 65), hashes) != -1 {
		t.Fatal("a wrong code matched")
	}
}

func FuzzVerifyTOTP(f *testing.F) {
	secret, _, _ := NewTOTPSecret("x", "y")
	f.Add("123456", int64(0))
	f.Add("\x00\x01", int64(-5))
	f.Fuzz(func(t *testing.T, code string, last int64) {
		now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
		step, ok := VerifyTOTP(secret, code, now, last)
		if ok && (step <= last || len(code) != 6) {
			t.Fatalf("accepted %q at step %d after %d", code, step, last)
		}
	})
}

func FuzzMatchRecoveryCode(f *testing.F) {
	codes, hashes, _ := NewRecoveryCodes(2)
	f.Add(codes[0])
	f.Add("")
	f.Fuzz(func(t *testing.T, c string) {
		if i := MatchRecoveryCode(c, hashes); i >= 0 && HashRecoveryCode(c) != hashes[i] {
			t.Fatalf("%q matched %d", c, i)
		}
	})
}

var _ = httpx.SlugConflict
