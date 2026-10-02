package authz

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
)

func TestLockForDoublesUpToTheMax(t *testing.T) {
	c := Config{LockoutAfter: 5, LockoutBase: time.Minute, LockoutMax: 10 * time.Minute}
	for failures, want := range map[int]time.Duration{5: time.Minute, 6: 2 * time.Minute, 7: 4 * time.Minute, 8: 8 * time.Minute, 9: 10 * time.Minute, 40: 10 * time.Minute} {
		if got := c.LockFor(failures); got != want {
			t.Errorf("%d failures: %s, want %s", failures, got, want)
		}
	}
}

// wrongCode spends one wrong code through a fresh challenge from a fresh
// address: the budget is the account's, not the challenge's or the
// address's.
func (f *fixture) wrongCode(t *testing.T, i int) string {
	t.Helper()
	r := ri
	r.RemoteIP = "198.51.100." + string(rune('0'+i%10))
	lr, err := f.svc.Login(context.Background(), "admin", adminPW, r)
	if err != nil {
		t.Fatalf("login %d: %v", i, err)
	}
	_, err = f.svc.VerifyMFA(context.Background(), lr.Token, "000000", "", r)
	return problemOf(t, err).Detail
}

func (f *fixture) rightCode(t *testing.T) error {
	t.Helper()
	lr, err := f.svc.Login(context.Background(), "admin", adminPW, ri)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(TOTPPeriod)
	code, _ := totp.GenerateCode(f.secrets["admin"], f.clk.Now())
	_, err = f.svc.VerifyMFA(context.Background(), lr.Token, code, "", ri)
	return err
}

// NIST SP 800-63B 5.2.2: wrong codes count against the account across
// challenges and addresses; the fifth locks it, the right code is then
// refused until the lock ends, a success clears the count, the lock
// doubles, and the hard bound needs an admin. Each refusal beside its
// acceptance.
func TestMFALockoutPerAccount(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	f.signIn(t, "admin", adminPW)
	for i := range 4 {
		f.wrongCode(t, i)
	}
	if err := f.rightCode(t); err != nil {
		t.Fatalf("four failures do not lock: %v", err)
	}
	if u := f.st.users[f.admin.ID]; u.MFAFailures != 0 {
		t.Fatalf("a success did not clear the count: %d", u.MFAFailures)
	}
	for i := range 5 {
		f.wrongCode(t, i)
	}
	u := f.st.users[f.admin.ID]
	if u.MFAFailures != 5 || u.MFALockedUntil == nil || !u.MFALockedUntil.Equal(f.clk.Now().Add(time.Minute)) {
		t.Fatalf("after five: %+v", u)
	}
	if err := f.rightCode(t); err == nil || !strings.Contains(problemOf(t, err).Detail, "try again after") {
		t.Fatalf("the right code while locked: %v", err)
	}
	evs := f.st.eventsOf(audit.EventMFARefused)
	if evs[len(evs)-1].Payload.(map[string]any)["reason"] != "mfa_locked" {
		t.Fatalf("refusal reason %v", evs[len(evs)-1].Payload)
	}
	if len(f.st.eventsOf(audit.EventMFALocked)) != 1 {
		t.Fatal("no mfa_locked event")
	}
	f.clk.Advance(time.Minute)
	// The sixth failure doubles the lock.
	f.wrongCode(t, 6)
	if u := f.st.users[f.admin.ID]; u.MFAFailures != 6 || !u.MFALockedUntil.Equal(f.clk.Now().Add(2*time.Minute)) {
		t.Fatalf("after six: %+v", u)
	}
	f.clk.Advance(2 * time.Minute)
	if err := f.rightCode(t); err != nil {
		t.Fatalf("after the lock: %v", err)
	}

	// The hard bound (12 here): only an admin unlocks.
	for i := range 12 {
		f.wrongCode(t, i)
		f.clk.Advance(time.Hour)
	}
	if u := f.st.users[f.admin.ID]; !u.MFAHardLocked {
		t.Fatalf("not hard-locked: %+v", u)
	}
	f.clk.Advance(48 * time.Hour)
	if err := f.rightCode(t); err == nil || !strings.Contains(problemOf(t, err).Detail, "admin") {
		t.Fatalf("hard lock outlived: %v", err)
	}
	if got, err := f.svc.UnlockMFA(ctx, f.admin.ID, adminActor); err != nil || got.MFAHardLocked || got.MFAFailures != 0 {
		t.Fatalf("unlock: %+v %v", got, err)
	}
	if err := f.rightCode(t); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	if len(f.st.eventsOf(audit.EventUserMFAUnlocked)) != 1 {
		t.Fatal("no unlock event")
	}
	if _, err := f.svc.UnlockMFA(ctx, "nobody", adminActor); err == nil {
		t.Fatal("unlocked nobody")
	}
}

// An MFA reset also clears the lock.
func TestMFAResetClearsTheLock(t *testing.T) {
	f := newFixture(t, fxOpts{})
	f.signIn(t, "admin", adminPW)
	for i := range 5 {
		f.wrongCode(t, i)
	}
	second, _ := f.svc.CreateUser(context.Background(), NewUser{Username: "second", Password: adminPW, Realm: "console", Roles: []string{"admin"}}, adminActor)
	_ = second
	if _, err := f.svc.ResetMFA(context.Background(), f.admin.ID, adminActor); err != nil {
		t.Fatal(err)
	}
	if u := f.st.users[f.admin.ID]; u.MFAFailures != 0 || u.MFALockedUntil != nil {
		t.Fatalf("reset kept the lock: %+v", u)
	}
	var _ = apiserver.RoleAdmin
}
