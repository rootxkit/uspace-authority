package authz

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"testing"

	"github.com/pquerna/otp/totp"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
)

func TestParseAllowListCanonicalises(t *testing.T) {
	got, err := ParseAllowList("ip_allowlist", []string{" 192.0.2.77/24 ", "198.51.100.7", "2001:db8::1/48", "::ffff:203.0.113.0/120", "198.51.100.7"})
	want := []string{"192.0.2.0/24", "198.51.100.7/32", "2001:db8::/48", "203.0.113.0/24"}
	slices.Sort(want)
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("got %v %v, want %v", got, err, want)
	}
	for _, bad := range [][]string{{""}, {"10.0.0.0/33"}, {"caddy"}, {"fe80::1%eth0"}, {"10.0.0.1/8/8"}} {
		if _, err := ParseAllowList("ip_allowlist", bad); err == nil || fieldNames(err)[0] != "ip_allowlist[0]" {
			t.Errorf("%q accepted or unnamed: %v", bad, err)
		}
	}
}

// E-10: the list is bounded; at the bound it is accepted, past it refused.
func TestParseAllowListBound(t *testing.T) {
	list := make([]string, 0, MaxAllowList+1)
	for i := range MaxAllowList {
		list = append(list, "10.0."+strconv.Itoa(i)+".0/24")
	}
	if got, err := ParseAllowList("ip_allowlist", list); err != nil || len(got) != MaxAllowList {
		t.Fatalf("at the bound: %d %v", len(got), err)
	}
	if _, err := ParseAllowList("ip_allowlist", append(list, "10.1.0.0/24")); err == nil {
		t.Fatal("past the bound accepted")
	}
}

// E-01 pairs: inside and outside, an empty list and an address that does
// not parse admit nothing, a mapped IPv4 address is its IPv4 address.
func TestAddressAllowed(t *testing.T) {
	allow := []string{"192.0.2.0/24", "2001:db8::/48"}
	for ip, want := range map[string]bool{
		"192.0.2.10": true, "198.51.100.1": false, "2001:db8::5": true, "2001:db9::5": false,
		"::ffff:192.0.2.10": true, "": false, "not-an-ip": false, "192.0.2.10:443": false,
	} {
		if got := AddressAllowed(allow, ip); got != want {
			t.Errorf("%q: %v, want %v", ip, got, want)
		}
	}
	if AddressAllowed(nil, "192.0.2.10") || AddressAllowed([]string{"garbage"}, "192.0.2.10") {
		t.Fatal("an empty or unreadable list admitted an address")
	}
}

func FuzzParseAllowList(f *testing.F) {
	for _, s := range []string{"192.0.2.0/24", "::1", "::ffff:1.2.3.4/120", "", "x/y", "1.2.3.4/0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseAllowList("f", []string{s})
		if err != nil {
			return
		}
		// What is accepted is canonical: parsing it again is the identity.
		again, err := ParseAllowList("f", got)
		if err != nil || !slices.Equal(again, got) {
			t.Fatalf("%q -> %v -> %v %v", s, got, again, err)
		}
	})
}

func newPolice(t *testing.T, f *fixture, name string, allow ...string) User {
	t.Helper()
	u, err := f.svc.CreateUser(context.Background(), NewUser{Username: name, Password: adminPW, Realm: apiserver.RealmPolice,
		Roles: []string{apiserver.RolePoliceQuery}, Agency: "TEST-POLICE", IPAllow: allow}, adminActor)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// A realm's roles and access fields, each refusal beside its acceptance.
func TestPoliceAccountRules(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	cases := []struct {
		name  string
		in    NewUser
		field string
	}{
		{"police with a console role", NewUser{Realm: "police", Roles: []string{"inspector"}, Agency: "A", IPAllow: []string{"192.0.2.0/24"}}, "roles[0]"},
		{"console with police.query", NewUser{Realm: "console", Roles: []string{"police.query"}}, "roles[0]"},
		{"police without an agency", NewUser{Realm: "police", IPAllow: []string{"192.0.2.0/24"}}, "agency"},
		{"police with a bad agency", NewUser{Realm: "police", Agency: "-x", IPAllow: []string{"192.0.2.0/24"}}, "agency"},
		{"police without an allow-list", NewUser{Realm: "police", Agency: "A"}, "ip_allowlist"},
		{"console with an agency", NewUser{Realm: "console", Agency: "A"}, "agency"},
		{"console with an allow-list", NewUser{Realm: "console", IPAllow: []string{"192.0.2.0/24"}}, "ip_allowlist"},
	}
	for i, c := range cases {
		c.in.Username, c.in.Password = "user"+strconv.Itoa(i), adminPW
		if _, err := f.svc.CreateUser(ctx, c.in, adminActor); !slices.Contains(fieldNames(err), c.field) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	u := newPolice(t, f, "officer", "192.0.2.0/24")
	if !slices.Equal(u.Roles, []string{"police.query"}) || u.Agency != "TEST-POLICE" || !slices.Equal(u.IPAllow, []string{"192.0.2.0/24"}) {
		t.Fatalf("police account %+v", u)
	}
	// Roles follow the realm on a change too.
	if _, err := f.svc.SetRoles(ctx, u.ID, []string{"admin"}, adminActor); err == nil {
		t.Fatal("a police account was given a console role")
	}
	if _, err := f.svc.SetRoles(ctx, f.admin.ID, []string{"admin", "police.query"}, adminActor); err == nil {
		t.Fatal("a console account was given police.query")
	}
	if got, err := f.svc.SetRoles(ctx, u.ID, []string{}, adminActor); err != nil || len(got.Roles) != 0 {
		t.Fatalf("revoke police.query: %+v %v", got, err)
	}
	if got, err := f.svc.SetRoles(ctx, u.ID, []string{"police.query"}, adminActor); err != nil || !slices.Equal(got.Roles, []string{"police.query"}) {
		t.Fatalf("grant police.query: %+v %v", got, err)
	}
}

func lastReason(t *testing.T, f *fixture, eventType string) string {
	t.Helper()
	ev := f.st.eventsOf(eventType)
	if len(ev) == 0 {
		t.Fatalf("no %s event", eventType)
	}
	return ev[len(ev)-1].Payload.(map[string]any)["reason"].(string)
}

// E-01: a police sign-in from inside the allow-list opens a police
// session; from outside it is refused at the password step and at the
// TOTP step with the answer of a wrong password, and recorded.
func TestPoliceSignInOnlyFromTheAllowList(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	u := newPolice(t, f, "officer", "192.0.2.0/24")
	res := f.signIn(t, "officer", adminPW)
	id, err := f.identify(res.Token)
	if err != nil || id.Realm != apiserver.RealmPolice || !slices.Equal(id.Roles, []string{"police.query"}) {
		t.Fatalf("police session: %+v %v", id, err)
	}
	outside := apiserver.RequestInfo{RemoteIP: "198.51.100.9", UserAgent: "test"}
	if _, err := f.svc.Login(ctx, "officer", adminPW, outside); problemOf(t, err).Slug() != SlugInvalidCredentials {
		t.Fatalf("login from outside: %v", err)
	}
	if r := lastReason(t, f, audit.EventLoginRefused); r != ReasonAddressNotAllowed {
		t.Fatalf("refusal reason %q", r)
	}
	// The password step from inside, the TOTP step from outside.
	lr, err := f.svc.Login(ctx, "officer", adminPW, ri)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(TOTPPeriod)
	code, err := totp.GenerateCode(f.secrets["officer"], f.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.VerifyMFA(ctx, lr.Token, code, "", outside); problemOf(t, err).Slug() != SlugMFARefused {
		t.Fatalf("TOTP from outside: %v", err)
	}
	if r := lastReason(t, f, audit.EventMFARefused); r != ReasonAddressNotAllowed {
		t.Fatalf("refusal reason %q", r)
	}
	// A console account is not held to any list.
	if _, err := f.svc.Login(ctx, "admin", adminPW, outside); err != nil {
		t.Fatalf("console login from anywhere: %v", err)
	}
	_ = u
}

// Changing a police account's access ends its sessions and is one event
// with the before and after; a console account has none to change.
func TestSetPoliceAccess(t *testing.T) {
	f := newFixture(t, fxOpts{})
	ctx := context.Background()
	u := newPolice(t, f, "officer", "192.0.2.0/24")
	res := f.signIn(t, "officer", adminPW)
	got, err := f.svc.SetPoliceAccess(ctx, u.ID, "TEST-POLICE-2", []string{"198.51.100.0/24"}, adminActor)
	if err != nil || got.Agency != "TEST-POLICE-2" || !slices.Equal(got.IPAllow, []string{"198.51.100.0/24"}) {
		t.Fatalf("set: %+v %v", got, err)
	}
	if _, err := f.identify(res.Token); !errors.Is(err, ErrSessionRefused) {
		t.Fatal("a session outlived the change of its allow-list")
	}
	ev := f.st.eventsOf(audit.EventUserPoliceAccessChange)
	if len(ev) != 1 || len(ev[0].Payload.(map[string]any)["sessions_revoked"].([]string)) != 1 {
		t.Fatalf("events %+v", ev)
	}
	if _, err := f.svc.SetPoliceAccess(ctx, f.admin.ID, "X", []string{"192.0.2.0/24"}, adminActor); problemOf(t, err).Status != http.StatusConflict {
		t.Fatalf("console account: %v", err)
	}
	if _, err := f.svc.SetPoliceAccess(ctx, u.ID, "X", nil, adminActor); !slices.Contains(fieldNames(err), "ip_allowlist") {
		t.Fatalf("an empty list: %v", err)
	}
	if _, err := f.svc.SetPoliceAccess(ctx, "0123456789abcdef0123456789abcdef", "X", []string{"192.0.2.0/24"}, adminActor); problemOf(t, err).Status != http.StatusNotFound {
		t.Fatalf("unknown account: %v", err)
	}
}
