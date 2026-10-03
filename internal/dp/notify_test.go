package dp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

const (
	testIssuer = "https://authority.example.test"
	ownHost    = "authority.example.test"
)

// issuerKit signs ecosystem tokens with a run-time key (rule 11) and
// verifies them with uspace-core's verifier, as dp-poller does.
type issuerKit struct {
	iss *auth.Issuer
	v   *auth.Verifier
}

func newIssuerKit(t *testing.T) issuerKit {
	t.Helper()
	iss, err := auth.NewIssuer(testIssuer, tokentest.Key(t, 0), "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers: map[string]auth.IssuerConfig{testIssuer: {Keys: iss.JWKS()}}, Audiences: []string{ownHost}, StrictSessionClaims: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issuerKit{iss: iss, v: v}
}

func (k issuerKit) token(t *testing.T, sub, aud string, scopes ...string) string {
	t.Helper()
	tok, err := k.iss.Issue(sub, aud, scopes, 10*time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func notification(owner string, deleted bool) []byte {
	p := f3411.PutIdentificationServiceAreaNotificationParameters{
		Subscriptions: []f3411.SubscriptionState{{SubscriptionId: "sub-1"}},
	}
	if !deleted {
		a := isa("isa-9", owner, spBase)
		p.ServiceArea = &a
		v := Volume(box2km, t0.Add(-time.Hour), t0.Add(time.Hour))
		p.Extents = &v
	}
	raw, _ := json.Marshal(p)
	return raw
}

func post(t *testing.T, mux *http.ServeMux, tok string, body []byte) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/uss/identification_service_areas/isa-9", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// E-01, M6, M18: a notification posted by the Service Provider that owns
// the ISA, with a token of this issuer for this host granting
// rid.service_provider, is applied (204); one with another host's aud,
// without the scope, without a token, by another owner, larger than the
// bound or malformed is refused with the F3411 status, counted, and
// changes nothing.
func TestNotificationAcceptedAndEveryRefusal(t *testing.T) {
	k := newIssuerKit(t)
	isas := &ISAs{Max: 10}
	cnt := &core.Counters{}
	changed := 0
	n := &Notifications{Verifier: k.v, ISAs: isas, Known: func(id string) bool { return id == "sub-1" }, MaxBytes: 64 << 10,
		Changed: func() { changed++ }, Counters: cnt}
	mux := http.NewServeMux()
	n.Mount(mux)
	sp := string(f3411.ScopeServiceProvider)

	cases := []struct {
		name    string
		tok     string
		body    []byte
		status  int
		counter string
	}{
		{"another host's aud", k.token(t, "ussp-lab-01", "other.example.test", sp), notification("ussp-lab-01", false), 401, CounterNotifyBadToken},
		{"no token", "", notification("ussp-lab-01", false), 401, CounterNotifyNoToken},
		{"display provider scope", k.token(t, "ussp-lab-01", ownHost, string(f3411.ScopeDisplayProvider)), notification("ussp-lab-01", false), 403, CounterNotifyScope},
		{"not the owner", k.token(t, "ussp-other-01", ownHost, sp), notification("ussp-lab-01", false), 403, CounterNotifyNotOwner},
		{"too large", k.token(t, "ussp-lab-01", ownHost, sp), bytes.Repeat([]byte(" "), 70<<10), 413, CounterNotifyTooLarge},
		{"malformed", k.token(t, "ussp-lab-01", ownHost, sp), []byte(`{"subscriptions": 7}`), 400, CounterNotifyMalformed},
	}
	for _, c := range cases {
		code, body := post(t, mux, c.tok, c.body)
		if code != c.status || cnt.Snapshot()[c.counter] == 0 {
			t.Errorf("%s: %d %s, counters %v", c.name, code, body, cnt.Snapshot())
		}
		if code != 204 && !strings.Contains(body, `"message"`) {
			t.Errorf("%s: not an F3411 ErrorResponse: %s", c.name, body)
		}
	}
	if isas.Len() != 0 || changed != 0 {
		t.Fatalf("a refused notification changed the ISAs (%d) or woke the engine (%d)", isas.Len(), changed)
	}

	code, body := post(t, mux, k.token(t, "ussp-lab-01", ownHost, sp), notification("ussp-lab-01", false))
	if code != http.StatusNoContent || isas.Len() != 1 || changed != 1 || cnt.Snapshot()[CounterNotifyAccepted] != 1 {
		t.Fatalf("accepted: %d %s isas %d changed %d", code, body, isas.Len(), changed)
	}
	if got := isas.ForTile(Tile{Box: box2km}, t0); len(got) != 1 || got[0].Owner != "ussp-lab-01" {
		t.Fatalf("the ISA is not in the tile its extents meet: %+v", got)
	}
	// Deleted by another owner: refused; by its owner: removed.
	if code, _ := post(t, mux, k.token(t, "ussp-other-01", ownHost, sp), notification("", true)); code != 403 || isas.Len() != 1 {
		t.Fatalf("deletion by another owner: %d", code)
	}
	if code, _ := post(t, mux, k.token(t, "ussp-lab-01", ownHost, sp), notification("", true)); code != 204 || isas.Len() != 0 {
		t.Fatalf("deletion by its owner: %d, %d ISAs", code, isas.Len())
	}
}

// Fail closed: without a verifier every notification is refused (503).
func TestNotificationWithoutVerifierIsRefused(t *testing.T) {
	n := &Notifications{ISAs: &ISAs{}, Counters: &core.Counters{}}
	mux := http.NewServeMux()
	n.Mount(mux)
	if code, _ := post(t, mux, "x.y.z", notification("u", false)); code != http.StatusServiceUnavailable {
		t.Fatalf("%d", code)
	}
	// Only the notification route is mounted from the generated server.
	req := httptest.NewRequest(http.MethodGet, "/uss/flights?view=1,2,3,4", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /uss/flights answered %d", rec.Code)
	}
}

func FuzzParseNotification(f *testing.F) {
	f.Add(notification("ussp-lab-01", false))
	f.Add(notification("", true))
	f.Add([]byte(`{"service_area":{"id":"x","owner":"o","uss_base_url":"ftp://x","time_start":{"value":"2026-01-01T00:00:00Z","format":"RFC3339"},"time_end":{"value":"2026-01-01T00:00:00Z","format":"RFC3339"},"version":"1"},"subscriptions":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := ParseNotification(raw)
		if err != nil {
			return
		}
		if len(p.Subscriptions) > maxNotificationSubscriptions {
			t.Fatal("bound not held")
		}
		if a := p.ServiceArea; a != nil && (a.Id == "" || a.Owner == "" || len(a.Id) > maxIDBytes) {
			t.Fatalf("service area accepted: %+v", a)
		}
	})
}

// impostorNotification is a notification for isa-9 that names owner and
// base, as a Service Provider other than the held owner would post it.
func impostorNotification(owner, base string) []byte {
	a := isa("isa-9", owner, base)
	v := Volume(box2km, t0.Add(-time.Hour), t0.Add(time.Hour))
	raw, _ := json.Marshal(f3411.PutIdentificationServiceAreaNotificationParameters{ServiceArea: &a, Extents: &v})
	return raw
}

// Audit A-B1, E-01: a replacement of a held ISA is accepted from the
// held owner and refused (403, counted, nothing changed) from another
// Service Provider, even when the body names that Service Provider as
// the owner.
func TestNotificationReplaceOnlyByTheHeldOwner(t *testing.T) {
	k := newIssuerKit(t)
	isas := &ISAs{Max: 10}
	cnt := &core.Counters{}
	n := &Notifications{Verifier: k.v, ISAs: isas, MaxBytes: 64 << 10, Counters: cnt}
	mux := http.NewServeMux()
	n.Mount(mux)
	sp := string(f3411.ScopeServiceProvider)

	if code, body := post(t, mux, k.token(t, "ussp-lab-01", ownHost, sp), impostorNotification("ussp-lab-01", spBase)); code != 204 {
		t.Fatalf("created by its owner: %d %s", code, body)
	}
	code, body := post(t, mux, k.token(t, "ussp-other-01", ownHost, sp), impostorNotification("ussp-other-01", "https://other.example.test"))
	if code != http.StatusForbidden || cnt.Snapshot()[CounterNotifyNotOwner] != 1 {
		t.Fatalf("replaced by another Service Provider: %d %s %v", code, body, cnt.Snapshot())
	}
	if owner, _ := isas.Owner("isa-9"); owner != "ussp-lab-01" {
		t.Fatalf("the impostor took the ISA: owner %q", owner)
	}
	if got := isas.ForTile(Tile{Box: box2km}, t0); len(got) != 1 || got[0].UssBaseUrl != spBase {
		t.Fatalf("the impostor changed the base URL: %+v", got)
	}
	// The held owner replaces it.
	if code, body := post(t, mux, k.token(t, "ussp-lab-01", ownHost, sp), impostorNotification("ussp-lab-01", "https://sp2.example.test")); code != 204 {
		t.Fatalf("replaced by its owner: %d %s", code, body)
	}
	if got := isas.ForTile(Tile{Box: box2km}, t0); len(got) != 1 || got[0].UssBaseUrl != "https://sp2.example.test" {
		t.Fatalf("the owner's replacement was not applied: %+v", got)
	}
}

// Audit A-B1, defence in depth: ISAs.Notify itself refuses a change of
// owner and applies a replacement by the same owner.
func TestISAsNotifyRefusesOwnerChange(t *testing.T) {
	s := &ISAs{Max: 10}
	a := isa("isa-1", "ussp-a-01", spBase)
	if !s.Notify("isa-1", &a, nil) {
		t.Fatal("creation refused")
	}
	b := isa("isa-1", "ussp-b-01", "https://b.example.test")
	if s.Notify("isa-1", &b, nil) {
		t.Fatal("owner change applied")
	}
	if owner, _ := s.Owner("isa-1"); owner != "ussp-a-01" {
		t.Fatalf("owner %q", owner)
	}
	if s.Counters.Snapshot()[CounterISAsOwnerChange] != 1 {
		t.Fatalf("not counted: %v", s.Counters.Snapshot())
	}
	a2 := isa("isa-1", "ussp-a-01", "https://a2.example.test")
	if !s.Notify("isa-1", &a2, nil) {
		t.Fatal("replacement by the owner refused")
	}
}
