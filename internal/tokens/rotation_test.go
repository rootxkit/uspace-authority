package tokens

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

var admin2 = audit.Actor{Type: audit.ActorUser, ID: "admin-2", Realm: "console"}

// Start-up registers every configured key, activates the first, and is
// idempotent on a restart.
func TestSyncRegistersAndBootstrapsOnce(t *testing.T) {
	f := newFixture(t, fixtureOpts{keys: 2, publication: true})
	rows, _ := f.st.SigningKeys(context.Background())
	if len(rows) != 3 {
		t.Fatalf("%d rows", len(rows))
	}
	files := f.parts.Keys.Files()
	if f.parts.Keys.ActiveKID() != files[0].KID {
		t.Fatal("the first configured key is not the active one")
	}
	if n := len(f.st.eventsOf(audit.EventSigningKeyRegistered)); n != 3 {
		t.Fatalf("%d registration events", n)
	}
	if n := len(f.st.eventsOf(audit.EventSigningKeyActivated)); n != 2 {
		t.Fatalf("%d activation events (token bootstrap and publication)", n)
	}
	if err := f.parts.Manager.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(f.st.eventsOf(audit.EventSigningKeyRegistered)); n != 3 {
		t.Fatalf("a restart registered again: %d", n)
	}
	if got := f.parts.StatusAttrs(); got[0].Value.String() != files[0].KID {
		t.Fatalf("status %v", got)
	}
}

// T4: the two-person rule. The first admin requests (202), the same
// admin cannot confirm (409, event), a second admin activates; the old
// key keeps verifying for 24 h and not after (E-02).
func TestTwoPersonRotationAndTheRetiringKeyWindow(t *testing.T) {
	f := newFixture(t, fixtureOpts{keys: 2, twoPerson: true})
	ctx := context.Background()
	m := f.parts.Manager
	old := f.parts.Keys.ActiveKID()
	next := f.parts.Keys.Files()[1].KID
	secret := f.register(t, "cisp-01", []string{"cis.read"}, []string{cispHost})
	before, oerr := f.token(secretReq("cisp-01", secret, "cis.read", cispHost))
	if oerr != nil {
		t.Fatal(oerr)
	}

	r, err := m.Rotate(ctx, admin)
	if err != nil || r.State != "requested" || r.KID != next || r.ActiveKID != old || !r.ConfirmBefore.Equal(f.clock.Now().Add(10*time.Minute)) {
		t.Fatalf("request: %+v %v", r, err)
	}
	var pe *httpx.ProblemError
	if _, err := m.Rotate(ctx, admin); !errors.As(err, &pe) || pe.Problem.Status != http.StatusConflict {
		t.Fatalf("same admin: %v", err)
	}
	if ev := f.st.eventsOf(audit.EventKeyRotationRefused); len(ev) != 1 || ev[0].Payload.(map[string]any)["reason"] != ReasonSameAdmin {
		t.Fatalf("refusal events %+v", ev)
	}
	if f.parts.Keys.ActiveKID() != old {
		t.Fatal("a request alone rotated")
	}
	f.clock.Advance(time.Minute)
	r, err = m.Rotate(ctx, admin2)
	if err != nil || r.State != "activated" || r.ActiveKID != next || r.PreviousKID != old || r.RequestedBy != "admin-1" {
		t.Fatalf("confirm: %+v %v", r, err)
	}
	if f.parts.Keys.ActiveKID() != next {
		t.Fatal("the next key does not sign")
	}
	act := f.st.eventsOf(audit.EventSigningKeyActivated)
	if p := act[len(act)-1].Payload.(map[string]any); p["confirmed_by"] != "admin-2" || p["requested_by"] != "admin-1" {
		t.Fatalf("activation event %v", p)
	}

	after, oerr := f.token(secretReq("cisp-01", secret, "cis.read", cispHost))
	if oerr != nil || headerOf(t, after.AccessToken)["kid"] != next {
		t.Fatalf("after rotation: %v", oerr)
	}
	// The JWKS lists both keys now; the pre-rotation token verifies.
	set, _ := f.parts.Keys.JWKS(f.clock.Now())
	if set.Len() != 2 {
		t.Fatalf("JWKS holds %d keys", set.Len())
	}
	// A verifier that refreshes its JWKS 23 h later still finds the old
	// key; its token, checked at its own iat, verifies.
	f.clock.Advance(23 * time.Hour)
	if s, _ := f.parts.Keys.JWKS(f.clock.Now()); s.Len() != 2 {
		t.Fatal("the retiring key left the JWKS before 24 h")
	}
	v := verifierAt(t, f, f.clock.Now(), before.Issued.IssuedAt.Add(time.Minute))
	if _, err := v.Verify(ctx, before.AccessToken); err != nil {
		t.Fatalf("retiring key within 24 h: %v", err)
	}
	f.clock.Advance(time.Hour + time.Second)
	if s, _ := f.parts.Keys.JWKS(f.clock.Now()); s.Len() != 1 {
		t.Fatal("the retired key is still published after 24 h")
	}
	v = verifierAt(t, f, f.clock.Now(), before.Issued.IssuedAt.Add(time.Minute))
	var te *auth.TokenError
	if _, err := v.Verify(ctx, before.AccessToken); !errors.As(err, &te) || te.Counter != auth.CounterRejectedKID {
		t.Fatalf("retired key after 24 h: %v", err)
	}
	if _, err := v.Verify(ctx, after.AccessToken); err != nil {
		t.Fatalf("active key: %v", err)
	}
	// Nothing left to rotate to.
	if _, err := m.Rotate(ctx, admin); !errors.As(err, &pe) || pe.Problem.Status != http.StatusConflict {
		t.Fatalf("no candidate: %v", err)
	}
	if ev := f.st.eventsOf(audit.EventKeyRotationRefused); ev[len(ev)-1].Payload.(map[string]any)["reason"] != ReasonNoCandidate {
		t.Fatalf("refusal %+v", ev)
	}
}

// verifierAt builds a verifier from the JWKS published at jwksAt whose
// clock reads verifyAt (a token is checked while it is valid).
func verifierAt(t *testing.T, f *fixture, jwksAt, verifyAt time.Time) *auth.Verifier {
	t.Helper()
	set, err := f.parts.Keys.JWKS(jwksAt)
	if err != nil {
		t.Fatal(err)
	}
	v, err := auth.NewVerifier(context.Background(), auth.Config{
		Issuers: map[string]auth.IssuerConfig{testIssuer: {Keys: set}}, Audience: cispHost, StrictSessionClaims: true,
		Now: func() time.Time { return verifyAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestARequestExpiresAfterTheConfirmWindow(t *testing.T) {
	f := newFixture(t, fixtureOpts{keys: 2, twoPerson: true})
	ctx := context.Background()
	if r, _ := f.parts.Manager.Rotate(ctx, admin); r.State != "requested" {
		t.Fatal("no request")
	}
	f.clock.Advance(11 * time.Minute)
	// The late confirmation is a fresh request, by admin-2 this time.
	r, err := f.parts.Manager.Rotate(ctx, admin2)
	if err != nil || r.State != "requested" || r.RequestedBy != "admin-2" {
		t.Fatalf("%+v %v", r, err)
	}
	// So admin-1 can now confirm.
	if r, err := f.parts.Manager.Rotate(ctx, admin); err != nil || r.State != "activated" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRotationWithoutTheTwoPersonRuleActivatesAtOnce(t *testing.T) {
	f := newFixture(t, fixtureOpts{keys: 2})
	r, err := f.parts.Manager.Rotate(context.Background(), admin)
	if err != nil || r.State != "activated" || f.parts.Keys.ActiveKID() != f.parts.Keys.Files()[1].KID {
		t.Fatalf("%+v %v", r, err)
	}
	if f.parts.Counters.Get(CounterKeyRotated) != 1 {
		t.Fatalf("counters %v", f.parts.Counters.Snapshot())
	}
}

// A replica whose active kid has no file keeps signing with the key it
// had, counts it, and says so; the accepted twin is a refresh that
// finds its own file active.
func TestRefreshWithTheActiveKeyMissingKeepsSigning(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()
	had := f.parts.Keys.ActiveKID()
	// Another replica rotated to a key this one does not have.
	other, _ := NewKeyFile("elsewhere.pem", tokentestKey(t, 5))
	now := f.clock.Now()
	_ = f.st.InTx(ctx, func(tx Tx) error {
		_ = tx.InsertSigningKey(ctx, KeyRow{KID: other.KID, Purpose: PurposeToken, PublicJWK: other.PublicJWK, PrivateRef: other.Ref, RegisteredAt: now})
		_ = tx.RetireSigningKey(ctx, had, now)
		return tx.ActivateSigningKey(ctx, other.KID, now)
	})
	err := f.parts.Manager.Refresh(ctx)
	if !errors.Is(err, ErrNoActiveKey) || f.parts.Keys.ActiveKID() != had || f.parts.Counters.Get(CounterKeyFileMissing) != 1 {
		t.Fatalf("err %v active %s counters %v", err, f.parts.Keys.ActiveKID(), f.parts.Counters.Snapshot())
	}
	if _, err := f.parts.Keys.Issue("x", "h", nil, time.Minute, now); err != nil {
		t.Fatalf("stopped signing: %v", err)
	}
	f.st.failReads = true
	if err := f.parts.Manager.Refresh(ctx); err == nil || f.parts.Counters.Get(CounterKeyRefreshFailed) != 1 {
		t.Fatalf("read failure: %v", err)
	}
}

// A newly configured publication key replaces the previous one.
func TestPublicationKeyChangeRetiresThePreviousOne(t *testing.T) {
	f := newFixture(t, fixtureOpts{publication: true})
	ctx := context.Background()
	prev := f.parts.Keys.Publication().KID
	newPub, _ := NewKeyFile("pub2.pem", tokentestKey(t, 8))
	keys, err := NewKeys(testIssuer, 24*time.Hour, f.parts.Keys.Files(), &newPub)
	if err != nil {
		t.Fatal(err)
	}
	m := &KeyManager{Store: f.st, Keys: keys, Now: f.clock.Now}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _ := f.st.SigningKeys(ctx)
	for _, r := range rows {
		if r.KID == prev && r.RetiredAt == nil {
			t.Fatal("the previous publication key is still active")
		}
		if r.KID == newPub.KID && !r.Active() {
			t.Fatal("the new publication key is not active")
		}
	}
	// A key registered for one purpose cannot be configured for the other.
	swapped, err := NewKeys(testIssuer, time.Hour, []KeyFile{newPub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&KeyManager{Store: f.st, Keys: swapped, Now: f.clock.Now}).Sync(ctx); err == nil {
		t.Fatal("a publication key was accepted as a token key")
	}
}

func TestKeyManagerRunStopsWithItsContext(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	changes := 0
	f.parts.Manager.OnChange = func() { changes++ }
	go func() { f.parts.Manager.Run(ctx, time.Millisecond); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if changes == 0 {
		t.Fatal("Run never refreshed")
	}
}
