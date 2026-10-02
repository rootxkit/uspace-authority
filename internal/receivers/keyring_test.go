package receivers

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/passhash"
)

// cheapHasher is argon2id at its smallest legal cost: the tests check the
// key handling, not the work factor.
func cheapHasher(t testing.TB) *passhash.Hasher {
	t.Helper()
	h, err := passhash.New(passhash.Params{MemoryKiB: 8, Time: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// testReceiver is one receiver's entry with credentials generated at
// test time (CLAUDE.md rule 11: no key in git).
type testReceiver struct {
	Entry  Entry
	Creds  Credentials
	Secret []byte
}

func newTestReceiver(t testing.TB, h *passhash.Hasher, id string) testReceiver {
	t.Helper()
	c, secret, err := GenerateCredentials(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.Hash(c.BearerKey)
	if err != nil {
		t.Fatal(err)
	}
	return testReceiver{
		Entry: Entry{ReceiverID: id, Status: StatusEnabled, LatDeg: 41.7, LonDeg: 44.8, Version: 1,
			Keys: []KeyGeneration{{Generation: 1, BearerHash: hash, HMACSecretHex: hex.EncodeToString(secret)}}},
		Creds: c, Secret: secret,
	}
}

func testKeyring(t testing.TB, h *passhash.Hasher, slots int) *Keyring {
	t.Helper()
	kr, err := NewKeyring(KeyringOptions{MaxSkew: MaxSkew, NonceMemory: 8, MaxDatagramBytes: MaxDatagramBytes(MaxBatchBytes),
		HashSlots: slots, HashWait: 50 * time.Millisecond, BadCache: 4}, h, &core.Counters{})
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func signed(secret []byte, report string) []byte {
	return Datagram([]byte(report), auth.SignReport(secret, []byte(report)))
}

func report(id string, sentAtMS int64, nonce string) string {
	return fmt.Sprintf(`{"receiver_id":%q,"sent_at_ms":%d,"nonce":%q,"observations":[]}`, id, sentAtMS, nonce)
}

// E-01: the key a receiver was given authenticates it; no key, a
// malformed key, an unknown receiver and another receiver's key do not.
func TestAuthenticateAcceptsItsKeyAndRefusesTheRest(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 2)
	a, b := newTestReceiver(t, h, "rx-a"), newTestReceiver(t, h, "rx-b")
	if err := kr.Replace([]Entry{a.Entry, b.Entry}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	e, g, err := kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, now)
	if err != nil || e.ReceiverID != "rx-a" || g.Number != 1 {
		t.Fatalf("own key: %v %+v", err, e)
	}
	wrongSecret := "rx-a." + strings.Repeat("E", 43)
	for name, header := range map[string]string{
		"none":                "",
		"not bearer":          "Basic " + a.Creds.BearerKey,
		"malformed":           "Bearer rx-a",
		"unknown receiver":    "Bearer rx-zz." + strings.Repeat("A", 43),
		"another's key":       "Bearer " + strings.Replace(b.Creds.BearerKey, "rx-b", "rx-a", 1),
		"wrong secret":        "Bearer " + wrongSecret,
		"too long":            "Bearer " + strings.Repeat("x", MaxBearerBytes),
		"id with a dot first": "Bearer .rx-a",
	} {
		if _, _, err := kr.Authenticate(context.Background(), header, now); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if kr.Counters().Get(CounterKeyMissing) != 1 || kr.Counters().Get(CounterKeyUnknown) < 7 {
		t.Fatalf("counters %v", kr.Counters().Snapshot())
	}
}

// B-06: argon2id runs once per key: the second request with the same key,
// right or wrong, is answered from the cache.
func TestAuthenticateHashesEachKeyOnce(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 2)
	a := newTestReceiver(t, h, "rx-a")
	if err := kr.Replace([]Entry{a.Entry}); err != nil {
		t.Fatal(err)
	}
	wrong := "Bearer rx-a." + strings.Repeat("E", 43)
	for range 3 {
		_, _, _ = kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, time.Now())
		_, _, _ = kr.Authenticate(context.Background(), wrong, time.Now())
	}
	if n := kr.Counters().Get(CounterKeyChecks); n != 2 {
		t.Fatalf("argon2id ran %d times, want 2", n)
	}
}

// T8, E-01: with every argon2id slot taken a key never seen is refused as
// busy (503, retried), and the key that was checked before still passes.
func TestAuthenticateIsBusyWhenTheSlotsAreTaken(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 1)
	a := newTestReceiver(t, h, "rx-a")
	if err := kr.Replace([]Entry{a.Entry}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	kr.slots <- struct{}{}
	defer func() { <-kr.slots }()
	if _, _, err := kr.Authenticate(context.Background(), "Bearer rx-a."+strings.Repeat("E", 43), time.Now()); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy: %v", err)
	}
	if kr.Counters().Get(CounterKeyCheckBusy) != 1 {
		t.Fatal("busy not counted")
	}
	if _, _, err := kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, time.Now()); err != nil {
		t.Fatalf("cached key while busy: %v", err)
	}
}

// E-10: the remembered failed keys are bounded; the oldest is forgotten
// and counted.
func TestBadKeyCacheIsBounded(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 2)
	a := newTestReceiver(t, h, "rx-a")
	if err := kr.Replace([]Entry{a.Entry}); err != nil {
		t.Fatal(err)
	}
	for i := range 6 {
		key := fmt.Sprintf("rx-a.%042dA", i)
		_, _, _ = kr.Authenticate(context.Background(), "Bearer "+key, time.Now())
	}
	if len(kr.bad) != 4 || kr.Counters().Get(CounterBadKeyEvicted) != 2 {
		t.Fatalf("bad cache %d evicted %d", len(kr.bad), kr.Counters().Get(CounterBadKeyEvicted))
	}
}

// A rotation's previous generation works until its grace ends and not
// after; the current one works throughout.
func TestPreviousGenerationWorksUntilItsGraceEnds(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 2)
	old := newTestReceiver(t, h, "rx-a")
	cur, secret, err := GenerateCredentials("rx-a", 2)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := h.Hash(cur.BearerKey)
	until := time.Now().Add(time.Minute)
	e := old.Entry
	prev := e.Keys[0]
	prev.NotAfter = &until
	e.Keys = []KeyGeneration{prev, {Generation: 2, BearerHash: hash, HMACSecretHex: hex.EncodeToString(secret)}}
	if err := kr.Replace([]Entry{e}); err != nil {
		t.Fatal(err)
	}
	if _, g, err := kr.Authenticate(context.Background(), "Bearer "+old.Creds.BearerKey, until.Add(-time.Second)); err != nil || g.Number != 1 {
		t.Fatalf("in grace: %v", err)
	}
	if _, _, err := kr.Authenticate(context.Background(), "Bearer "+old.Creds.BearerKey, until); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("after grace: %v", err)
	}
	if kr.Counters().Get(CounterGenerationExpired) != 1 {
		t.Fatalf("expired generation not counted: %v", kr.Counters().Snapshot())
	}
	if _, g, err := kr.Authenticate(context.Background(), "Bearer "+cur.BearerKey, until.Add(time.Hour)); err != nil || g.Number != 2 {
		t.Fatalf("current: %v", err)
	}
}

// A reload keeps the verifier of an unchanged secret, so a nonce used
// before the reload is still refused after it (the replay window never
// reopens); a changed secret gets a new verifier.
func TestReplaceKeepsTheNonceMemoryOfAnUnchangedSecret(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 2)
	a := newTestReceiver(t, h, "rx-a")
	if err := kr.Replace([]Entry{a.Entry}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, g, err := kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, now)
	if err != nil {
		t.Fatal(err)
	}
	d := signed(a.Secret, report("rx-a", now.UnixMilli(), "n-1"))
	if _, err := g.Verify(d, now); err != nil {
		t.Fatal(err)
	}
	reloaded := a.Entry
	reloaded.Version = 2
	if err := kr.Replace([]Entry{reloaded}); err != nil {
		t.Fatal(err)
	}
	_, g2, _ := kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, now)
	var re *auth.ReceiverError
	if _, err := g2.Verify(d, now); !errors.As(err, &re) || re.Counter != auth.CounterRejectedReplay {
		t.Fatalf("replay after reload: %v", err)
	}
	if g2.verifier != g.verifier {
		t.Fatal("the verifier was rebuilt for an unchanged secret")
	}
	changed := newTestReceiver(t, h, "rx-a")
	if err := kr.Upsert(changed.Entry); err != nil {
		t.Fatal(err)
	}
	_, g3, err := kr.Authenticate(context.Background(), "Bearer "+changed.Creds.BearerKey, now)
	if err != nil || g3.verifier == g.verifier {
		t.Fatalf("a new secret kept the old verifier: %v", err)
	}
	if _, _, err := kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, now); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("the replaced key still works: %v", err)
	}
}

// B-14: a set with an id twice or an invalid entry is refused whole and
// the keyring keeps what it held; a valid set beside it is taken.
func TestReplaceRefusesADuplicateOrInvalidSetWhole(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 2)
	a, b := newTestReceiver(t, h, "rx-a"), newTestReceiver(t, h, "rx-b")
	if err := kr.Replace([]Entry{a.Entry}); err != nil {
		t.Fatal(err)
	}
	dup := b.Entry
	dup.ReceiverID = "rx-a"
	if err := kr.Replace([]Entry{a.Entry, dup}); err == nil || !strings.Contains(err.Error(), "appears twice") {
		t.Fatalf("duplicate: %v", err)
	}
	bad := b.Entry
	bad.ReceiverID = ""
	if err := kr.Replace([]Entry{bad}); err == nil {
		t.Fatal("empty id taken")
	}
	if ids := kr.IDs(); len(ids) != 1 || ids[0] != "rx-a" || kr.Counters().Get(CounterKeysetRefused) != 2 {
		t.Fatalf("held %v counters %v", ids, kr.Counters().Snapshot())
	}
	if err := kr.Replace([]Entry{a.Entry, b.Entry}); err != nil || kr.Len() != 2 {
		t.Fatalf("valid set: %v", err)
	}
	kr.Remove("rx-a")
	if _, ok := kr.Lookup("rx-a"); ok {
		t.Fatal("removed receiver still held")
	}
}

// E-10: core's nonce memory per receiver generation is bounded by the
// configured size; past it the oldest nonce is forgotten and counted.
func TestNonceMemoryBoundIsCounted(t *testing.T) {
	h := cheapHasher(t)
	kr := testKeyring(t, h, 2)
	a := newTestReceiver(t, h, "rx-a")
	if err := kr.Replace([]Entry{a.Entry}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_, g, _ := kr.Authenticate(context.Background(), "Bearer "+a.Creds.BearerKey, now)
	for i := range 10 {
		if _, err := g.Verify(signed(a.Secret, report("rx-a", now.UnixMilli(), fmt.Sprintf("n-%d", i))), now); err != nil {
			t.Fatal(err)
		}
	}
	if kr.NoncesEvicted() != 2 {
		t.Fatalf("evicted %d, want 2 past a memory of 8", kr.NoncesEvicted())
	}
}

func TestNewKeyringRefusesZeroBounds(t *testing.T) {
	h := cheapHasher(t)
	if _, err := NewKeyring(KeyringOptions{}, h, &core.Counters{}); err == nil {
		t.Fatal("zero bounds taken")
	}
	if _, err := NewKeyring(KeyringOptions{MaxSkew: time.Second, NonceMemory: 1, MaxDatagramBytes: 1, HashSlots: 1, BadCache: 1}, nil, &core.Counters{}); err == nil {
		t.Fatal("nil hasher taken")
	}
}
