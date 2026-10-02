package passhash

import (
	"strings"
	"testing"
)

// cheap are test parameters: the bounds allow them, the configuration
// does not (its minimum is the OWASP one).
var cheap = Params{MemoryKiB: 64, Time: 1, Threads: 1}

func newCheap(t testing.TB) *Hasher {
	t.Helper()
	h, err := New(cheap)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// E-01: the right secret is accepted, a wrong one refused.
func TestHashVerifiesTheSecretAndRefusesAnother(t *testing.T) {
	h := newCheap(t)
	enc, err := h.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("encoding %q", enc)
	}
	if ok, err := h.Verify("correct horse", enc); !ok || err != nil {
		t.Fatalf("right secret: %v %v", ok, err)
	}
	if ok, err := h.Verify("correct horsf", enc); ok || err != nil {
		t.Fatalf("wrong secret: %v %v", ok, err)
	}
	other, _ := h.Hash("correct horse")
	if other == enc {
		t.Fatal("two hashes of one secret share a salt")
	}
}

func TestDefaultIsTheOWASPMinimum(t *testing.T) {
	if d := Default(); d.MemoryKiB != 19456 || d.Time != 2 || d.Threads != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestOverlongSecretIsRefusedAfterTheWork(t *testing.T) {
	h := newCheap(t)
	long := strings.Repeat("a", MaxSecretBytes+1)
	if _, err := h.Hash(long); err == nil {
		t.Fatal("hashed an overlong secret")
	}
	enc, _ := h.Hash(long[:MaxSecretBytes])
	if ok, err := h.Verify(long, enc); ok || err != nil {
		t.Fatalf("overlong secret matched its prefix: %v %v", ok, err)
	}
	if ok, _ := h.Verify(long[:MaxSecretBytes], enc); !ok {
		t.Fatal("the secret of exactly the bound was refused")
	}
}

func TestMalformedHashesAreRefused(t *testing.T) {
	h := newCheap(t)
	good, _ := h.Hash("x")
	parts := strings.Split(good, "$")
	bad := []string{
		"", "plain", "$argon2i$v=19$m=64,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=18$m=64,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$t=1,m=64,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=64,t=1,p=1,x=2$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=99999999,t=1,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=64,t=0,p=1$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=64,t=1,p=300$" + parts[4] + "$" + parts[5],
		"$argon2id$v=19$m=64,t=1,p=1$!!$" + parts[5],
		"$argon2id$v=19$m=64,t=1,p=1$" + parts[4] + "$AAAA",
	}
	for _, b := range bad {
		if ok, err := h.Verify("x", b); ok || err == nil {
			t.Errorf("%q: ok %v err %v", b, ok, err)
		}
	}
	if !h.NeedsRehash("garbage") {
		t.Error("a malformed hash does not need a rehash")
	}
}

func TestNeedsRehashWhenParametersRise(t *testing.T) {
	weak := newCheap(t)
	enc, _ := weak.Hash("x")
	if weak.NeedsRehash(enc) {
		t.Fatal("same parameters need a rehash")
	}
	strong, err := New(Params{MemoryKiB: 128, Time: 2, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strong.NeedsRehash(enc) {
		t.Fatal("weaker hash does not need a rehash")
	}
	// A hash made with the old parameters still verifies.
	if ok, _ := strong.Verify("x", enc); !ok {
		t.Fatal("raising the parameters locked the secret out")
	}
}

func TestParamsBounds(t *testing.T) {
	for _, p := range []Params{{0, 1, 1}, {64, 0, 1}, {64, 1, 0}, {64, 101, 1}, {8, 1, 2}, {maxMemoryKiB + 1, 1, 1}} {
		if _, err := New(p); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestDummyVerificationDoesTheWork(t *testing.T) {
	h := newCheap(t)
	if h.dummy == "" || !strings.HasPrefix(h.dummy, "$argon2id$") {
		t.Fatalf("dummy %q", h.dummy)
	}
	h.VerifyDummy("anything") // must not panic, reports nothing
}

// Hash strings come from the database; fuzz the parser so a planted or
// corrupted row cannot crash or stall a verification.
func FuzzVerify(f *testing.F) {
	h := newCheap(f)
	good, _ := h.Hash("seed")
	f.Add("seed", good)
	f.Add("", "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$dGFn")
	f.Add("x", "$$$$$")
	f.Fuzz(func(t *testing.T, secret, encoded string) {
		if p, _, _, err := decode(encoded); err == nil && (p.MemoryKiB > 4096 || p.Time > 4) {
			t.Skip("valid but expensive parameters: the work, not the parser, would be measured")
		}
		ok, err := h.Verify(secret, encoded)
		if ok && err != nil {
			t.Fatal("accepted with an error")
		}
		if ok && encoded != good {
			// Only the seed hash can match; anything else matching means
			// the comparison is broken.
			if _, _, _, derr := decode(encoded); derr != nil {
				t.Fatalf("accepted %q", encoded)
			}
		}
	})
}
