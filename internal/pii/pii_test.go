package pii

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rootxkit/uspace-core/core"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, KeyBytes) }

func TestSealOpensForItsRowOnly(t *testing.T) {
	s, err := NewSealer("pii-1", testKey(7))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("user_mfa:u-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("JBSWY3DP")) {
		t.Fatal("plaintext visible")
	}
	got, err := s.Open("pii-1", sealed, []byte("user_mfa:u-1"))
	if err != nil || string(got) != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("accepted twin: %q %v", got, err)
	}
	other, _ := NewSealer("pii-1", testKey(8))
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	for name, open := range map[string]func() ([]byte, error){
		"another row": func() ([]byte, error) { return s.Open("pii-1", sealed, []byte("user_mfa:u-2")) },
		"another id":  func() ([]byte, error) { return s.Open("pii-2", sealed, []byte("user_mfa:u-1")) },
		"another key": func() ([]byte, error) { return other.Open("pii-1", sealed, []byte("user_mfa:u-1")) },
		"tampered":    func() ([]byte, error) { return s.Open("pii-1", tampered, []byte("user_mfa:u-1")) },
		"short":       func() ([]byte, error) { return s.Open("pii-1", sealed[:5], []byte("user_mfa:u-1")) },
	} {
		if _, err := open(); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	again, _ := s.Seal([]byte("JBSWY3DPEHPK3PXP"), []byte("user_mfa:u-1"))
	if bytes.Equal(again, sealed) {
		t.Fatal("two seals share a nonce")
	}
}

func TestLoadSealerNamesTheVariable(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "pii.key")
	_ = os.WriteFile(good, []byte(base64.StdEncoding.EncodeToString(testKey(1))+"\n"), 0o600)
	if s, err := LoadSealer("pii-1", good); err != nil || s.KeyID() != "pii-1" {
		t.Fatalf("accepted twin: %v", err)
	}
	short := filepath.Join(dir, "short.key")
	_ = os.WriteFile(short, []byte(base64.StdEncoding.EncodeToString(testKey(1)[:16])), 0o600)
	garbage := filepath.Join(dir, "garbage.key")
	_ = os.WriteFile(garbage, []byte("not base64!"), 0o600)
	for _, p := range []string{filepath.Join(dir, "absent"), short, garbage} {
		var fe *core.FieldError
		if _, err := LoadSealer("pii-1", p); !errors.As(err, &fe) || fe.Field != "PII_KEY_FILE" {
			t.Errorf("%s: %v", p, err)
		}
	}
	var fe *core.FieldError
	if _, err := LoadSealer("bad id!", good); !errors.As(err, &fe) || fe.Field != "PII_KEY_ID" {
		t.Errorf("key id: %v", err)
	}
}

func FuzzOpen(f *testing.F) {
	s, _ := NewSealer("pii-1", testKey(3))
	sealed, _ := s.Seal([]byte("x"), []byte("a"))
	f.Add(sealed, []byte("a"))
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, sealed, aad []byte) {
		out, err := s.Open("pii-1", sealed, aad)
		if err == nil && string(out) != "x" {
			t.Fatalf("opened forged bytes to %q", out)
		}
	})
}

// Plan D9: the occurrence key must not be the PII key. SameKey tells two
// keys apart whatever their ids, and holds the same key under two ids
// together (E-01 pair).
func TestSameKey(t *testing.T) {
	a, _ := NewSealer("pii-1", testKey(7))
	b, _ := NewSealer("occ-1", testKey(7))
	c, _ := NewSealer("pii-1", testKey(8))
	if !a.SameKey(b) {
		t.Fatal("the same key under another id is another key")
	}
	if a.SameKey(c) {
		t.Fatal("another key under the same id is the same key")
	}
	if a.SameKey(nil) || (*Sealer)(nil).SameKey(a) {
		t.Fatal("a missing sealer has the same key")
	}
}

// LoadSealerAs names its own variables in every refusal, and loads a
// valid key like LoadSealer.
func TestLoadSealerAsNamesItsVariables(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadSealerAs("OCCURRENCE_KEY_ID", "OCCURRENCE_KEY_FILE", "occ-1", filepath.Join(dir, "absent")); !isField(err, "OCCURRENCE_KEY_FILE") {
		t.Fatalf("absent: %v", err)
	}
	p := filepath.Join(dir, "occ.key")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(testKey(9))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSealerAs("OCCURRENCE_KEY_ID", "OCCURRENCE_KEY_FILE", "bad id!", p); !isField(err, "OCCURRENCE_KEY_ID") {
		t.Fatalf("bad id: %v", err)
	}
	s, err := LoadSealerAs("OCCURRENCE_KEY_ID", "OCCURRENCE_KEY_FILE", "occ-1", p)
	if err != nil || s.KeyID() != "occ-1" {
		t.Fatalf("%v %v", s, err)
	}
}

func isField(err error, field string) bool {
	var fe *core.FieldError
	return errors.As(err, &fe) && fe.Field == field
}
