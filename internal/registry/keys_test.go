package registry

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The registry hash key is read like the PII key; every refusal names
// REGISTRY_HASH_KEY_FILE, and a good key is accepted (E-01).
func TestLoadHasher(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(randomKey(t))
	for _, c := range []struct{ name, path string }{
		{"missing", filepath.Join(t.TempDir(), "absent.key")},
		{"not base64", writeFile(t, "bad.key", "not base64!")},
		{"16 bytes", writeFile(t, "short.key", base64.StdEncoding.EncodeToString(make([]byte, 16)))},
	} {
		if _, err := LoadHasher(c.path); err == nil || !strings.Contains(err.Error(), "REGISTRY_HASH_KEY_FILE") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	h, err := LoadHasher(writeFile(t, "good.key", good+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := NewHasher(randomKey(t))
	if h.PersonRef(" 01001012345 ") != h.PersonRef("01001012345") || h.PersonRef("01001012345") == h2.PersonRef("01001012345") {
		t.Fatal("the national id hash is not keyed, or not trimmed")
	}
	salt, hash, err := h.NewSecretPart("x9z")
	if err != nil || !h.SecretPartMatches(salt, hash, "x9z") || h2.SecretPartMatches(salt, hash, "x9z") {
		t.Fatal("the secret part hash is not keyed")
	}
	salt2, hash2, _ := h.NewSecretPart("x9z")
	if hash2 == hash || bytes.Equal(salt2, salt) {
		t.Fatal("the secret part is not salted per row")
	}
}
