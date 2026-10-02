package registry

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
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

// Assemble refuses a missing key before it opens anything, and on the
// real telemetry database opens the projector pool (E-02 both ways).
func TestIntegrationAssemble(t *testing.T) {
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	pii := writeFile(t, "pii.key", base64.StdEncoding.EncodeToString(randomKey(t)))
	hash := writeFile(t, "hash.key", base64.StdEncoding.EncodeToString(randomKey(t)))
	ctx := context.Background()
	if _, err := Assemble(ctx, Setup{PIIKeyID: "pii-1", PIIKeyFile: pii, HashKeyFile: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Fatal("assembled without a hash key")
	}
	if _, err := Assemble(ctx, Setup{PIIKeyID: "pii-1", PIIKeyFile: filepath.Join(t.TempDir(), "absent"), HashKeyFile: hash}); err == nil {
		t.Fatal("assembled without a PII key")
	}
	if _, err := Assemble(ctx, Setup{PIIKeyID: "pii-1", PIIKeyFile: pii, HashKeyFile: hash, TSURL: "postgres://u:p@127.0.0.1:1/x?connect_timeout=1"}); err == nil {
		t.Fatal("assembled without the telemetry database")
	}
	p, err := Assemble(ctx, Setup{PIIKeyID: "pii-1", PIIKeyFile: pii, HashKeyFile: hash, TSURL: tsURL, TSRole: "authority_ts_projector", TSMaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Projector.Ping(ctx); err != nil || p.Service.Publisher == nil || p.Handler.Service != p.Service {
		t.Fatalf("parts %+v %v", p, err)
	}
}
