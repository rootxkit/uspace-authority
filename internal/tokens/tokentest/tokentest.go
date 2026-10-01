// Package tokentest makes RSA keys for tests at run time (spec 06 §4:
// no key, not even a test key, is ever in the repository). Keys are
// generated once per test binary and shared; files are written into the
// test's temporary directory. Imported by _test.go files only.
package tokentest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

var (
	mu   sync.Mutex
	keys []*rsa.PrivateKey
)

// Key returns the i-th shared 2048-bit test key, generating it on first
// use.
func Key(t testing.TB, i int) *rsa.PrivateKey {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	for len(keys) <= i {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	return keys[i]
}

// PEM encodes key as PKCS #8.
func PEM(t testing.TB, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// WriteKey writes the i-th shared key as a PEM file in dir and returns
// its path.
func WriteKey(t testing.TB, dir string, i int) string {
	t.Helper()
	p := filepath.Join(dir, "key-"+strconv.Itoa(i)+".pem")
	if err := os.WriteFile(p, PEM(t, Key(t, i)), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
