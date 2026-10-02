package registry

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// HashKeyBytes is the length of the registry hash key.
const HashKeyBytes = 32

// saltBytes is the per-row salt of a secret part.
const saltBytes = 16

// Hasher derives the stored, one-way forms of a registry secret (spec
// 06 §5, D9): HMAC-SHA-256 under a key read from REGISTRY_HASH_KEY_FILE,
// which the database never sees. A three-character secret part has too
// few values for a salt alone to protect it; the key does. The national
// id is hashed without a row salt so a person is found again (one
// registration per person), and the key keeps it from being enumerated
// from the database alone.
type Hasher struct {
	key []byte
}

// NewHasher builds a hasher from a 32-byte key.
func NewHasher(key []byte) (*Hasher, error) {
	if len(key) != HashKeyBytes {
		return nil, core.Fieldf("REGISTRY_HASH_KEY_FILE", "the key is %d bytes, not %d", len(key), HashKeyBytes)
	}
	return &Hasher{key: append([]byte(nil), key...)}, nil
}

// LoadHasher reads the key from path: 32 bytes in standard base64 on one
// line (openssl rand -base64 32), as internal/pii reads the PII key.
func LoadHasher(path string) (*Hasher, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return nil, core.Fieldf("REGISTRY_HASH_KEY_FILE", "%q cannot be read: %v", path, errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, core.Fieldf("REGISTRY_HASH_KEY_FILE", "%q cannot be read", path)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, core.Fieldf("REGISTRY_HASH_KEY_FILE", "%q is not one line of base64 (openssl rand -base64 32)", path)
	}
	return NewHasher(key)
}

func (h *Hasher) mac(domain string, parts ...[]byte) string {
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(domain))
	m.Write([]byte{0})
	for _, p := range parts {
		m.Write(p)
	}
	return hex.EncodeToString(m.Sum(nil))
}

// PersonRef is the stored form of a national id (trimmed first).
func (h *Hasher) PersonRef(ref string) string {
	return h.mac("person_ref", []byte(normalPersonRef(ref)))
}

// NewSecretPart salts and hashes a secret part.
func (h *Hasher) NewSecretPart(secret string) (salt []byte, hash string, err error) {
	salt = make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, "", err
	}
	return salt, h.SecretPart(salt, secret), nil
}

// SecretPart is the hash of secret under salt.
func (h *Hasher) SecretPart(salt []byte, secret string) string {
	return h.mac("secret_part", salt, []byte(secret))
}

// SecretPartMatches compares a presented secret part with the stored
// hash in constant time.
func (h *Hasher) SecretPartMatches(salt []byte, hash, secret string) bool {
	return hmac.Equal([]byte(h.SecretPart(salt, secret)), []byte(hash))
}
