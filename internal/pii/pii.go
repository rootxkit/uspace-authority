package pii

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/rootxkit/uspace-core/core"
)

// KeyBytes is the AES-256 key length.
const KeyBytes = 32

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// Sealer seals and opens values with one key.
type Sealer struct {
	keyID string
	aead  cipher.AEAD
	// fp tells two sealers' keys apart without keeping the key (SameKey).
	fp [sha256.Size]byte
}

// NewSealer builds a sealer from a 32-byte key under keyID.
func NewSealer(keyID string, key []byte) (*Sealer, error) {
	return newSealer("PII_KEY_ID", "PII_KEY_FILE", keyID, key)
}

func newSealer(idVar, fileVar, keyID string, key []byte) (*Sealer, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, core.Fieldf(idVar, "%q is not 1 to 32 of [A-Za-z0-9._-]", keyID)
	}
	if len(key) != KeyBytes {
		return nil, core.Fieldf(fileVar, "the key is %d bytes, not %d", len(key), KeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{keyID: keyID, aead: aead, fp: sha256.Sum256(append([]byte("uspace-authority sealer key/"), key...))}, nil
}

// LoadSealer reads the key from path: 32 bytes in standard base64 (one
// line, as `openssl rand -base64 32` writes it).
func LoadSealer(keyID, path string) (*Sealer, error) {
	return LoadSealerAs("PII_KEY_ID", "PII_KEY_FILE", keyID, path)
}

// LoadSealerAs is LoadSealer for a key configured by other variables
// (OCCURRENCE_KEY_ID, OCCURRENCE_KEY_FILE): its errors name them.
func LoadSealerAs(idVar, fileVar, keyID, path string) (*Sealer, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return nil, core.Fieldf(fileVar, "%q cannot be read: %v", path, errors.Unwrap(err))
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, core.Fieldf(fileVar, "%q cannot be read", path)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, core.Fieldf(fileVar, "%q is not one line of base64 (openssl rand -base64 32)", path)
	}
	return newSealer(idVar, fileVar, keyID, key)
}

// SameKey reports whether s and o seal with the same key bytes, whatever
// their key ids: a key that must be separate from another (the
// occurrence key from the PII key, plan D9) is checked with it.
func (s *Sealer) SameKey(o *Sealer) bool {
	if s == nil || o == nil {
		return false
	}
	return subtle.ConstantTimeCompare(s.fp[:], o.fp[:]) == 1
}

// KeyID is the id stored beside every value this sealer seals.
func (s *Sealer) KeyID() string { return s.keyID }

// Seal encrypts plaintext bound to aad: a random 96-bit nonce followed by
// the GCM ciphertext and tag.
func (s *Sealer) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// ErrOpen is a value that does not open: another key id, another row,
// or tampered bytes.
var ErrOpen = errors.New("sealed value does not open")

// Open decrypts a value sealed under keyID with aad.
func (s *Sealer) Open(keyID string, sealed, aad []byte) ([]byte, error) {
	if keyID != s.keyID {
		return nil, fmt.Errorf("%w: key id %q is not the configured %q", ErrOpen, keyID, s.keyID)
	}
	n := s.aead.NonceSize()
	if len(sealed) < n+s.aead.Overhead() {
		return nil, ErrOpen
	}
	out, err := s.aead.Open(nil, sealed[:n], sealed[n:], aad)
	if err != nil {
		return nil, ErrOpen
	}
	return out, nil
}
