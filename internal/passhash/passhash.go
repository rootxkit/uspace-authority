// Package passhash hashes and verifies secrets that a person or a client
// presents: console passwords (internal/authz) and OAuth client secrets
// (internal/tokens). It is argon2id from golang.org/x/crypto/argon2 in
// the PHC string format, compared in constant time. Nothing here is a
// hand-written primitive: the package chooses parameters, encodes and
// compares.
//
// Parameters: the defaults are the OWASP Password Storage Cheat Sheet's
// argon2id recommendation current at the time of writing (2026-10):
// "a minimum configuration of 19 MiB of memory, an iteration count of 2,
// and 1 degree of parallelism" (m=19456 KiB, t=2, p=1), with a 16-byte
// salt and a 32-byte tag. They come from configuration
// (ARGON2_MEMORY_KIB, ARGON2_TIME, ARGON2_THREADS, internal/config),
// whose lower bounds are that minimum. A stored hash carries its own
// parameters, so raising them never locks anyone out; NeedsRehash says
// when a stored hash is weaker than the current parameters.
package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// OWASP minimum argon2id parameters (see the package comment).
const (
	DefaultMemoryKiB = 19456
	DefaultTime      = 2
	DefaultThreads   = 1
	SaltBytes        = 16
	TagBytes         = 32
	// MaxSecretBytes bounds what is hashed: a longer input is refused
	// before any work, so a request cannot make the server hash megabytes.
	MaxSecretBytes = 1024
	// Upper bounds of a stored hash's parameters: a hash string outside
	// them is refused rather than run (a corrupted or planted row must not
	// make one verification take gigabytes).
	maxMemoryKiB = 4 << 20
	maxTime      = 100
	maxThreads   = 64
)

// ErrMalformed is a stored hash that is not an argon2id PHC string within
// the bounds above.
var ErrMalformed = errors.New("not an argon2id hash string")

// Params are the argon2id parameters of new hashes.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// Default is the OWASP minimum.
func Default() Params {
	return Params{MemoryKiB: DefaultMemoryKiB, Time: DefaultTime, Threads: DefaultThreads}
}

// Validate refuses parameters that would make a weak or absurd hash.
func (p Params) Validate() error {
	if p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxMemoryKiB || p.Time < 1 || p.Time > maxTime || p.Threads < 1 || p.Threads > maxThreads {
		return fmt.Errorf("argon2id parameters m=%d t=%d p=%d are out of bounds", p.MemoryKiB, p.Time, p.Threads)
	}
	return nil
}

// Hasher hashes with fixed parameters and holds a dummy hash of the same
// cost, so a lookup that finds nothing can spend the same time as one
// that finds a wrong secret (no user or client enumeration by timing).
type Hasher struct {
	p     Params
	dummy string
}

// New returns a Hasher for p.
func New(p Params) (*Hasher, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	h := &Hasher{p: p}
	var junk [32]byte
	if _, err := rand.Read(junk[:]); err != nil {
		return nil, err
	}
	d, err := h.Hash(base64.RawStdEncoding.EncodeToString(junk[:]))
	if err != nil {
		return nil, err
	}
	h.dummy = d
	return h, nil
}

// Params returns the hasher's parameters.
func (h *Hasher) Params() Params { return h.p }

// Hash returns the PHC string of secret with a random salt.
func (h *Hasher) Hash(secret string) (string, error) {
	if len(secret) > MaxSecretBytes {
		return "", fmt.Errorf("secret longer than %d bytes", MaxSecretBytes)
	}
	salt := make([]byte, SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	tag := argon2.IDKey([]byte(secret), salt, h.p.Time, h.p.MemoryKiB, h.p.Threads, TagBytes)
	return encode(h.p, salt, tag), nil
}

func encode(p Params, salt, tag []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(tag))
}

// Verify reports whether secret matches encoded. A secret longer than
// MaxSecretBytes is a mismatch after the same work as any other
// mismatch, and a malformed hash is an error after the work of the
// dummy, so neither answers faster.
func (h *Hasher) Verify(secret, encoded string) (bool, error) {
	ok, err := h.verify(secret, encoded)
	if err != nil {
		h.VerifyDummy(secret)
		return false, err
	}
	return ok && len(secret) <= MaxSecretBytes, nil
}

// VerifyDummy spends the work of one verification and reports nothing:
// the path taken when there is no stored hash to compare with.
func (h *Hasher) VerifyDummy(secret string) {
	_, _ = h.verify(secret, h.dummy)
}

func (h *Hasher) verify(secret, encoded string) (bool, error) {
	p, salt, tag, err := decode(encoded)
	if err != nil {
		return false, err
	}
	if len(secret) > MaxSecretBytes {
		secret = secret[:MaxSecretBytes]
	}
	got := argon2.IDKey([]byte(secret), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(tag)))
	return subtle.ConstantTimeCompare(got, tag) == 1, nil
}

// NeedsRehash reports whether encoded was made with weaker parameters
// than the hasher's (or does not parse).
func (h *Hasher) NeedsRehash(encoded string) bool {
	p, _, _, err := decode(encoded)
	if err != nil {
		return true
	}
	return p.MemoryKiB < h.p.MemoryKiB || p.Time < h.p.Time || p.Threads < h.p.Threads
}

// decode parses $argon2id$v=19$m=..,t=..,p=..$salt$tag.
func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Params{}, nil, nil, ErrMalformed
	}
	var p Params
	for i, kv := range strings.Split(parts[3], ",") {
		name, val, ok := strings.Cut(kv, "=")
		want := [...]string{"m", "t", "p"}
		if !ok || i > 2 || name != want[i] {
			return Params{}, nil, nil, ErrMalformed
		}
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return Params{}, nil, nil, ErrMalformed
		}
		switch i {
		case 0:
			p.MemoryKiB = uint32(n)
		case 1:
			p.Time = uint32(n)
		default:
			if n > 255 {
				return Params{}, nil, nil, ErrMalformed
			}
			p.Threads = uint8(n)
		}
	}
	if p.Validate() != nil {
		return Params{}, nil, nil, ErrMalformed
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return Params{}, nil, nil, ErrMalformed
	}
	tag, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(tag) < 16 || len(tag) > 64 {
		return Params{}, nil, nil, ErrMalformed
	}
	return p, salt, tag, nil
}
