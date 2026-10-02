package receivers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// SignatureHeader carries the hex HMAC-SHA256 of the exact body bytes
// (docs/runbooks/receivers.md). The body and this header together are the
// datagram uspace-core auth.ReceiverVerifier verifies: body + "\nsig=" +
// header (Datagram).
const SignatureHeader = "X-Report-Signature"

// HMACSecretBytes is the length of a generated HMAC secret: core's minimum
// receiver key (LESSONS R-06).
const HMACSecretBytes = auth.MinReceiverKeyBytes

// bearerSecretBytes is the random part of a bearer key.
const bearerSecretBytes = 32

// MaxBearerBytes bounds the Authorization value read before anything is
// parsed or hashed: an id of at most 63 bytes, a dot and 43 base64url
// characters, with room to spare.
const MaxBearerBytes = 256

// idPattern is the receiver id slug (migration 00010_rid_receivers).
var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// ValidID reports whether id is a receiver slug.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// Credentials are a receiver's keys of one generation, shown once.
type Credentials struct {
	Generation    int
	BearerKey     string
	HMACSecretHex string
}

// GenerateCredentials returns new credentials for receiver id: a bearer key
// "<id>.<43 base64url characters>" naming the receiver, and a separate
// 32-byte HMAC secret (spec 02 F9: a captured bearer key alone cannot sign).
func GenerateCredentials(id string, generation int) (Credentials, []byte, error) {
	var b [bearerSecretBytes]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Credentials{}, nil, err
	}
	secret := make([]byte, HMACSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return Credentials{}, nil, err
	}
	return Credentials{
		Generation:    generation,
		BearerKey:     id + "." + base64.RawURLEncoding.EncodeToString(b[:]),
		HMACSecretHex: hex.EncodeToString(secret),
	}, secret, nil
}

// ParseBearer reads an Authorization header value ("Bearer <id>.<secret>")
// and returns the receiver id it names and the whole key. Nothing is
// trusted yet: the key still has to match the receiver's stored hash.
func ParseBearer(header string) (id, key string, err error) {
	if header == "" {
		return "", "", &core.FieldError{Field: "Authorization", Reason: "no bearer key"}
	}
	if len(header) > MaxBearerBytes {
		return "", "", core.Fieldf("Authorization", "longer than %d bytes", MaxBearerBytes)
	}
	scheme, key, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", "", &core.FieldError{Field: "Authorization", Reason: "not a bearer key"}
	}
	key = strings.TrimSpace(key)
	id, secret, ok := strings.Cut(key, ".")
	if !ok || !ValidID(id) || len(secret) != base64.RawURLEncoding.EncodedLen(bearerSecretBytes) {
		return "", "", &core.FieldError{Field: "Authorization", Reason: "not a receiver key"}
	}
	if _, err := base64.RawURLEncoding.Strict().DecodeString(secret); err != nil {
		return "", "", &core.FieldError{Field: "Authorization", Reason: "not a receiver key"}
	}
	return id, key, nil
}

// Datagram is the bytes core verifies for a request: the exact body,
// then "\nsig=" and the header's signature (auth.Datagram). Without a
// signature header it is the body alone, which core refuses as unsigned.
func Datagram(body []byte, signature string) []byte {
	if signature == "" {
		return body
	}
	return auth.Datagram(body, signature)
}
