package authz

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
)

// TOTP parameters (RFC 6238 defaults every authenticator app reads):
// SHA-1, 6 digits, 30 s period, a 160-bit secret, one step of skew on
// each side.
const (
	TOTPPeriod     = 30 * time.Second
	TOTPSkewSteps  = 1
	TOTPSecretSize = 20
)

// NewTOTPSecret makes an enrolment: the base32 secret and the otpauth
// URI authenticator apps scan. Generation and the HMAC are
// pquerna/otp's.
func NewTOTPSecret(issuer, account string) (secret, uri string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account, SecretSize: TOTPSecretSize})
	if err != nil {
		return "", "", err
	}
	return k.Secret(), k.URL(), nil
}

// TOTPURI renders the otpauth URI of an existing secret (a pending
// enrolment shown again).
func TOTPURI(issuer, account, secret string) (string, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	k, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account, Secret: raw})
	if err != nil {
		return "", err
	}
	return k.URL(), nil
}

// VerifyTOTP checks code against secret at now, within one step of skew,
// and returns the time step it matched. A step at or before lastStep is
// refused: each code is accepted once (RFC 6238 §5.2). The comparison
// is pquerna/otp's constant-time one.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	step := now.Unix() / int64(TOTPPeriod/time.Second)
	for d := int64(-TOTPSkewSteps); d <= TOTPSkewSteps; d++ {
		s := step + d
		if s <= lastStep || s < 0 {
			continue
		}
		ok, err := hotp.ValidateCustom(code, uint64(s), secret, hotp.ValidateOpts{Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && ok {
			return s, true
		}
	}
	return 0, false
}

// RecoveryCodes is how many recovery codes an enrolment gets.
const RecoveryCodes = 10

// NewRecoveryCodes makes n codes of 80 random bits, shown as four groups
// of four base32 characters, and their hashes (what is stored).
func NewRecoveryCodes(n int) (codes, hashes []string, err error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for range n {
		var b [10]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, nil, err
		}
		s := strings.ToLower(enc.EncodeToString(b[:]))
		code := s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode is the stored form of a recovery code: SHA-256 of the
// code without separators, lower-case. The code carries 80 random bits,
// so a fast hash does not make it guessable.
func HashRecoveryCode(code string) string {
	norm := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// MatchRecoveryCode returns the index of code among hashes, comparing
// every hash in constant time, or -1.
func MatchRecoveryCode(code string, hashes []string) int {
	if len(code) > 64 {
		return -1
	}
	h := []byte(HashRecoveryCode(code))
	found := -1
	for i, stored := range hashes {
		if subtle.ConstantTimeCompare(h, []byte(stored)) == 1 && found < 0 {
			found = i
		}
	}
	return found
}
