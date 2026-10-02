package receivers

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

// Receiver statuses.
const (
	StatusEnabled  = "enabled"
	StatusDisabled = "disabled"
)

// MaxEntryBytes bounds a key-set entry read from the KV bucket before it
// is parsed (E-10).
const MaxEntryBytes = bus.RIDReceiverKeyValueBytes

// KeyGeneration is one generation of a receiver's keys as the key set
// carries it: the bearer key's argon2id hash and the HMAC secret. NotAfter
// is nil for the current generation and the end of the grace for the
// previous one.
type KeyGeneration struct {
	Generation    int        `json:"generation"`
	BearerHash    string     `json:"bearer_hash"`
	HMACSecretHex string     `json:"hmac_secret_hex"`
	NotAfter      *time.Time `json:"not_after"`
}

// Entry is one receiver in the key set (KV bucket rid_receiver_keys, key =
// receiver id): what rid-ingest needs to authenticate it and to refuse it
// when disabled, and nothing else.
//
// The HMAC secret travels in clear inside the bus: anything that can read
// this bucket can also publish tracks directly, so the bucket's access is
// the trust boundary (per-process NATS credentials, WP-10).
type Entry struct {
	ReceiverID     string          `json:"receiver_id"`
	Status         string          `json:"status"`
	DisabledBy     *string         `json:"disabled_by"`
	DisabledReason *string         `json:"disabled_reason"`
	LatDeg         float64         `json:"lat_deg"`
	LonDeg         float64         `json:"lon_deg"`
	Keys           []KeyGeneration `json:"keys"`
	Version        int64           `json:"version"`
}

// Enabled reports whether the registry has the receiver enabled.
func (e *Entry) Enabled() bool { return e.Status == StatusEnabled }

// Validate refuses an entry rid-ingest must not load, naming the field:
// a bad id (B-14), an unknown status, an invalid pinned position, no keys
// or more than two, a generation twice, a key that is not an argon2id hash
// or a secret shorter than core's minimum, and more than one current
// generation.
func (e *Entry) Validate() error {
	var errs []error
	if !ValidID(e.ReceiverID) {
		errs = append(errs, core.Fieldf("receiver_id", "%q is not a receiver id", short(e.ReceiverID)))
	}
	if e.Status != StatusEnabled && e.Status != StatusDisabled {
		errs = append(errs, core.Fieldf("status", "must be enabled or disabled"))
	}
	if !(core.LatLon{LatDeg: e.LatDeg, LonDeg: e.LonDeg}).Valid() {
		errs = append(errs, core.Fieldf("lat_deg", "the pinned position is not a valid position"))
	}
	if len(e.Keys) < 1 || len(e.Keys) > 2 {
		errs = append(errs, core.Fieldf("keys", "must hold one or two generations, got %d", len(e.Keys)))
	}
	current := 0
	seen := map[int]bool{}
	for _, k := range e.Keys {
		if k.Generation < 1 || seen[k.Generation] {
			errs = append(errs, core.Fieldf("keys", "generation %d is invalid or repeated", k.Generation))
		}
		seen[k.Generation] = true
		if !strings.HasPrefix(k.BearerHash, "$argon2id$") || len(k.BearerHash) > 512 {
			errs = append(errs, core.Fieldf("keys", "generation %d: the bearer hash is not argon2id", k.Generation))
		}
		if b, err := hex.DecodeString(k.HMACSecretHex); err != nil || len(b) < HMACSecretBytes || len(b) > 1024 {
			errs = append(errs, core.Fieldf("keys", "generation %d: the HMAC secret is not %d to 1024 bytes of hex", k.Generation, HMACSecretBytes))
		}
		if k.NotAfter == nil {
			current++
		}
	}
	if len(e.Keys) > 0 && current != 1 {
		errs = append(errs, core.Fieldf("keys", "exactly one current generation (not_after null), got %d", current))
	}
	return errors.Join(errs...)
}

// ParseEntry reads one key-set entry stored under key: bounded before it
// is parsed, strict JSON, validated, and its id equal to the key.
func ParseEntry(key string, raw []byte) (Entry, error) {
	if len(raw) > MaxEntryBytes {
		return Entry{}, core.Fieldf("entry", "%d bytes, longer than %d", len(raw), MaxEntryBytes)
	}
	var e Entry
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Entry{}, core.Fieldf("entry", "not a key-set entry: %v", err)
	}
	if dec.More() {
		return Entry{}, core.Fieldf("entry", "trailing data after the entry")
	}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	if e.ReceiverID != key {
		return Entry{}, core.Fieldf("receiver_id", "%q is stored under the key %q", short(e.ReceiverID), short(key))
	}
	return e, nil
}

// short bounds an untrusted string quoted in an error.
func short(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
