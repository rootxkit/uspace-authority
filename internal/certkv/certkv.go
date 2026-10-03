// Package certkv is the certificate register as it travels from api to
// dp-poller (WP-16 for WP-14): the USSPs whose certificate is operating
// or limited, published by api to KV bucket certificates under key
// "ussps" after every commit that changes a certificate and republished
// periodically, with the register's version (the database's
// certificates_version_seq), never replacing a higher one. dp-poller
// never opens the relational database (B-15); it reads this value to
// tell a certified Service Provider from one shown provider_unknown.
// The package holds the shape, its bounds (E-10) and the KV operations;
// nothing here decides what is certified.
package certkv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/nats-io/nats.go/jetstream"
)

// Bucket and key.
const (
	Bucket = "certificates"
	Key    = "ussps"
)

// Bounds (E-10).
const (
	// MaxUSSPs bounds the USSPs of one value (cis/ussp_list/v1 holds at
	// most 200; the register here is bounded the same way).
	MaxUSSPs = 200
	// ValueBytes bounds the KV value.
	ValueBytes = 128 << 10
	// MaxBaseURL bounds one base URL.
	MaxBaseURL = 2048
)

// USSP is one certified USSP.
type USSP struct {
	// ClientID is its client at this issuer (ussp-<code>-01): the
	// subject of its tokens and the owner of its ISAs at the DSS.
	ClientID string `json:"client_id"`
	Code     string `json:"code"`
	BaseURL  string `json:"base_url"`
	// Status is operating or limited.
	Status string `json:"status"`
}

// Register is the KV value.
type Register struct {
	Version int64  `json:"version"`
	USSPs   []USSP `json:"ussps"`
}

// ErrMalformed is a value that is not a Register.
var ErrMalformed = errors.New("certificate register value malformed")

var (
	clientPattern = regexp.MustCompile(`^ussp-[A-Z0-9]{1,8}-[0-9]{2}$`)
	codePattern   = regexp.MustCompile(`^[A-Z0-9]{1,8}$`)
)

// Check refuses a register a reader must not take: over the bounds, a
// version below zero, an entry whose client id, code, base URL or
// status is not of the shape api writes.
func (r Register) Check() error {
	if r.Version < 0 {
		return fmt.Errorf("%w: version %d", ErrMalformed, r.Version)
	}
	if len(r.USSPs) > MaxUSSPs {
		return fmt.Errorf("%w: %d USSPs, at most %d", ErrMalformed, len(r.USSPs), MaxUSSPs)
	}
	for i, u := range r.USSPs {
		switch {
		case !clientPattern.MatchString(u.ClientID):
			return fmt.Errorf("%w: ussps[%d].client_id", ErrMalformed, i)
		case !codePattern.MatchString(u.Code):
			return fmt.Errorf("%w: ussps[%d].code", ErrMalformed, i)
		case u.BaseURL == "" || len(u.BaseURL) > MaxBaseURL:
			return fmt.Errorf("%w: ussps[%d].base_url", ErrMalformed, i)
		case u.Status != "operating" && u.Status != "limited":
			return fmt.Errorf("%w: ussps[%d].status", ErrMalformed, i)
		}
	}
	return nil
}

// Decode reads a value, bounded; a bad entry refuses the whole value
// (the reader keeps what it holds).
func Decode(raw []byte) (Register, error) {
	if len(raw) > ValueBytes {
		return Register{}, fmt.Errorf("%w: %d bytes", ErrMalformed, len(raw))
	}
	var r Register
	if err := json.Unmarshal(raw, &r); err != nil {
		return Register{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := r.Check(); err != nil {
		return Register{}, err
	}
	return r, nil
}

// ClientIDs is the set of the register's client ids.
func (r Register) ClientIDs() map[string]bool {
	out := make(map[string]bool, len(r.USSPs))
	for _, u := range r.USSPs {
		out[u.ClientID] = true
	}
	return out
}

// BucketConfig is the bucket: no TTL, the register stays until api
// replaces it. name empty is Bucket.
func BucketConfig(name string) jetstream.KeyValueConfig {
	if name == "" {
		name = Bucket
	}
	return jetstream.KeyValueConfig{
		Bucket: name, Description: "the certified USSPs (WP-16): one key, every USSP operating or limited",
		History: 8, MaxValueSize: ValueBytes, MaxBytes: -1, Storage: jetstream.FileStorage, Replicas: 1,
	}
}

// Put stores r unless the bucket holds a higher version, with
// compare-and-set so two writers never interleave (at most attempts
// tries). It reports whether r was stored.
func Put(ctx context.Context, kv jetstream.KeyValue, r Register, attempts int) (bool, error) {
	if err := r.Check(); err != nil {
		return false, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return false, err
	}
	if len(data) > ValueBytes {
		return false, fmt.Errorf("the register is %d bytes, at most %d", len(data), ValueBytes)
	}
	var last error
	for range max(1, attempts) {
		e, err := kv.Get(ctx, Key)
		switch {
		case errors.Is(err, jetstream.ErrKeyNotFound):
			if _, last = kv.Create(ctx, Key, data); last == nil {
				return true, nil
			}
			continue
		case err != nil:
			return false, err
		}
		if held, err := Decode(e.Value()); err == nil && held.Version > r.Version {
			return false, nil
		}
		if _, last = kv.Update(ctx, Key, data, e.Revision()); last == nil {
			return true, nil
		}
	}
	return false, last
}
