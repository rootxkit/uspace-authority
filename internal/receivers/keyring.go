package receivers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/passhash"
)

// Counter names of a Keyring (E-09).
const (
	CounterKeyMissing        = "key_missing"
	CounterKeyUnknown        = "key_unknown"
	CounterKeyCheckBusy      = "key_check_busy"
	CounterKeyChecks         = "key_argon2_checks"
	CounterBadKeyEvicted     = "bad_key_cache_evicted"
	CounterKeysetRefused     = "keyset_refused"
	CounterKeysetApplied     = "keyset_applied"
	CounterGenerationExpired = "key_generation_expired"
)

// Errors of Authenticate.
var (
	// ErrUnauthenticated is a missing, malformed or unknown bearer key,
	// or one whose generation's grace has ended (401).
	ErrUnauthenticated = errors.New("unknown receiver key")
	// ErrBusy is a bearer key that could not be checked now because the
	// argon2id budget is spent (503 with Retry-After).
	ErrBusy = errors.New("receiver key check busy")
)

// KeyringOptions configure a Keyring.
type KeyringOptions struct {
	// MaxSkew is core's sent_at_ms window (30 s, R-06).
	MaxSkew time.Duration
	// NonceMemory bounds the nonces remembered per receiver generation
	// (auth.WithNonceMemory, E-10).
	NonceMemory int
	// MaxDatagramBytes bounds what core parses (auth.WithMaxDatagramBytes):
	// the body cap plus the signature suffix.
	MaxDatagramBytes int
	// HashSlots bounds concurrent argon2id verifications of unknown
	// bearer keys (B-06, T8); beyond it a request waits up to
	// HashWait and is then refused as busy.
	HashSlots int
	HashWait  time.Duration
	// BadCache bounds the remembered failed bearer keys (E-10).
	BadCache int
}

// Generation is one generation of one receiver's keys with its verifier.
type Generation struct {
	ReceiverID string
	Number     int
	NotAfter   *time.Time

	bearerHash string
	secretSum  [32]byte
	verifier   *auth.ReceiverVerifier
}

// Verify checks the datagram (body + signature) with this generation's
// HMAC secret, its sent_at_ms window and its nonce memory (uspace-core
// auth.ReceiverVerifier.Verify; nothing here re-implements it).
func (g *Generation) Verify(datagram []byte, now time.Time) (auth.Report, error) {
	return g.verifier.Verify(datagram, now)
}

type keyed struct {
	entry Entry
	gens  []*Generation
}

// Keyring holds the receivers' key set with one core verifier per
// receiver generation. Replacing the set keeps the verifier, and so its
// nonce memory, of every generation whose secret did not change: a reload
// never reopens the replay window. It is safe for concurrent use.
type Keyring struct {
	opts     KeyringOptions
	hasher   *passhash.Hasher
	counters *core.Counters
	slots    chan struct{}

	mu      sync.RWMutex
	entries map[string]*keyed

	cacheMu sync.Mutex
	good    map[string][32]byte // bearer hash -> SHA-256 of the key it verified
	bad     map[[32]byte]struct{}
	badFIFO [][32]byte
}

// NewKeyring returns an empty keyring.
func NewKeyring(o KeyringOptions, hasher *passhash.Hasher, counters *core.Counters) (*Keyring, error) {
	if o.MaxSkew <= 0 || o.NonceMemory < 1 || o.MaxDatagramBytes < 1 || o.HashSlots < 1 || o.HashWait < 0 || o.BadCache < 1 {
		return nil, core.Fieldf("keyring", "every bound must be positive: %+v", o)
	}
	if hasher == nil || counters == nil {
		return nil, core.Fieldf("keyring", "a hasher and counters are required")
	}
	return &Keyring{
		opts: o, hasher: hasher, counters: counters, slots: make(chan struct{}, o.HashSlots),
		entries: map[string]*keyed{}, good: map[string][32]byte{}, bad: map[[32]byte]struct{}{},
	}, nil
}

// Counters returns the keyring's counters.
func (k *Keyring) Counters() *core.Counters { return k.counters }

// build makes the generations of e, reusing old's verifiers where the
// secret is unchanged.
func (k *Keyring) build(e Entry, old *keyed) (*keyed, error) {
	out := &keyed{entry: e}
	for _, kg := range e.Keys {
		secret, err := hex.DecodeString(kg.HMACSecretHex)
		if err != nil {
			return nil, core.Fieldf("keys", "%s generation %d: the secret is not hex", e.ReceiverID, kg.Generation)
		}
		sum := sha256.Sum256(secret)
		var reuse *auth.ReceiverVerifier
		if old != nil {
			for _, og := range old.gens {
				if og.Number == kg.Generation && og.secretSum == sum {
					reuse = og.verifier
				}
			}
		}
		if reuse == nil {
			// AddReceiverKey refuses an empty id and a short key with
			// core's own phrases (B-14).
			keys := map[string][]byte{}
			if err := auth.AddReceiverKey(keys, e.ReceiverID, secret); err != nil {
				return nil, err
			}
			reuse, err = auth.NewReceiverVerifier(keys, k.opts.MaxSkew,
				auth.WithNonceMemory(k.opts.NonceMemory), auth.WithMaxDatagramBytes(k.opts.MaxDatagramBytes))
			if err != nil {
				return nil, err
			}
		}
		out.gens = append(out.gens, &Generation{
			ReceiverID: e.ReceiverID, Number: kg.Generation, NotAfter: kg.NotAfter,
			bearerHash: kg.BearerHash, secretSum: sum, verifier: reuse,
		})
	}
	// The current generation is tried first.
	sort.SliceStable(out.gens, func(i, j int) bool { return out.gens[i].NotAfter == nil && out.gens[j].NotAfter != nil })
	return out, nil
}

// Replace installs a whole key set. An entry that does not validate, or
// a receiver id that appears twice, refuses the whole set (B-14) and the
// keyring keeps what it held.
func (k *Keyring) Replace(entries []Entry) error {
	ids := map[string][]byte{}
	for i := range entries {
		e := &entries[i]
		if err := e.Validate(); err != nil {
			k.counters.Inc(CounterKeysetRefused)
			return err
		}
		// A placeholder key: AddReceiverKey is core's duplicate and
		// empty-id check of a key file read line by line.
		if err := auth.AddReceiverKey(ids, e.ReceiverID, make([]byte, auth.MinReceiverKeyBytes)); err != nil {
			k.counters.Inc(CounterKeysetRefused)
			return err
		}
	}
	k.mu.RLock()
	built := make(map[string]*keyed, len(entries))
	for _, e := range entries {
		b, err := k.build(e, k.entries[e.ReceiverID])
		if err != nil {
			k.mu.RUnlock()
			k.counters.Inc(CounterKeysetRefused)
			return err
		}
		built[e.ReceiverID] = b
	}
	k.mu.RUnlock()
	k.mu.Lock()
	k.entries = built
	k.mu.Unlock()
	k.pruneGood()
	k.counters.Inc(CounterKeysetApplied)
	return nil
}

// Upsert installs or replaces one receiver's entry.
func (k *Keyring) Upsert(e Entry) error {
	if err := e.Validate(); err != nil {
		k.counters.Inc(CounterKeysetRefused)
		return err
	}
	k.mu.Lock()
	b, err := k.build(e, k.entries[e.ReceiverID])
	if err == nil {
		k.entries[e.ReceiverID] = b
	}
	k.mu.Unlock()
	if err != nil {
		k.counters.Inc(CounterKeysetRefused)
		return err
	}
	k.pruneGood()
	return nil
}

// Remove forgets a receiver (deleted from the registry).
func (k *Keyring) Remove(id string) {
	k.mu.Lock()
	delete(k.entries, id)
	k.mu.Unlock()
	k.pruneGood()
}

// Len is the number of receivers held.
func (k *Keyring) Len() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.entries)
}

// Lookup returns the entry of id.
func (k *Keyring) Lookup(id string) (Entry, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	e, ok := k.entries[id]
	if !ok {
		return Entry{}, false
	}
	return e.entry, true
}

// IDs lists the receivers held, sorted.
func (k *Keyring) IDs() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]string, 0, len(k.entries))
	for id := range k.entries {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// NoncesEvicted sums nonces_evicted over every verifier held (E-10: a
// nonce memory past its bound is counted, never silent).
func (k *Keyring) NoncesEvicted() uint64 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var n uint64
	for _, e := range k.entries {
		for _, g := range e.gens {
			n += g.verifier.Counters().Get(auth.CounterNoncesEvicted)
		}
	}
	return n
}

// Authenticate finds the receiver and the key generation an
// Authorization header names: the current generation, or the previous
// one until its grace ends. A key checked once is remembered by its
// SHA-256, so argon2id runs once per key and generation, not per
// request (B-06); a failed key is remembered too (bounded), and at most
// HashSlots argon2id checks run at once (T8).
func (k *Keyring) Authenticate(ctx context.Context, header string, now time.Time) (Entry, *Generation, error) {
	if header == "" {
		k.counters.Inc(CounterKeyMissing)
		return Entry{}, nil, ErrUnauthenticated
	}
	id, key, err := ParseBearer(header)
	if err != nil {
		k.counters.Inc(CounterKeyUnknown)
		return Entry{}, nil, ErrUnauthenticated
	}
	k.mu.RLock()
	e, ok := k.entries[id]
	k.mu.RUnlock()
	if !ok {
		k.counters.Inc(CounterKeyUnknown)
		return Entry{}, nil, ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(key))
	for _, g := range e.gens {
		if g.NotAfter != nil && !now.Before(*g.NotAfter) {
			continue
		}
		match, err := k.check(ctx, g.bearerHash, key, sum)
		if err != nil {
			return Entry{}, nil, err
		}
		if match {
			return e.entry, g, nil
		}
	}
	for _, g := range e.gens {
		if g.NotAfter != nil && !now.Before(*g.NotAfter) {
			if match, _ := k.cached(g.bearerHash, sum); match {
				k.counters.Inc(CounterGenerationExpired)
			}
		}
	}
	k.counters.Inc(CounterKeyUnknown)
	return Entry{}, nil, ErrUnauthenticated
}

// cached answers from the caches: (match, known).
func (k *Keyring) cached(hash string, sum [32]byte) (bool, bool) {
	k.cacheMu.Lock()
	defer k.cacheMu.Unlock()
	if got, ok := k.good[hash]; ok && subtle.ConstantTimeCompare(got[:], sum[:]) == 1 {
		return true, true
	}
	if _, ok := k.bad[badKey(hash, sum)]; ok {
		return false, true
	}
	return false, false
}

func badKey(hash string, sum [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(hash))
	h.Write(sum[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (k *Keyring) check(ctx context.Context, hash, key string, sum [32]byte) (bool, error) {
	if match, known := k.cached(hash, sum); known {
		return match, nil
	}
	timer := time.NewTimer(k.opts.HashWait)
	defer timer.Stop()
	select {
	case k.slots <- struct{}{}:
	case <-timer.C:
		k.counters.Inc(CounterKeyCheckBusy)
		return false, ErrBusy
	case <-ctx.Done():
		k.counters.Inc(CounterKeyCheckBusy)
		return false, ErrBusy
	}
	ok, err := k.hasher.Verify(key, hash)
	<-k.slots
	k.counters.Inc(CounterKeyChecks)
	if err != nil {
		ok = false
	}
	k.cacheMu.Lock()
	defer k.cacheMu.Unlock()
	if ok {
		k.good[hash] = sum
		return true, nil
	}
	bk := badKey(hash, sum)
	if _, dup := k.bad[bk]; !dup {
		for len(k.badFIFO) >= k.opts.BadCache {
			delete(k.bad, k.badFIFO[0])
			k.badFIFO = k.badFIFO[1:]
			k.counters.Inc(CounterBadKeyEvicted)
		}
		k.bad[bk] = struct{}{}
		k.badFIFO = append(k.badFIFO, bk)
	}
	return false, nil
}

// pruneGood forgets remembered keys of generations no longer held, so the
// cache is bounded by the key set (E-10) and a revoked key is checked
// against nothing.
func (k *Keyring) pruneGood() {
	k.mu.RLock()
	live := map[string]bool{}
	for _, e := range k.entries {
		for _, g := range e.gens {
			live[g.bearerHash] = true
		}
	}
	k.mu.RUnlock()
	k.cacheMu.Lock()
	for h := range k.good {
		if !live[h] {
			delete(k.good, h)
		}
	}
	k.cacheMu.Unlock()
}
