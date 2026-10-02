package ingest

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

func cheapHasher(t testing.TB) *passhash.Hasher {
	t.Helper()
	h, err := passhash.New(passhash.Params{MemoryKiB: 8, Time: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// rx is a receiver registered at test time (keys generated now, never
// in git).
type rx struct {
	entry  receivers.Entry
	bearer string
	secret []byte
}

func newRx(t testing.TB, h *passhash.Hasher, id string, secret []byte) rx {
	t.Helper()
	c, gen, err := receivers.GenerateCredentials(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if secret == nil {
		secret = gen
	}
	hash, err := h.Hash(c.BearerKey)
	if err != nil {
		t.Fatal(err)
	}
	return rx{
		entry: receivers.Entry{ReceiverID: id, Status: receivers.StatusEnabled, LatDeg: 41.7, LonDeg: 44.8, Version: 1,
			Keys: []receivers.KeyGeneration{{Generation: 1, BearerHash: hash, HMACSecretHex: hex.EncodeToString(secret)}}},
		bearer: "Bearer " + c.BearerKey, secret: secret,
	}
}

type fakeQueue struct {
	mu      sync.Mutex
	batches []*ridpipe.Batch
	err     error
}

func (q *fakeQueue) Enqueue(_ context.Context, b *ridpipe.Batch) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.err != nil {
		return q.err
	}
	q.batches = append(q.batches, b)
	return nil
}

func (q *fakeQueue) rows() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	n := 0
	for _, b := range q.batches {
		n += len(b.Rows)
	}
	return n
}

type fixture struct {
	h        *Handler
	queue    *fakeQueue
	gate     *sources.Follower
	counters *core.Counters
	kr       *receivers.Keyring
	now      time.Time
}

func quietLimiter() *logging.Limiter {
	return logging.NewLimiter(logging.Discard(), time.Minute, 0, nil)
}

func newFixture(t testing.TB, rxs ...rx) *fixture {
	t.Helper()
	counters := &core.Counters{}
	kr, err := receivers.NewKeyring(receivers.KeyringOptions{
		MaxSkew: receivers.MaxSkew, NonceMemory: 64, MaxDatagramBytes: receivers.MaxDatagramBytes(receivers.MaxBatchBytes),
		HashSlots: 2, HashWait: time.Second, BadCache: 64,
	}, cheapHasher(t), &core.Counters{})
	if err != nil {
		t.Fatal(err)
	}
	var entries []receivers.Entry
	for i := range rxs {
		entries = append(entries, rxs[i].entry)
	}
	if err := kr.Replace(entries); err != nil {
		t.Fatal(err)
	}
	dd, err := NewDedupe(time.Minute, 1000, 100, counters)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{queue: &fakeQueue{}, gate: sources.NewFollower(), counters: counters, kr: kr,
		now: time.UnixMilli(1_790_000_000_000).UTC()}
	f.h = &Handler{Keyring: kr, Gate: f.gate, Dedupe: dd, Queue: f.queue,
		DisabledRetryAfter: 30 * time.Second, QueueRetryAfter: 2 * time.Second, Counters: counters, Limiter: quietLimiter(),
		Now: func() time.Time { return f.now }}
	return f
}

// post sends body signed with secret (sig "" sends no signature header).
func (f *fixture) post(t testing.TB, bearer, body, sig string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	f.h.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/rid/observations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	if sig != "" {
		req.Header.Set(receivers.SignatureHeader, sig)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func sign(secret []byte, body string) string { return auth.SignReport(secret, []byte(body)) }

// payload is a 25-byte ODID message of type typ (only the type nibble is
// read here; decoding is WP-8's).
func payload(typ byte, fill byte) string {
	b := make([]byte, 25)
	b[0] = typ<<4 | 0x2
	for i := 1; i < 25; i++ {
		b[i] = fill
	}
	return hex.EncodeToString(b)
}

func obs(tx, payloadHex, rxTS string) string {
	if rxTS == "" {
		return fmt.Sprintf(`{"transmitter":%q,"payload_hex":%q,"rssi_dbm":-70.5}`, tx, payloadHex)
	}
	return fmt.Sprintf(`{"transmitter":%q,"payload_hex":%q,"rssi_dbm":-70.5,"rx_ts":%q,"receiver_position":{"lat_deg":41.7,"lon_deg":44.8,"alt_hae_m":520}}`, tx, payloadHex, rxTS)
}

func batchBody(id string, sentAtMS int64, nonce string, backlog bool, observations ...string) string {
	return fmt.Sprintf(`{"receiver_id":%q,"sent_at_ms":%d,"nonce":%q,"backlog":%v,"observations":[%s]}`,
		id, sentAtMS, nonce, backlog, strings.Join(observations, ","))
}
