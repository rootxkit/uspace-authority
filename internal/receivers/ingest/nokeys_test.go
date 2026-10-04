package ingest

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/receivers"
)

// WP-L6 finding 5: with no receiver keys every batch is refused, each
// refusal is counted, and /readyz says so with the count; nothing is
// queued.
func TestNoKeysRefusesEveryBatchCountedAndSaidInReadiness(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-nk-01", nil)
	f := newFixture(t) // no receiver registered
	ready := KeysReady(f.kr, f.counters)
	for i, nonce := range []string{"n-1", "n-2"} {
		body := batchBody("rx-nk-01", f.now.UnixMilli(), nonce, false, obs(tx1, payload(1, 7), "2026-10-02T09:15:05.120Z"))
		if rec := f.post(t, r.bearer, body, sign(r.secret, body)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("batch %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if len(f.queue.batches) != 0 {
		t.Fatalf("%d batches queued with no keys", len(f.queue.batches))
	}
	if got := f.counters.Get(CounterRefusedNoKeys); got != 2 {
		t.Fatalf("%s = %d, want 2", CounterRefusedNoKeys, got)
	}
	err := ready(context.Background())
	if err == nil {
		t.Fatal("ready with no receiver keys")
	}
	if msg := err.Error(); !strings.Contains(msg, "no receiver keys") || !strings.Contains(msg, "2 batches refused") {
		t.Fatalf("readiness says %q", msg)
	}
}

// The twin: keys that arrive while the process runs (the key set
// follower's Replace) are accepted on the same handler with no restart;
// readiness passes, and the no-keys counter stays where it was.
func TestKeysAddedAtRuntimeAreAcceptedAndReadinessPasses(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-nk-02", nil)
	f := newFixture(t)
	ready := KeysReady(f.kr, f.counters)
	body := batchBody("rx-nk-02", f.now.UnixMilli(), "n-1", false, obs(tx1, payload(1, 7), "2026-10-02T09:15:05.120Z"))
	if rec := f.post(t, r.bearer, body, sign(r.secret, body)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("before the keys: %d", rec.Code)
	}
	if err := f.kr.Replace([]receivers.Entry{r.entry}); err != nil {
		t.Fatal(err)
	}
	if err := ready(context.Background()); err != nil {
		t.Fatalf("not ready with a receiver key: %v", err)
	}
	body = batchBody("rx-nk-02", f.now.UnixMilli(), "n-2", false, obs(tx1, payload(1, 8), "2026-10-02T09:15:05.320Z"))
	if rec := f.post(t, r.bearer, body, sign(r.secret, body)); rec.Code != http.StatusAccepted {
		t.Fatalf("after the keys: %d %s", rec.Code, rec.Body.String())
	}
	if len(f.queue.batches) != 1 {
		t.Fatalf("%d batches queued", len(f.queue.batches))
	}
	if got := f.counters.Get(CounterRefusedNoKeys); got != 1 {
		t.Fatalf("%s = %d, want 1", CounterRefusedNoKeys, got)
	}
}
