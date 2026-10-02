package ingest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/receivers"
)

const tx1 = "aa:bb:cc:00:00:01"

func problemOf(t *testing.T, body string) *httpx.Problem {
	t.Helper()
	var p httpx.Problem
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("not a problem: %s", body)
	}
	return &p
}

// The success path, read: 202 only with the batch in the queue, its rows
// carrying the raw payload, the frame ids, the receiver's cell and the
// type nibble; the counters say so.
func TestAcceptedBatchIsQueuedThenAcknowledged(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-tbs-01", nil)
	f := newFixture(t, r)
	body := batchBody("rx-tbs-01", f.now.UnixMilli(), "n-1", false,
		obs(tx1, payload(1, 7), "2026-10-02T09:15:05.120Z"), obs(tx1, payload(0, 1), "2026-10-02T09:15:05.320Z"))
	rec := f.post(t, r.bearer, body, sign(r.secret, body))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var ack struct {
		BatchID    string `json:"batch_id"`
		Accepted   int    `json:"accepted"`
		Duplicates int    `json:"duplicates"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ack)
	if ack.Accepted != 2 || ack.Duplicates != 0 || !strings.HasPrefix(ack.BatchID, "rx-tbs-01:") {
		t.Fatalf("ack %+v", ack)
	}
	if len(f.queue.batches) != 1 {
		t.Fatalf("queued %d", len(f.queue.batches))
	}
	b := f.queue.batches[0]
	if b.Cell3 != "c3:131:224" || b.ReceiverID != "rx-tbs-01" || len(b.Rows) != 2 || b.ID != ack.BatchID {
		t.Fatalf("batch %+v", b)
	}
	row := b.Rows[0]
	if row.Transmitter != "AA:BB:CC:00:00:01" || *row.MsgType != 1 || len(row.Payload) != 25 || len(row.PayloadSHA256) != 32 ||
		row.ReceiverTS == nil || !row.IngestTS.Equal(f.now) || *row.RSSIDBM != -70.5 || *row.ReceiverAltHAEM != 520 || row.Nonce != "n-1" {
		t.Fatalf("row %+v", row)
	}
	if *b.Rows[1].MsgType != 0 || b.Rows[0].FrameID == b.Rows[1].FrameID {
		t.Fatalf("second row %+v", b.Rows[1])
	}
	if f.counters.Get(CounterBatchesAccepted) != 1 || f.counters.Get(CounterObservationsAccepted) != 2 {
		t.Fatalf("counters %v", f.counters.Snapshot())
	}
}

// E-01: every refusal beside the acceptance it differs from by one thing.
// Each answers its status and slug, stores nothing, and counts its reason.
func TestEveryRefusalBesideItsAcceptance(t *testing.T) {
	h := cheapHasher(t)
	type tc struct {
		name    string
		setup   func(t *testing.T, f *fixture, r rx)
		request func(f *fixture, r rx) (bearer, body, sig string)
		status  int
		slug    string
		reason  string
	}
	good := func(f *fixture, r rx, nonce string) (string, string, string) {
		body := batchBody(r.entry.ReceiverID, f.now.UnixMilli(), nonce, false, obs(tx1, payload(1, 2), "2026-10-02T09:15:05.000Z"))
		return r.bearer, body, sign(r.secret, body)
	}
	cases := []tc{
		{"unsigned", nil, func(f *fixture, r rx) (string, string, string) {
			b, body, _ := good(f, r, "n")
			return b, body, ""
		}, http.StatusUnauthorized, receivers.SlugSignature, receivers.ReasonUnsigned},
		{"unknown key", nil, func(f *fixture, r rx) (string, string, string) {
			_, body, sig := good(f, r, "n")
			return "Bearer rx-1." + strings.Repeat("A", 43), body, sig
		}, http.StatusUnauthorized, httpx.SlugUnauthn, receivers.ReasonUnauthenticated},
		{"no key", nil, func(f *fixture, r rx) (string, string, string) {
			_, body, sig := good(f, r, "n")
			return "", body, sig
		}, http.StatusUnauthorized, httpx.SlugUnauthn, receivers.ReasonUnauthenticated},
		{"bad signature", nil, func(f *fixture, r rx) (string, string, string) {
			b, body, _ := good(f, r, "n")
			return b, body, sign([]byte(strings.Repeat("k", 32)), body)
		}, http.StatusUnauthorized, receivers.SlugSignature, receivers.ReasonBadSignature},
		{"another receiver's id in the body", nil, func(f *fixture, r rx) (string, string, string) {
			body := batchBody("rx-other", f.now.UnixMilli(), "n", false, obs(tx1, payload(1, 2), ""))
			return r.bearer, body, sign(r.secret, body)
		}, http.StatusUnauthorized, receivers.SlugSignature, receivers.ReasonUnknownReceiver},
		{"skew", nil, func(f *fixture, r rx) (string, string, string) {
			body := batchBody(r.entry.ReceiverID, f.now.Add(-31*time.Second).UnixMilli(), "n", false, obs(tx1, payload(1, 2), ""))
			return r.bearer, body, sign(r.secret, body)
		}, http.StatusUnauthorized, receivers.SlugSkew, receivers.ReasonSkew},
		{"replay", func(t *testing.T, f *fixture, r rx) {
			b, body, sig := good(f, r, "n-replayed")
			if rec := f.post(t, b, body, sig); rec.Code != http.StatusAccepted {
				t.Fatalf("first send %d", rec.Code)
			}
			f.queue.batches = nil
		}, func(f *fixture, r rx) (string, string, string) { return good(f, r, "n-replayed") },
			http.StatusConflict, receivers.SlugReplay, receivers.ReasonReplay},
		{"disabled by the registry", func(t *testing.T, f *fixture, r rx) {
			e := r.entry
			e.Status = receivers.StatusDisabled
			who, why := "admin-1", "maintenance"
			e.DisabledBy, e.DisabledReason = &who, &why
			if err := f.kr.Upsert(e); err != nil {
				t.Fatal(err)
			}
		}, func(f *fixture, r rx) (string, string, string) { return good(f, r, "n") },
			http.StatusServiceUnavailable, receivers.SlugSourceDisabled, receivers.ReasonDisabled},
		{"disabled by source control (type)", func(_ *testing.T, f *fixture, _ rx) {
			f.gate.Apply(sources.State{Controls: []sources.Control{{SourceType: SourceType, Enabled: false}}, Version: 1, Epoch: "e"})
		}, func(f *fixture, r rx) (string, string, string) { return good(f, r, "n") },
			http.StatusServiceUnavailable, receivers.SlugSourceDisabled, receivers.ReasonDisabled},
		{"malformed", nil, func(f *fixture, r rx) (string, string, string) {
			body := fmt.Sprintf(`{"receiver_id":%q,"sent_at_ms":%d,"nonce":"n"}`, r.entry.ReceiverID, f.now.UnixMilli())
			return r.bearer, body, sign(r.secret, body)
		}, http.StatusBadRequest, receivers.SlugValidation, receivers.ReasonMalformed},
		{"oversize", nil, func(f *fixture, r rx) (string, string, string) {
			body := batchBody(r.entry.ReceiverID, f.now.UnixMilli(), "n", false, obs(tx1, strings.Repeat("00", 40_000), ""))
			return r.bearer, body, sign(r.secret, body)
		}, http.StatusRequestEntityTooLarge, httpx.SlugBodyTooLarge, receivers.ReasonOversize},
		{"queue full", func(_ *testing.T, f *fixture, _ rx) { f.queue.err = fmt.Errorf("%w: test", ErrQueueFull) },
			func(f *fixture, r rx) (string, string, string) { return good(f, r, "n") },
			http.StatusServiceUnavailable, receivers.SlugQueueFull, receivers.ReasonQueueFull},
		{"queue unavailable", func(_ *testing.T, f *fixture, _ rx) { f.queue.err = fmt.Errorf("%w: test", ErrQueueUnavailable) },
			func(f *fixture, r rx) (string, string, string) { return good(f, r, "n") },
			http.StatusServiceUnavailable, receivers.SlugQueueUnavailable, receivers.ReasonQueueUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRx(t, h, "rx-1", nil)
			// The acceptance: the same fixture with nothing changed.
			ok := newFixture(t, r)
			ob, obody, osig := good(ok, r, "n-ok")
			if rec := ok.post(t, ob, obody, osig); rec.Code != http.StatusAccepted || len(ok.queue.batches) != 1 {
				t.Fatalf("acceptance twin: %d %s", rec.Code, rec.Body.String())
			}
			f := newFixture(t, r)
			if c.setup != nil {
				c.setup(t, f, r)
			}
			bearer, body, sig := c.request(f, r)
			rec := f.post(t, bearer, body, sig)
			p := problemOf(t, rec.Body.String())
			if rec.Code != c.status || p.Slug() != c.slug {
				t.Fatalf("got %d %s (%s), want %d %s", rec.Code, p.Slug(), p.Detail, c.status, c.slug)
			}
			if rec.Code == http.StatusForbidden {
				t.Fatal("403 is never an answer to a receiver (B-10)")
			}
			if len(f.queue.batches) != 0 {
				t.Fatalf("a refused batch was queued: %d", len(f.queue.batches))
			}
			if f.counters.Get(c.reason) != 1 || f.counters.Get(CounterBatchesRefused) != 1 {
				t.Fatalf("reason %s not counted once: %v", c.reason, f.counters.Snapshot())
			}
			if c.status == http.StatusServiceUnavailable && rec.Header().Get("Retry-After") == "" {
				t.Fatal("a 503 without Retry-After")
			}
		})
	}
}

// B-05: a batch replayed with a new nonce (the 202 was lost) queues
// nothing twice; its observations count as duplicates.
func TestReplayedObservationsAreQueuedOnce(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-1", nil)
	f := newFixture(t, r)
	o := []string{obs(tx1, payload(1, 1), "2026-10-02T09:15:05.000Z"), obs(tx1, payload(1, 2), "2026-10-02T09:15:05.500Z")}
	for i, nonce := range []string{"n-1", "n-2"} {
		body := batchBody("rx-1", f.now.UnixMilli(), nonce, false, o...)
		rec := f.post(t, r.bearer, body, sign(r.secret, body))
		var ack struct{ Accepted, Duplicates int }
		_ = json.Unmarshal(rec.Body.Bytes(), &ack)
		if rec.Code != http.StatusAccepted || (i == 0 && ack.Accepted != 2) || (i == 1 && (ack.Accepted != 0 || ack.Duplicates != 2)) {
			t.Fatalf("send %d: %d %+v", i, rec.Code, ack)
		}
	}
	if len(f.queue.batches) != 1 || f.counters.Get(CounterDuplicates) != 2 || f.counters.Get(CounterEmptyBatches) != 1 {
		t.Fatalf("queued %d, counters %v", len(f.queue.batches), f.counters.Snapshot())
	}
	// One observation new, one repeated: only the new one is queued.
	body := batchBody("rx-1", f.now.UnixMilli(), "n-3", false, o[0], obs(tx1, payload(1, 3), "2026-10-02T09:15:06.000Z"))
	if rec := f.post(t, r.bearer, body, sign(r.secret, body)); rec.Code != http.StatusAccepted || f.queue.rows() != 3 {
		t.Fatalf("mixed: %d rows %d", rec.Code, f.queue.rows())
	}
}

// A refused queue write gives its reservation back: the retry is
// accepted, not swallowed as a duplicate.
func TestFailedQueueWriteReleasesTheReservation(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-1", nil)
	f := newFixture(t, r)
	o := obs(tx1, payload(1, 1), "2026-10-02T09:15:05.000Z")
	f.queue.err = ErrQueueUnavailable
	body := batchBody("rx-1", f.now.UnixMilli(), "n-1", false, o)
	if rec := f.post(t, r.bearer, body, sign(r.secret, body)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("down: %d", rec.Code)
	}
	f.queue.err = nil
	body = batchBody("rx-1", f.now.UnixMilli(), "n-2", false, o)
	if rec := f.post(t, r.bearer, body, sign(r.secret, body)); rec.Code != http.StatusAccepted || f.queue.rows() != 1 {
		t.Fatalf("retry: %d rows %d", rec.Code, f.queue.rows())
	}
}

// T-12: an observation without rx_ts has no dedupe key; two identical
// broadcasts are two frames, never merged.
func TestObservationsWithoutRxTSAreNeverMerged(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-1", nil)
	f := newFixture(t, r)
	o := obs(tx1, payload(0, 9), "")
	for _, nonce := range []string{"n-1", "n-2"} {
		body := batchBody("rx-1", f.now.UnixMilli(), nonce, false, o, o)
		if rec := f.post(t, r.bearer, body, sign(r.secret, body)); rec.Code != http.StatusAccepted {
			t.Fatalf("%d", rec.Code)
		}
	}
	if f.queue.rows() != 4 {
		t.Fatalf("rows %d, want 4", f.queue.rows())
	}
	seen := map[string]bool{}
	for _, b := range f.queue.batches {
		for _, row := range b.Rows {
			if seen[row.FrameID] {
				t.Fatal("two frames without rx_ts share an id")
			}
			seen[row.FrameID] = true
		}
	}
}

// An observation reserved by a request still writing makes a concurrent
// request with it retry (503 in_flight), never answer "duplicate" for
// rows not yet stored; a key twice in one batch is a plain duplicate.
func TestObservationInFlightIsRetriedNotSwallowed(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-1", nil)
	f := newFixture(t, r)
	o := obs(tx1, payload(1, 1), "2026-10-02T09:15:05.000Z")
	b0 := batchBody("rx-1", f.now.UnixMilli(), "n-0", false, o)
	parsed, err := ParseBatch([]byte(b0))
	if err != nil {
		t.Fatal(err)
	}
	rows := Rows(&parsed, f.now)
	f.h.Dedupe.Reserve("rx-1", []string{rows[0].FrameID}, f.now)
	body := batchBody("rx-1", f.now.UnixMilli(), "n-1", false, o)
	rec := f.post(t, r.bearer, body, sign(r.secret, body))
	if rec.Code != http.StatusServiceUnavailable || problemOf(t, rec.Body.String()).Slug() != SlugInFlight {
		t.Fatalf("in flight: %d %s", rec.Code, rec.Body.String())
	}
	f.h.Dedupe.Release("rx-1", []string{rows[0].FrameID})
	body = batchBody("rx-1", f.now.UnixMilli(), "n-2", false, o, o)
	rec = f.post(t, r.bearer, body, sign(r.secret, body))
	var ack struct{ Accepted, Duplicates int }
	_ = json.Unmarshal(rec.Body.Bytes(), &ack)
	if rec.Code != http.StatusAccepted || ack.Accepted != 1 || ack.Duplicates != 1 {
		t.Fatalf("twice in one batch: %d %+v", rec.Code, ack)
	}
}

// The batch size is bounded before the key check when the length is
// declared, and by the read when it is not (chunked): 413 either way,
// counted, nothing queued.
func TestOversizeWithoutADeclaredLength(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-1", nil)
	f := newFixture(t, r)
	body := batchBody("rx-1", f.now.UnixMilli(), "n", false, obs(tx1, strings.Repeat("00", 40_000), ""))
	mux := http.NewServeMux()
	f.h.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/rid/observations", strings.NewReader(body))
	req.ContentLength = -1
	req.Header.Set("Authorization", r.bearer)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || f.counters.Get(receivers.ReasonOversize) != 1 || len(f.queue.batches) != 0 {
		t.Fatalf("%d %v", rec.Code, f.counters.Snapshot())
	}
}
