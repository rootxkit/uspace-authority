package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/receivers/ingest"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// These tests run rid-ingest as a process against a real NATS JetStream
// (NATS_URL, INTEGRATION=1). They share the INGEST and TSW stream names,
// so they run one after another inside this package and each starts from
// deleted streams; every test has its own key-set bucket. tsdb-writer
// (WP-9) is stood in for by reading the TSW stream: a row there is a row
// handed to the writer.

// lines is a goroutine-safe stdout read back as JSON log lines.
type lines struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lines) find(msg string, ok func(map[string]any) bool) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var found map[string]any
	sc := bufio.NewScanner(bytes.NewReader(l.b.Bytes()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil && m["msg"] == msg && (ok == nil || ok(m)) {
			found = m
		}
	}
	return found
}

func (l *lines) waitFor(t *testing.T, msg string, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if m := l.find(msg, ok); m != nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t.Fatalf("no %q line; stdout:\n%s", msg, l.b.String())
	return nil
}

func natsURL(t *testing.T) string {
	t.Helper()
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("INTEGRATION=1 not set: needs NATS JetStream (make up)")
	}
	u := os.Getenv("NATS_URL")
	if u == "" {
		t.Fatal("INTEGRATION=1 but NATS_URL is unset")
	}
	return u
}

// testRx is a receiver registered at test time; its keys never reach git.
type testRx struct {
	id     string
	bearer string
	secret []byte
	entry  receivers.Entry
}

var cheap = func() *passhash.Hasher {
	h, err := passhash.New(passhash.Params{MemoryKiB: 8, Time: 1, Threads: 1})
	if err != nil {
		panic(err)
	}
	return h
}()

func newTestRx(t *testing.T, id string) testRx {
	t.Helper()
	c, secret, err := receivers.GenerateCredentials(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := cheap.Hash(c.BearerKey)
	if err != nil {
		t.Fatal(err)
	}
	return testRx{id: id, bearer: "Bearer " + c.BearerKey, secret: secret, entry: receivers.Entry{
		ReceiverID: id, Status: receivers.StatusEnabled, LatDeg: 41.72, LonDeg: 44.79, Version: 1,
		Keys: []receivers.KeyGeneration{{Generation: 1, BearerHash: hash, HMACSecretHex: hex.EncodeToString(secret)}},
	}}
}

type harness struct {
	t      *testing.T
	nc     *nats.Conn
	js     jetstream.JetStream
	kv     jetstream.KeyValue
	bucket string
	stdout *lines
	base   string
	exit   chan int
	cancel context.CancelFunc
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	u := natsURL(t)
	nc, err := nats.Connect(u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, s := range []string{ingest.QueueStream, "TSW"} {
		if err := js.DeleteStream(ctx, s); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
			t.Fatal(err)
		}
	}
	bucket := fmt.Sprintf("rid_keys_test_%d", time.Now().UnixNano())
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: bucket, History: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	return &harness{t: t, nc: nc, js: js, kv: kv, bucket: bucket}
}

func (h *harness) put(e receivers.Entry) {
	h.t.Helper()
	raw, _ := json.Marshal(e)
	if _, err := h.kv.Put(context.Background(), e.ReceiverID, raw); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) env(extra map[string]string) map[string]string {
	m := map[string]string{
		"NATS_URL": natsURL(h.t), "TS_URL": "postgres://unused@127.0.0.1:1/unused", "RID_KEYSET_BUCKET": h.bucket,
		"RID_INGEST_ADDR": ":0", "ADMIN_ADDR": "127.0.0.1:0", "STATUS_INTERVAL_S": "1", "SHUTDOWN_TIMEOUT_S": "5",
		"RID_INGEST_STATUS_INTERVAL_MS": "200", "RID_INGEST_STORAGE_RETRY_MS": "100", "RID_INGEST_KEYSET_REREAD_S": "1",
		"HTTP_RATE_LIMIT_RPS": "10000", "HTTP_RATE_LIMIT_BURST": "10000",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// start runs the process until the test ends and waits for its listener.
func (h *harness) start(extra map[string]string, o ingest.Options) {
	h.t.Helper()
	h.stdout = &lines{}
	m := h.env(extra)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.exit = cancel, make(chan int, 1)
	go func() {
		h.exit <- proc.Main(ctx, specWith(&config.RIDIngest{}, o), nil, h.stdout, io.Discard,
			func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	}()
	h.t.Cleanup(func() {
		cancel()
		select {
		case code := <-h.exit:
			if code != proc.ExitOK {
				h.t.Errorf("exit %d", code)
			}
		case <-time.After(20 * time.Second):
			h.t.Error("rid-ingest did not stop")
		}
	})
	listen := h.stdout.waitFor(h.t, "public listener open", nil)
	h.base = "http://" + listen["addr"].(string)
}

// createTSW stands in for WP-9/WP-10's TSW stream: the writer's input.
func (h *harness) createTSW() {
	h.t.Helper()
	if _, err := h.js.CreateStream(context.Background(), jetstream.StreamConfig{
		Name: "TSW", Subjects: []string{"tsw.v1.>"}, Storage: jetstream.MemoryStorage, Duplicates: 2 * time.Minute,
	}); err != nil {
		h.t.Fatal(err)
	}
}

// handedOver reads every row and gap record on the TSW stream.
func (h *harness) handedOver() (rows []ridpipe.Row, gaps []ingest.Gap) {
	h.t.Helper()
	ctx := context.Background()
	s, err := h.js.Stream(ctx, "TSW")
	if err != nil {
		return nil, nil
	}
	info, err := s.Info(ctx)
	if err != nil || info.State.Msgs == 0 {
		return nil, nil
	}
	for seq := info.State.FirstSeq; seq <= info.State.LastSeq; seq++ {
		m, err := s.GetMsg(ctx, seq)
		if err != nil {
			continue
		}
		switch m.Subject {
		case ingest.RowsSubject:
			var rm ingest.RowsMessage
			if err := json.Unmarshal(m.Data, &rm); err != nil {
				h.t.Fatal(err)
			}
			rows = append(rows, rm.Rows...)
		case ingest.GapsSubject:
			var g ingest.Gap
			if err := json.Unmarshal(m.Data, &g); err != nil {
				h.t.Fatal(err)
			}
			gaps = append(gaps, g)
		}
	}
	return rows, gaps
}

type ack struct {
	BatchID    string `json:"batch_id"`
	Accepted   int    `json:"accepted"`
	Duplicates int    `json:"duplicates"`
	Type       string `json:"type"`
	Detail     string `json:"detail"`
}

var client = &http.Client{Timeout: 10 * time.Second}

func observation(tx string, n int, at time.Time) string {
	p := make([]byte, 25)
	p[0] = 0x12
	p[1], p[2] = byte(n>>8), byte(n)
	return fmt.Sprintf(`{"transmitter":%q,"payload_hex":%q,"rssi_dbm":-71,"rx_ts":%q}`, tx, hex.EncodeToString(p),
		at.UTC().Format("2006-01-02T15:04:05.000Z"))
}

func (h *harness) post(r testRx, nonce string, obs ...string) (int, ack, http.Header) {
	h.t.Helper()
	body := fmt.Sprintf(`{"receiver_id":%q,"sent_at_ms":%d,"nonce":%q,"backlog":false,"observations":[%s]}`,
		r.id, time.Now().UnixMilli(), nonce, strings.Join(obs, ","))
	req, _ := http.NewRequest(http.MethodPost, h.base+"/v1/rid/observations", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", r.bearer)
	req.Header.Set(receivers.SignatureHeader, auth.SignReport(r.secret, []byte(body)))
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var a ack
	_ = json.NewDecoder(resp.Body).Decode(&a)
	return resp.StatusCode, a, resp.Header
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not met in %s", d)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// E-02, R-06: with no receiver keys the ingest listens on loopback only
// and says so, whatever address it was configured with.
func TestIntegrationNoKeysListensOnLoopbackOnly(t *testing.T) {
	h := newHarness(t)
	h.start(nil, ingest.Options{})
	if !strings.HasPrefix(h.base, "http://127.0.0.1:") {
		t.Fatalf("listening on %s", h.base)
	}
	h.stdout.waitFor(t, "no receiver keys: listening on loopback only (R-06); restart once receivers are registered", nil)
	h.stdout.waitFor(t, "no decode pipeline in this build (WP-8): observations are stored raw and no track is published", nil)
}

// E-02, B-05: the success path read end to end: a signed batch is
// acknowledged only once queued, its rows reach the writer's stream with
// the raw payload, and the receiver's status says live. With keys the
// configured address is used (E-01 twin of the loopback test).
func TestIntegrationAcceptedBatchReachesTheWriter(t *testing.T) {
	h := newHarness(t)
	r := newTestRx(t, "rx-int-01")
	h.put(r.entry)
	h.createTSW()
	statuses := make(chan *nats.Msg, 64)
	sub, err := h.nc.ChanSubscribe(ingest.StatusSubject(r.id), statuses)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()
	h.start(nil, ingest.Options{})
	h.stdout.waitFor(t, "receiver key set loaded", func(m map[string]any) bool { return m["receivers"] == 1.0 })
	if strings.HasPrefix(h.base, "http://127.0.0.1:") && h.stdout.find("no receiver keys: listening on loopback only (R-06); restart once receivers are registered", nil) != nil {
		t.Fatal("loopback with keys present")
	}
	now := time.Now()
	code, a, _ := h.post(r, "n-1", observation("AA:BB:CC:00:00:01", 1, now), observation("AA:BB:CC:00:00:02", 2, now))
	if code != http.StatusAccepted || a.Accepted != 2 {
		t.Fatalf("%d %+v", code, a)
	}
	var rows []ridpipe.Row
	waitUntil(t, 10*time.Second, func() bool { rows, _ = h.handedOver(); return len(rows) == 2 })
	if rows[0].ReceiverID != r.id || len(rows[0].Payload) != 25 || rows[0].Payload[0] != 0x12 || *rows[0].MsgType != 1 {
		t.Fatalf("row %+v", rows[0])
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-statuses:
			var env ingest.Envelope
			if err := json.Unmarshal(m.Data, &env); err != nil {
				t.Fatal(err)
			}
			if env.Body.State == "live" && env.Body.Counters["accepted"] == 2 && env.Body.Counters["stored"] == 2 {
				return
			}
		case <-deadline:
			t.Fatal("no live status with the counts")
		}
	}
}

// SC-18: storage (the writer's stream) is down: batches are still
// acknowledged, because they are durably queued, and wait; when storage
// returns every row is handed over once, none lost, none twice.
func TestIntegrationSC18RowsWaitForStorageAndNoneIsLost(t *testing.T) {
	h := newHarness(t)
	r := newTestRx(t, "rx-int-18")
	h.put(r.entry)
	h.start(nil, ingest.Options{})
	sent := 0
	now := time.Now()
	for i := range 5 {
		var obs []string
		for j := range 4 {
			obs = append(obs, observation("AA:BB:CC:00:00:01", i*10+j, now.Add(time.Duration(i*10+j)*time.Millisecond)))
		}
		code, a, _ := h.post(r, fmt.Sprintf("n-%d", i), obs...)
		if code != http.StatusAccepted || a.Accepted != 4 {
			t.Fatalf("batch %d while storage is down: %d %+v", i, code, a)
		}
		sent += 4
	}
	h.stdout.waitFor(t, "rows not handed to tsdb-writer; the batch waits in the queue", nil)
	h.createTSW()
	var rows []ridpipe.Row
	waitUntil(t, 15*time.Second, func() bool { rows, _ = h.handedOver(); return len(rows) >= sent })
	time.Sleep(500 * time.Millisecond)
	rows, gaps := h.handedOver()
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.FrameID] {
			t.Fatalf("frame %s handed over twice", row.FrameID)
		}
		seen[row.FrameID] = true
	}
	if len(rows) != sent || len(gaps) != 0 {
		t.Fatalf("handed over %d of %d, gaps %v", len(rows), sent, gaps)
	}
}

// SC-18 step 3, E-10, 05 §5: past the queue's bound the oldest batches
// are shed with writer_gaps records, never the newest; every observation
// is either handed over or counted in a gap.
func TestIntegrationSC18QueueBoundShedsTheOldestWithGaps(t *testing.T) {
	h := newHarness(t)
	r := newTestRx(t, "rx-int-cap")
	h.put(r.entry)
	h.start(map[string]string{"RID_INGEST_QUEUE_MAX_BATCHES": "3", "RID_INGEST_QUEUE_MAX_ACK_PENDING": "1"}, ingest.Options{})
	now := time.Now()
	for i := range 8 {
		code, a, _ := h.post(r, fmt.Sprintf("n-%d", i), observation("AA:BB:CC:00:00:01", i, now.Add(time.Duration(i)*time.Millisecond)),
			observation("AA:BB:CC:00:00:02", i, now.Add(time.Duration(i)*time.Millisecond)))
		if code != http.StatusAccepted || a.Accepted != 2 {
			t.Fatalf("batch %d: %d %+v", i, code, a)
		}
	}
	h.stdout.waitFor(t, "a batch due to be shed waits in the queue until its gap record is stored", nil)
	h.createTSW()
	var rows []ridpipe.Row
	var gaps []ingest.Gap
	waitUntil(t, 15*time.Second, func() bool {
		rows, gaps = h.handedOver()
		shed := 0
		for _, g := range gaps {
			shed += g.Count
		}
		return len(rows)+shed == 16
	})
	if len(gaps) == 0 || len(rows) == 0 {
		t.Fatalf("rows %d gaps %v", len(rows), gaps)
	}
	// The newest batch is never the one shed.
	newest := map[string]bool{}
	for _, row := range rows {
		newest[row.Nonce] = true
	}
	if !newest["n-7"] {
		t.Fatalf("the newest batch was shed: kept %v", newest)
	}
	for _, g := range gaps {
		if g.Cause != ingest.CauseQueueFull || g.Table != "rid_observations" {
			t.Fatalf("gap %+v", g)
		}
	}
	t.Logf("8 batches of 2 with the bound at 3: %d observations handed over, %d shed in %d gap records", len(rows), 16-len(rows), len(gaps))
}

// SC-08 steps 2-3, receiver side, B-10: a receiver disabled in the
// registry is refused with 503 and Retry-After (never 401 or 403), counted,
// and nothing is stored; enabled again it is accepted within a second.
func TestIntegrationSC08DisabledReceiverIsRefusedThenAcceptedWithinASecond(t *testing.T) {
	h := newHarness(t)
	r := newTestRx(t, "rx-int-08")
	h.put(r.entry)
	h.createTSW()
	h.start(nil, ingest.Options{})
	if code, _, _ := h.post(r, "n-0", observation("AA:BB:CC:00:00:01", 0, time.Now())); code != http.StatusAccepted {
		t.Fatalf("enabled: %d", code)
	}
	off := r.entry
	off.Status = receivers.StatusDisabled
	who, why := "admin-1", "SC-08"
	off.DisabledBy, off.DisabledReason, off.Version = &who, &why, 2
	h.put(off)
	var code int
	var a ack
	var hdr http.Header
	i := 0
	refused := map[string]bool{}
	waitUntil(t, 3*time.Second, func() bool {
		i++
		nonce := fmt.Sprintf("off-%d", i)
		code, a, hdr = h.post(r, nonce, observation("AA:BB:CC:00:00:01", 100+i, time.Now()))
		if code == http.StatusServiceUnavailable {
			refused[nonce] = true
		}
		return code == http.StatusServiceUnavailable
	})
	for j := range 3 {
		nonce := fmt.Sprintf("still-off-%d", j)
		if c, _, _ := h.post(r, nonce, observation("AA:BB:CC:00:00:01", 150+j, time.Now())); c != http.StatusServiceUnavailable {
			t.Fatalf("disabled receiver answered %d", c)
		}
		refused[nonce] = true
	}
	if !strings.HasSuffix(a.Type, "/source_disabled") || hdr.Get("Retry-After") == "" {
		t.Fatalf("disabled: %d %+v %v", code, a, hdr)
	}
	h.stdout.waitFor(t, "status", func(m map[string]any) bool { return counter(m, "rid_ingest", "refused_disabled") > 0 })
	rowsBefore, _ := h.handedOver()
	on := r.entry
	on.Version = 3
	h.put(on)
	enabledAt := time.Now()
	waitUntil(t, 3*time.Second, func() bool {
		i++
		code, _, _ = h.post(r, fmt.Sprintf("on-%d", i), observation("AA:BB:CC:00:00:01", 200+i, time.Now()))
		return code == http.StatusAccepted
	})
	if took := time.Since(enabledAt); took > time.Second {
		t.Fatalf("accepted %s after enabling, more than 1 s", took)
	}
	time.Sleep(300 * time.Millisecond)
	rowsAfter, _ := h.handedOver()
	for _, row := range append(rowsBefore, rowsAfter...) {
		if refused[row.Nonce] {
			t.Fatalf("refused batch %s was stored", row.Nonce)
		}
	}
}

// SC-08, source control by type (WP-10's follower, fed here directly): a
// disabled type refuses every receiver with 503; enabled, accepted.
func TestIntegrationSC08DisabledByTypeThenEnabled(t *testing.T) {
	h := newHarness(t)
	r := newTestRx(t, "rx-int-type")
	h.put(r.entry)
	h.createTSW()
	gate := newGate()
	h.start(nil, ingest.Options{Gate: gate})
	gate.set(false, 1)
	if code, a, hdr := h.post(r, "n-1", observation("AA:BB:CC:00:00:01", 1, time.Now())); code != http.StatusServiceUnavailable ||
		!strings.HasSuffix(a.Type, "/source_disabled") || hdr.Get("Retry-After") == "" {
		t.Fatalf("disabled by type: %d %+v", code, a)
	}
	gate.set(true, 2)
	if code, _, _ := h.post(r, "n-2", observation("AA:BB:CC:00:00:01", 2, time.Now())); code != http.StatusAccepted {
		t.Fatalf("enabled: %d", code)
	}
}

// B-14: a key set with an entry stored under another receiver's id stops
// the ingest at start with the field named, rather than serving a
// partial set.
func TestIntegrationInvalidKeySetStopsTheIngest(t *testing.T) {
	h := newHarness(t)
	r := newTestRx(t, "rx-int-a")
	raw, _ := json.Marshal(r.entry)
	if _, err := h.kv.Put(context.Background(), "rx-int-b", raw); err != nil {
		t.Fatal(err)
	}
	m := h.env(nil)
	out := &lines{}
	code := proc.Main(context.Background(), specWith(&config.RIDIngest{}, ingest.Options{}), nil, out, io.Discard,
		func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	if code != proc.ExitFailed || out.find("process failed", func(l map[string]any) bool {
		return strings.Contains(l["error"].(string), "stored under the key")
	}) == nil {
		t.Fatalf("exit %d:\n%s", code, out.b.String())
	}
}

// counter reads one counter of a status line.
func counter(line map[string]any, component, name string) float64 {
	cs, _ := line["counters"].(map[string]any)
	c, _ := cs[component].(map[string]any)
	v, _ := c[name].(float64)
	return v
}

// gate is the source-control follower as WP-10 will feed it, driven by
// the test.
type gate struct{ f *sources.Follower }

func newGate() *gate { return &gate{f: sources.NewFollower()} }

func (g *gate) set(enabled bool, version uint64) {
	g.f.Apply(sources.State{Controls: []sources.Control{{SourceType: ingest.SourceType, Enabled: enabled}}, Version: version, Epoch: "test"})
}

func (g *gate) Query(sourceType string, instanceID *string) sources.Decision {
	return g.f.Query(sourceType, instanceID)
}

// Load smoke (05 §7, no silent loss): 50 receivers x 20 aircraft x 3
// messages a second, each receiver posting one batch a second, for
// RID_LOAD_SMOKE_S seconds (60 by default). Every observation sent ends
// in exactly one place: handed to the writer, shed with a gap record,
// refused, or a duplicate; the counts must add up to what was sent.
func TestIntegrationLoadSmoke(t *testing.T) {
	h := newHarness(t)
	seconds := 60
	if v := os.Getenv("RID_LOAD_SMOKE_S"); v != "" {
		if _, err := fmt.Sscan(v, &seconds); err != nil || seconds < 1 {
			t.Fatalf("RID_LOAD_SMOKE_S=%q", v)
		}
	}
	const nRx, aircraft, perSecond = 50, 20, 3
	rxs := make([]testRx, nRx)
	for i := range rxs {
		rxs[i] = newTestRx(t, fmt.Sprintf("rx-load-%02d", i))
		h.put(rxs[i].entry)
	}
	if _, err := h.js.CreateStream(context.Background(), jetstream.StreamConfig{
		Name: "TSW", Subjects: []string{"tsw.v1.>"}, Storage: jetstream.FileStorage, Duplicates: 2 * time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	h.start(nil, ingest.Options{})
	h.stdout.waitFor(t, "receiver key set loaded", func(m map[string]any) bool { return m["receivers"] == float64(nRx) })

	var mu sync.Mutex
	var sent, accepted, duplicates, refused, transport int
	statuses := map[int]int{}
	var latencies []time.Duration
	start := time.Now()
	var wg sync.WaitGroup
	for i := range rxs {
		r := rxs[i]
		wg.Go(func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for s := range seconds {
				obs := make([]string, 0, aircraft*perSecond)
				for a := range aircraft {
					for m := range perSecond {
						at := start.Add(time.Duration(s)*time.Second + time.Duration(m*300+a)*time.Millisecond)
						obs = append(obs, observation(fmt.Sprintf("AA:BB:CC:%02X:%02X:%02X", i, a, m), s*100+a, at))
					}
				}
				t0 := time.Now()
				code, a, err := postNoFatal(h, r, fmt.Sprintf("load-%d", s), obs)
				mu.Lock()
				sent += len(obs)
				latencies = append(latencies, time.Since(t0))
				switch {
				case err != nil:
					transport += len(obs)
				case code == http.StatusAccepted:
					accepted += a.Accepted
					duplicates += a.Duplicates
				default:
					refused += len(obs)
				}
				statuses[code]++
				mu.Unlock()
				<-tick.C
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)

	var rows []ridpipe.Row
	var gaps []ingest.Gap
	shedOf := func() int {
		n := 0
		for _, g := range gaps {
			n += g.Count
		}
		return n
	}
	waitUntil(t, 60*time.Second, func() bool {
		rows, gaps = h.handedOver()
		return len(rows)+shedOf() >= accepted
	})
	shed := shedOf()
	line := h.stdout.waitFor(t, "status", func(m map[string]any) bool {
		return counter(m, "rid_ingest", "rows_handed_to_writer") == float64(len(rows))
	})
	lats := latencies
	var maxLat, sum time.Duration
	for _, l := range lats {
		sum += l
		maxLat = max(maxLat, l)
	}
	t.Logf("load smoke: %d receivers x %d aircraft x %d msg/s for %d s in %s", nRx, aircraft, perSecond, seconds, elapsed.Round(time.Millisecond))
	t.Logf("sent %d = handed over %d + shed %d + refused %d + duplicates %d + transport errors %d (HTTP %v)",
		sent, len(rows), shed, refused, duplicates, transport, statuses)
	t.Logf("request latency: mean %s, max %s", (sum / time.Duration(max(1, len(lats)))).Round(time.Microsecond), maxLat.Round(time.Microsecond))
	t.Logf("rid-ingest counters: observations_accepted %.0f, rows_handed_to_writer %.0f, queue_shed_observations %.0f, batches_refused %.0f, observations_duplicate %.0f",
		counter(line, "rid_ingest", "observations_accepted"), counter(line, "rid_ingest", "rows_handed_to_writer"),
		counter(line, "rid_ingest", "queue_shed_observations"), counter(line, "rid_ingest", "batches_refused"),
		counter(line, "rid_ingest", "observations_duplicate"))
	if sent != nRx*aircraft*perSecond*seconds {
		t.Fatalf("sent %d", sent)
	}
	if len(rows)+shed+refused+duplicates+transport != sent || accepted != len(rows)+shed {
		t.Fatalf("the counts do not add up: sent %d, accepted %d, handed over %d, shed %d, refused %d, duplicates %d, transport %d",
			sent, accepted, len(rows), shed, refused, duplicates, transport)
	}
	if counter(line, "rid_ingest", "observations_accepted") != float64(accepted) {
		t.Fatalf("the process counted %v accepted, the receivers %d", counter(line, "rid_ingest", "observations_accepted"), accepted)
	}
}

// postNoFatal is post for goroutines: errors are returned, not fatal.
func postNoFatal(h *harness, r testRx, nonce string, obs []string) (int, ack, error) {
	body := fmt.Sprintf(`{"receiver_id":%q,"sent_at_ms":%d,"nonce":%q,"backlog":false,"observations":[%s]}`,
		r.id, time.Now().UnixMilli(), nonce, strings.Join(obs, ","))
	req, err := http.NewRequest(http.MethodPost, h.base+"/v1/rid/observations", strings.NewReader(body))
	if err != nil {
		return 0, ack{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", r.bearer)
	req.Header.Set(receivers.SignatureHeader, auth.SignReport(r.secret, []byte(body)))
	resp, err := client.Do(req)
	if err != nil {
		return 0, ack{}, err
	}
	defer resp.Body.Close()
	var a ack
	_ = json.NewDecoder(resp.Body).Decode(&a)
	return resp.StatusCode, a, nil
}
