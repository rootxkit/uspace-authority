package bus

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testTopology is the full topology with the renamable buckets given
// names of their own, after deleting every stream and bucket it holds:
// an empty server as far as the topology goes.
func testTopology(t *testing.T, js jetstream.JetStream) Topology {
	t.Helper()
	l := DefaultLimits()
	l.SourceControlBucket, l.RIDReceiverKeysBucket = bustest.Name("sc"), bustest.Name("keys")
	topo := NewTopology(l)
	ctx := context.Background()
	for i := range topo.Streams {
		if err := js.DeleteStream(ctx, topo.Streams[i].Name); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
			t.Fatal(err)
		}
	}
	for i := range topo.Buckets {
		if err := js.DeleteKeyValue(ctx, topo.Buckets[i].Bucket); err != nil && !errors.Is(err, jetstream.ErrBucketNotFound) {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, b := range []string{l.SourceControlBucket, l.RIDReceiverKeysBucket} {
			_ = js.DeleteKeyValue(context.Background(), b)
		}
	})
	return topo
}

// Done-when: Ensure from an empty NATS creates every stream and bucket;
// a second run changes nothing and says so (E-02: the "nothing to do"
// line is read, not assumed).
func TestIntegrationEnsureFromEmptyThenNothingToDo(t *testing.T) {
	_, js := bustest.Connect(t)
	topo := testTopology(t, js)
	ctx := context.Background()
	var out syncBuf
	logger := slog.New(slog.NewJSONHandler(&out, nil))

	r, err := Ensure(ctx, js, topo, logger)
	if err != nil {
		t.Fatal(err)
	}
	if r.Count(ActionCreated) != len(topo.Streams)+len(topo.Buckets) {
		t.Fatalf("first run %+v", r)
	}
	for _, want := range topo.Streams {
		s, err := js.Stream(ctx, want.Name)
		if err != nil {
			t.Fatalf("%s: %v", want.Name, err)
		}
		if d := streamDiff(s.CachedInfo().Config, want); len(d) != 0 {
			t.Errorf("%s created differing in %v", want.Name, d)
		}
	}
	for _, want := range topo.Buckets {
		kv, err := js.KeyValue(ctx, want.Bucket)
		if err != nil {
			t.Fatalf("%s: %v", want.Bucket, err)
		}
		st, _ := kv.Status(ctx)
		if d := bucketDiff(st.Config(), want); len(d) != 0 {
			t.Errorf("%s created differing in %v", want.Bucket, d)
		}
	}
	if !strings.Contains(out.String(), "bus provisioning done") {
		t.Fatalf("first run log:\n%s", out.String())
	}

	out = syncBuf{}
	r, err = Ensure(ctx, js, topo, logger)
	if err != nil || !r.NothingToDo() || r.Count(ActionUnchanged) != len(r.Changes) {
		t.Fatalf("second run %+v %v", r, err)
	}
	if got := out.String(); !strings.Contains(got, `"msg":"bus provisioning: nothing to do"`) || strings.Contains(got, "bus provisioned") {
		t.Fatalf("second run log:\n%s", got)
	}

	// A changed bound is an update, named; storage is not changed in place.
	changed := topo
	changed.Streams = append([]jetstream.StreamConfig(nil), topo.Streams...)
	for i := range changed.Streams {
		if changed.Streams[i].Name == StreamTSW {
			changed.Streams[i].MaxAge = 20 * time.Minute
		}
	}
	r, err = Ensure(ctx, js, changed, logger)
	if err != nil || r.Count(ActionUpdated) != 1 {
		t.Fatalf("update %+v %v", r, err)
	}
	if s, _ := js.Stream(ctx, StreamTSW); s.CachedInfo().Config.MaxAge != 20*time.Minute {
		t.Fatal("TSW was not updated")
	}
	for i := range changed.Streams {
		if changed.Streams[i].Name == StreamTSW {
			changed.Streams[i].Storage = jetstream.MemoryStorage
		}
	}
	if _, err := Ensure(ctx, js, changed, logger); !errors.Is(err, ErrNotUpdatable) || !strings.Contains(err.Error(), "TSW") {
		t.Fatalf("storage change: %v", err)
	}
	if _, err := Ensure(ctx, js, topo, nil); err != nil {
		t.Fatal(err)
	}
}

// E-10: a message past a stream's maximum size and a value past a
// bucket's maximum are refused by the server; at the bound both pass.
func TestIntegrationStreamAndBucketBoundsRefuseWhatIsTooLarge(t *testing.T) {
	_, js := bustest.Connect(t)
	ctx := context.Background()
	l := DefaultLimits()
	l.SourceControlBucket, l.SourceControlValueBytes = bustest.Name("sc_bound"), 1024
	topo := NewTopology(l)
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), l.SourceControlBucket) })
	cfg, _ := topo.Bucket(l.SourceControlBucket)
	kv, err := OpenBucket(ctx, js, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, "state", bytes.Repeat([]byte("x"), 1024)); err != nil {
		t.Fatalf("a value at the bound: %v", err)
	}
	if _, err := kv.Put(ctx, "state", bytes.Repeat([]byte("x"), 1025)); err == nil {
		t.Fatal("a value past the bucket's bound was stored")
	}

	trk, _ := topo.Stream(StreamTRK)
	trk.Name, trk.Subjects, trk.Storage = bustest.Name("TRKBOUND"), []string{"trkbound.test.>"}, jetstream.MemoryStorage
	if _, err := OpenStream(ctx, js, trk); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), trk.Name) })
	if _, err := js.Publish(ctx, "trkbound.test.a", bytes.Repeat([]byte("x"), int(trk.MaxMsgSize))); err != nil {
		t.Fatalf("a message at the bound: %v", err)
	}
	if _, err := js.Publish(ctx, "trkbound.test.a", bytes.Repeat([]byte("x"), int(trk.MaxMsgSize)+1)); err == nil {
		t.Fatal("a message past the stream's bound was stored")
	}
}

// OpenStream and OpenBucket create what is missing and never change what
// exists (only api's Ensure does).
func TestIntegrationOpenCreatesWhatIsMissingAndLeavesTheRest(t *testing.T) {
	_, js := bustest.Connect(t)
	ctx := context.Background()
	name := bustest.Name("OPEN")
	cfg := jetstream.StreamConfig{Name: name, Subjects: []string{"opentest." + name + ".>"}, Storage: jetstream.MemoryStorage, MaxAge: time.Minute}
	t.Cleanup(func() { _ = js.DeleteStream(context.Background(), name) })
	if _, err := OpenStream(ctx, js, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.MaxAge = time.Hour
	s, err := OpenStream(ctx, js, cfg)
	if err != nil || s.CachedInfo().Config.MaxAge != time.Minute {
		t.Fatalf("OpenStream changed an existing stream: %v", err)
	}
	bucket := bustest.Name("open")
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	if _, err := OpenBucket(ctx, js, jetstream.KeyValueConfig{Bucket: bucket, History: 2, Storage: jetstream.MemoryStorage}); err != nil {
		t.Fatal(err)
	}
	kv, err := OpenBucket(ctx, js, jetstream.KeyValueConfig{Bucket: bucket, History: 8, Storage: jetstream.MemoryStorage})
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := kv.Status(ctx); st.History() != 2 {
		t.Fatalf("OpenBucket changed an existing bucket: history %d", st.History())
	}
}

// Push then re-read: a value reaches the follower through the watch and
// through the push subject, and the periodic re-read runs; a delete is a
// re-read, never a state.
func TestIntegrationFollowDeliversWatchPushAndReread(t *testing.T) {
	nc, js := bustest.Connect(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bucket, subject := bustest.Name("follow"), "ctltest."+bustest.Name("push")
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	cfg := jetstream.KeyValueConfig{Bucket: bucket, History: 8, Storage: jetstream.MemoryStorage}
	kv, err := OpenBucket(ctx, js, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var values []string
	reloads := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		Follow{
			Open: func(ctx context.Context) (jetstream.KeyValue, error) { return OpenBucket(ctx, js, cfg) },
			Key:  "state", Conn: nc, Subject: subject, Reread: 200 * time.Millisecond, Retry: 50 * time.Millisecond,
			OnValue: func(b []byte) { mu.Lock(); values = append(values, string(b)); mu.Unlock() },
			Reload:  func(context.Context) { mu.Lock(); reloads++; mu.Unlock() },
		}.Run(ctx)
	}()
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			good := ok()
			mu.Unlock()
			if good {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("no %s: values %v reloads %d", what, values, reloads)
	}
	time.Sleep(200 * time.Millisecond) // the watch and the subscription are up
	if _, err := kv.Put(ctx, "state", []byte("from-watch")); err != nil {
		t.Fatal(err)
	}
	waitFor("watch value", func() bool { return len(values) > 0 && values[len(values)-1] == "from-watch" })
	if err := nc.Publish(subject, []byte("from-push")); err != nil {
		t.Fatal(err)
	}
	waitFor("push value", func() bool { return values[len(values)-1] == "from-push" })
	mu.Lock()
	before := reloads
	mu.Unlock()
	if err := kv.Delete(ctx, "state"); err != nil {
		t.Fatal(err)
	}
	waitFor("re-read after a delete and on the timer", func() bool { return reloads >= before+2 })
	mu.Lock()
	for _, v := range values {
		if v == "" {
			t.Fatal("a delete was delivered as a value")
		}
	}
	mu.Unlock()
	cancel()
	<-done
}

// E-02 twin of TestConnectWithNATSDownStartsDegradedAndSaysSo: with NATS
// up, the process says it connected, on the first attempt.
func TestIntegrationConnectSaysItConnected(t *testing.T) {
	var buf syncBuf
	nc, err := Connect(context.Background(), Options{URL: bustest.URL(t), Name: "test", Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if nc.Status() != nats.CONNECTED || Ready(nc)(context.Background()) != nil {
		t.Fatal(nc.Status())
	}
	if out := buf.String(); !strings.Contains(out, `"msg":"NATS connected"`) || !strings.Contains(out, `"attempt":1`) || strings.Contains(out, "degraded") {
		t.Fatalf("log:\n%s", out)
	}
}
