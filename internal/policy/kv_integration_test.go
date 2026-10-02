package policy

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
)

func testKV(t *testing.T) KV {
	t.Helper()
	nc, js := bustest.Connect(t)
	bucket := bustest.Name("policy")
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	cfg := jetstream.KeyValueConfig{Bucket: bucket, History: bus.BucketHistory, MaxValueSize: bus.PolicyValueBytes, Storage: jetstream.MemoryStorage}
	return KV{
		Open: func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, js, cfg) },
		Conn: nc, Subject: "ctltest." + bustest.Name("policy"), Timeout: 2 * time.Second, Producer: "authority/api",
		Counters: &core.Counters{},
	}
}

func waitVersion(t *testing.T, f *Follower, v int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for f.Version() != v {
		if time.Now().After(deadline) {
			t.Fatalf("follower at %d, want %d", f.Version(), v)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// INV-03, G-08: the policy api activates reaches a follower through KV
// policy (watch and push), a lower version never rolls it back, and a
// lost bucket is rewritten by the repair; with nothing published the
// follower holds none and counts it (E-02).
func TestIntegrationPolicyTravelsThroughKVAndIsRepaired(t *testing.T) {
	kv := testKV(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := NewFollower(nil)
	go kv.Follow(ctx, f, 200*time.Millisecond, nil)
	time.Sleep(300 * time.Millisecond)
	if _, ok := f.Current(); ok || kv.Counters.Get(CounterKVNotPublished) == 0 {
		t.Fatalf("a policy before any was published: %v", kv.Counters.Snapshot())
	}
	p := Policy{Version: 2, Thresholds: Defaults()}
	p.HeightLimitAGLM = 100
	if err := kv.PublishPolicy(ctx, p); err != nil {
		t.Fatal(err)
	}
	waitVersion(t, f, 2)
	if got, _ := f.Current(); got.HeightLimitAGLM != 100 {
		t.Fatalf("thresholds %+v", got.Thresholds)
	}
	if err := kv.PublishPolicy(ctx, Policy{Version: 1, Thresholds: Defaults()}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if f.Version() != 2 {
		t.Fatalf("rolled back to %d", f.Version())
	}
	// The bucket lost: the repair writes the policy api holds.
	b, err := kv.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Purge(ctx, ActiveKey); err != nil {
		t.Fatal(err)
	}
	if _, published, _ := kv.Read(ctx); published {
		t.Fatal("the purge left a value")
	}
	api := NewFollower(nil)
	api.Apply(Policy{Version: 3, Thresholds: Defaults()})
	go kv.RunRepair(ctx, api, time.Hour, nil)
	waitVersion(t, f, 3)
	if kv.Counters.Get(CounterKVRepaired) == 0 {
		t.Fatal(kv.Counters.Snapshot())
	}
}
