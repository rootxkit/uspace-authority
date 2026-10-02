package bus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/config"
)

func TestSubjectsBuildEveryPlanSubject(t *testing.T) {
	for _, c := range []struct {
		got  func() (string, error)
		want string
	}{
		{func() (string, error) { return Subjects.Trk("c3_131_224", "c5_1317_2248", "trk-1") }, "trk.v1.c3_131_224.c5_1317_2248.trk-1"},
		{func() (string, error) { return Subjects.Man("c3_131_224", "c5_1317_2248", "4b1805") }, "man.v1.c3_131_224.c5_1317_2248.4b1805"},
		{func() (string, error) { return Subjects.Alrt("zone_incursion", "c5_1317_2248", "v-1") }, "alrt.v1.zone_incursion.c5_1317_2248.v-1"},
		{func() (string, error) { return Subjects.Ident("trk-1") }, "ident.v1.trk-1"},
		{func() (string, error) { return Subjects.Cis("restrictions") }, "cis.v1.restrictions"},
		{func() (string, error) { return Subjects.Src("direct_rid", "rx-tbs-01") }, "src.v1.direct_rid.rx-tbs-01"},
		{func() (string, error) { return Subjects.Ingest("c3_131_224") }, "ingest.v1.c3_131_224"},
		{func() (string, error) { return Subjects.Tsw("rid_observations") }, "tsw.v1.rid_observations"},
		// A colon and a dash are literal characters of one token.
		{func() (string, error) { return Subjects.Ident("AA:BB:CC:00:00:01") }, "ident.v1.AA:BB:CC:00:00:01"},
	} {
		got, err := c.got()
		if err != nil || got != c.want {
			t.Errorf("got %q %v, want %q", got, err, c.want)
		}
	}
}

// An id from outside never widens a subject: a dot, a wildcard, white
// space, an empty or an over-long token is refused naming the field.
func TestSubjectsRefuseATokenThatWouldWidenTheSubject(t *testing.T) {
	for _, bad := range []string{"", "a.b", "*", ">", "rx 1", "rx\t1", "a\x00", "a\x7f", strings.Repeat("x", maxTokenLen+1)} {
		_, err := Subjects.Src("direct_rid", bad)
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != "instance_id" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := Subjects.Trk("c3_1_1", "c5.1", "x"); err == nil || !strings.Contains(err.Error(), "cell5") {
		t.Fatalf("cell5 with a dot: %v", err)
	}
	if _, err := Token("t", strings.Repeat("x", maxTokenLen)); err != nil {
		t.Fatalf("a token at the bound: %v", err)
	}
}

var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func TestSystemEnvelopeCarriesThe04Fields(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 15, 6, 2_000_000, time.FixedZone("x", 4*3600))
	env := SystemEnvelope("source/status/v1", "authority/api", now, map[string]int{"n": 1})
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"schema", "msg_id", "producer", "ts", "rx_ts", "captured_at", "time_source", "backlog", "body"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %s in %s", k, raw)
		}
	}
	if m["ts"] != "2026-10-02T05:15:06.002Z" || m["time_source"] != "system" || m["backlog"] != false || !ulidPattern.MatchString(env.MsgID) {
		t.Fatalf("%s", raw)
	}
	a, b := NewULID(now), NewULID(now)
	if a == b || NewULID(time.UnixMilli(0))[:10] != "0000000000" {
		t.Fatalf("%s %s", a, b)
	}
}

type recPub struct {
	subject string
	data    []byte
	err     error
}

func (r *recPub) Publish(subject string, data []byte) error {
	r.subject, r.data = subject, data
	return r.err
}

func TestPublishCoreSendsTheEnvelopeAndReportsAFailure(t *testing.T) {
	p := &recPub{}
	env := SystemEnvelope("x/y/v1", "authority/test", time.Now(), "body")
	if err := PublishCore(p, "src.v1.a.b", env); err != nil || p.subject != "src.v1.a.b" || !bytes.Contains(p.data, []byte(`"body":"body"`)) {
		t.Fatalf("%v %s %s", err, p.subject, p.data)
	}
	p.err = errors.New("disconnected")
	if err := PublishCore(p, "src.v1.a.b", env); err == nil {
		t.Fatal("a failed publish was not reported")
	}
}

// The topology holds every stream and bucket of the plan, each with an
// explicit size bound (E-10), every bucket with history 8, and INGEST
// with no JetStream age limit (the consumer sheds by age with a record).
func TestTopologyHasEveryStreamAndBucketWithExplicitBounds(t *testing.T) {
	topo := NewTopology(DefaultLimits())
	ages := map[string]time.Duration{
		StreamTRK: time.Hour, StreamALRT: 7 * 24 * time.Hour, StreamIDENT: 24 * time.Hour,
		StreamCIS: 30 * 24 * time.Hour, StreamINGEST: 0, StreamTSW: 10 * time.Minute,
	}
	if len(topo.Streams) != len(ages) {
		t.Fatalf("%d streams", len(topo.Streams))
	}
	for name, age := range ages {
		s, ok := topo.Stream(name)
		if !ok || s.MaxAge != age || s.MaxMsgSize <= 0 || s.MaxMsgSize > MaxPayloadBytes || s.Duplicates != dedupe {
			t.Errorf("%s: %+v", name, s)
		}
	}
	in, _ := topo.Stream(StreamINGEST)
	if in.Retention != jetstream.WorkQueuePolicy || in.Discard != jetstream.DiscardNew || in.MaxMsgs != DefaultIngestMaxMsgs {
		t.Fatalf("INGEST %+v", in)
	}
	for _, name := range []string{BucketSourceControl, BucketPolicy, BucketCells, BucketRegistryVersion, BucketZonesVersion, BucketRIDReceiverKeys} {
		b, ok := topo.Bucket(name)
		if !ok || b.History != BucketHistory || b.MaxValueSize <= 0 {
			t.Errorf("%s: %+v", name, b)
		}
	}
	if _, ok := topo.Stream("NOPE"); ok {
		t.Fatal("an unknown stream was found")
	}
	if _, ok := topo.Bucket("nope"); ok {
		t.Fatal("an unknown bucket was found")
	}
	l := DefaultLimits()
	l.SourceControlBucket, l.RIDReceiverKeysBucket, l.SourceControlValueBytes, l.TRKStorage = "sc_test", "keys_test", 2048, jetstream.MemoryStorage
	topo = NewTopology(l)
	if b, ok := topo.Bucket("sc_test"); !ok || b.MaxValueSize != 2048 {
		t.Fatalf("renamed source-control bucket %+v", b)
	}
	if _, ok := topo.Bucket("keys_test"); !ok {
		t.Fatal("renamed key-set bucket missing")
	}
	if s, _ := topo.Stream(StreamTRK); s.Storage != jetstream.MemoryStorage {
		t.Fatal("TRK storage not taken from the limits")
	}
}

func TestLimitsOfReadsTheConfiguration(t *testing.T) {
	c := config.Bus{BusTRKStorage: "memory", BusIngestMaxMsgs: 10, SourceControlBucket: "b", SourceControlMaxValueBytes: 4096}
	l, err := LimitsOf(c, "k")
	if err != nil || l.TRKStorage != jetstream.MemoryStorage || l.IngestMaxMsgs != 10 || l.SourceControlBucket != "b" ||
		l.SourceControlValueBytes != 4096 || l.RIDReceiverKeysBucket != "k" {
		t.Fatalf("%+v %v", l, err)
	}
	c.BusTRKStorage = "tape"
	if _, err := LimitsOf(c, ""); err == nil || !strings.Contains(err.Error(), "BUS_TRK_STORAGE") {
		t.Fatalf("bad storage: %v", err)
	}
}

func TestDiffsNameTheManagedSettingsThatDiffer(t *testing.T) {
	topo := NewTopology(DefaultLimits())
	want, _ := topo.Stream(StreamTSW)
	have := want
	have.MaxMsgs, have.MaxBytes = 0, 0 // the server's spelling of "no limit"
	if d := streamDiff(have, want); len(d) != 0 {
		t.Fatalf("equal configs differ in %v", d)
	}
	have.MaxAge, have.MaxMsgSize, have.Storage, have.Subjects = time.Minute, 1, jetstream.MemoryStorage, []string{"x"}
	have.Discard, have.Duplicates, have.Description, have.Retention, have.MaxMsgs = jetstream.DiscardNew, time.Second, "old", jetstream.WorkQueuePolicy, 5
	have.MaxBytes = 7
	if d := streamDiff(have, want); len(d) != 10 {
		t.Fatalf("diff %v", d)
	}
	wb, _ := topo.Bucket(BucketCells)
	hb := wb
	if d := bucketDiff(hb, wb); len(d) != 0 {
		t.Fatalf("equal buckets differ in %v", d)
	}
	hb.History, hb.MaxValueSize, hb.MaxBytes, hb.Storage, hb.Description = 1, 1, 1, jetstream.MemoryStorage, "old"
	if d := bucketDiff(hb, wb); len(d) != 5 {
		t.Fatalf("bucket diff %v", d)
	}
}

func TestReportCountsAndSaysNothingToDo(t *testing.T) {
	r := Report{Changes: []Change{{Action: ActionUnchanged}, {Action: ActionUnchanged}}}
	if !r.NothingToDo() || r.Count(ActionUnchanged) != 2 {
		t.Fatal(r)
	}
	r.Changes = append(r.Changes, Change{Action: ActionCreated})
	if r.NothingToDo() || r.Count(ActionCreated) != 1 {
		t.Fatal(r)
	}
}

func TestPullConsumerRefusesAnUnboundedConsumer(t *testing.T) {
	_, err := PullConsumer(context.Background(), nil, PullSpec{Durable: "x"})
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "max_ack_pending" {
		t.Fatalf("%v", err)
	}
}

type lineBuf struct{ bytes.Buffer }

// E-02, B-08: with NATS down the process does not fail and does not
// hang: it tries the configured number of times, then returns a
// connection that keeps connecting and says it starts degraded.
func TestConnectWithNATSDownStartsDegradedAndSaysSo(t *testing.T) {
	var buf lineBuf
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	start := time.Now()
	nc, err := Connect(context.Background(), Options{
		URL: "nats://127.0.0.1:1", Name: "test", StartAttempts: 2, StartBackoff: 10 * time.Millisecond,
		DialTimeout: 200 * time.Millisecond, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if time.Since(start) > 5*time.Second {
		t.Fatalf("start took %s", time.Since(start))
	}
	if s := nc.Status(); s == nats.CONNECTED {
		t.Fatal("connected to a port nothing listens on")
	}
	if err := Ready(nc)(context.Background()); err == nil {
		t.Fatal("ready while not connected")
	}
	out := buf.String()
	if strings.Count(out, "NATS not reachable at start; retrying") != 1 || !strings.Contains(out, "starting degraded") {
		t.Fatalf("log:\n%s", out)
	}
}

func TestConnectRefusesAnUnreadableCredentialsFile(t *testing.T) {
	_, err := Connect(context.Background(), Options{URL: "nats://127.0.0.1:1", Creds: t.TempDir() + "/missing.creds"})
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "NATS_CREDS" {
		t.Fatalf("%v", err)
	}
}

func TestConnectStopsRetryingWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Connect(ctx, Options{URL: "nats://127.0.0.1:1", StartAttempts: 3, StartBackoff: time.Hour, DialTimeout: 100 * time.Millisecond})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
}
