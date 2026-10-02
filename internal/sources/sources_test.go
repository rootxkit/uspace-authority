package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-authority/internal/bus"
)

func strp(s string) *string { return &s }

type vecControl struct {
	SourceType string  `json:"source_type"`
	InstanceID *string `json:"instance_id"`
	Enabled    bool    `json:"enabled"`
}

type vecInput struct {
	Controls    []vecControl `json:"controls"`
	DefaultDeny bool         `json:"default_deny"`
	Query       struct {
		SourceType string  `json:"source_type"`
		InstanceID *string `json:"instance_id"`
	} `json:"query"`
}

type vecExpected struct {
	Enabled     bool    `json:"enabled"`
	WhyDisabled *string `json:"why_disabled"`
}

// source_control.json through this system's path: the wire shape of the
// vector becomes the KV document api writes, which is encoded in its
// envelope, decoded as a follower reads it, applied to the follower and
// queried. The judgement is core's; this proves the transport keeps it.
func TestVectorsSourceControlThroughTheKVEncoding(t *testing.T) {
	f := vectors.Load(t, "source_control.json")
	ran := 0
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in vecInput
		var exp vecExpected
		c.Decode(t, &in, &exp)
		d := Document{Epoch: "vectors", Version: 1, DefaultDeny: in.DefaultDeny}
		for _, rc := range in.Controls {
			d.Controls = append(d.Controls, Control{SourceType: rc.SourceType, InstanceID: rc.InstanceID, Enabled: rc.Enabled,
				Reason: "vector", Actor: "vector", ChangedAt: time.Unix(0, 0).UTC(), Version: 1})
		}
		raw, err := Encode(d, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fol := NewFollower()
		if !fol.Offer(raw) {
			t.Fatal("the first state was not applied")
		}
		got := fol.Query(in.Query.SourceType, in.Query.InstanceID)
		if got.Enabled != exp.Enabled {
			t.Errorf("enabled %v, want %v", got.Enabled, exp.Enabled)
		}
		var why *string
		if got.WhyDisabled != nil {
			why = strp(string(*got.WhyDisabled))
		}
		vectors.EqualStrPtr(t, "why_disabled", why, exp.WhyDisabled)
		ran++
	})
	if ran != 8 {
		t.Errorf("ran %d cases, want 8", ran)
	}
}

func doc(epoch string, version uint64, controls ...Control) Document {
	return Document{Epoch: epoch, Version: version, Controls: controls}
}

func ctl(typ string, inst *string, enabled bool, actor string) Control {
	return Control{SourceType: typ, InstanceID: inst, Enabled: enabled, Reason: "r-" + actor, Actor: actor, ChangedAt: time.Unix(100, 0).UTC(), Version: 1}
}

// B-09: within an epoch only a strictly higher version is taken; a new
// epoch is taken at any version. Each refusal and each new epoch is
// counted.
func TestFollowerGoesOnlyForwardWithinAnEpochAndTakesANewEpoch(t *testing.T) {
	f := NewFollower()
	if f.Known() || !f.Query(TypeDirectRID, strp("rx-1")).Enabled {
		t.Fatal("with no state everything must be enabled")
	}
	off := ctl(TypeDirectRID, nil, false, "admin-1")
	if !f.Apply(doc("e1", 5, off)) || f.Query(TypeDirectRID, strp("rx-1")).Enabled {
		t.Fatal("first state not applied")
	}
	if f.Apply(doc("e1", 5)) || f.Apply(doc("e1", 4)) {
		t.Fatal("an equal or lower version was applied")
	}
	if f.Query(TypeDirectRID, strp("rx-1")).Enabled {
		t.Fatal("an ignored state changed the decision")
	}
	if f.CoreCounters().Get(coresources.CounterIgnoredOlderVersion) != 2 {
		t.Fatal(f.CoreCounters().Snapshot())
	}
	if !f.Apply(doc("e1", 6)) || !f.Query(TypeDirectRID, strp("rx-1")).Enabled {
		t.Fatal("a higher version was not applied")
	}
	// A restored database: a new epoch at a lower version is taken.
	if !f.Apply(doc("e2", 1, off)) || f.Query(TypeDirectRID, nil).Enabled {
		t.Fatal("a new epoch was not taken")
	}
	if f.CoreCounters().Get(coresources.CounterNewEpoch) != 1 || f.CoreCounters().Get(coresources.CounterApplied) != 3 {
		t.Fatal(f.CoreCounters().Snapshot())
	}
}

// B-11: a disabled source says who disabled it: the type row's actor
// when the type is off, the instance row's when the instance is; nobody
// when it is enabled or disabled by default deny.
func TestFollowerSaysWhoDisabledASource(t *testing.T) {
	f := NewFollower()
	f.Apply(Document{Epoch: "e", Version: 1, Controls: []Control{
		ctl(TypeDirectRID, nil, false, "admin-type"), ctl(TypeDirectRID, strp("rx-1"), true, "admin-on"),
		ctl(TypeNetworkRID, strp("ussp-1"), false, "admin-inst"),
	}})
	if c := f.DisabledBy(TypeDirectRID, strp("rx-1")); c == nil || c.Actor != "admin-type" || c.Reason != "r-admin-type" {
		t.Fatalf("by type: %+v", c)
	}
	if w := f.DisabledByWho(TypeNetworkRID, strp("ussp-1")); w == nil || *w != "admin-inst" {
		t.Fatalf("by instance: %v", w)
	}
	if f.DisabledBy(TypeNetworkRID, strp("ussp-2")) != nil || f.DisabledByWho(TypeANSPFeed, nil) != nil {
		t.Fatal("an enabled source has a disabler")
	}
	g := NewFollower()
	g.Apply(Document{Epoch: "e", Version: 1, DefaultDeny: true})
	if d := g.Query(TypeANSPFeed, strp("feed-1")); d.Enabled || g.DisabledBy(TypeANSPFeed, strp("feed-1")) != nil {
		t.Fatalf("default deny: %+v", d)
	}
}

// A value that is not a document is ignored and counted; the state held
// stays (never fail closed).
func TestFollowerIgnoresAMalformedValueAndKeepsItsState(t *testing.T) {
	f := NewFollower()
	raw, _ := Encode(doc("e", 1, ctl(TypeDirectRID, nil, false, "a")), time.Now())
	f.Offer(raw)
	wrongSchema := bytes.Replace(raw, []byte(Schema), []byte("source/status/v1"), 1)
	noEpoch := bytes.Replace(raw, []byte(`"epoch":"e"`), []byte(`"epoch":""`), 1)
	noType := bytes.Replace(raw, []byte(`"source_type":"direct_rid"`), []byte(`"source_type":""`), 1)
	for _, bad := range [][]byte{[]byte("{"), wrongSchema, noEpoch, noType} {
		if f.Offer(bad) {
			t.Fatalf("applied %s", bad)
		}
	}
	if f.Counters().Get(CounterMalformed) != 4 || f.Query(TypeDirectRID, nil).Enabled {
		t.Fatal(f.Counters().Snapshot())
	}
	if _, err := Decode(wrongSchema); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

func TestDocumentEncodesInItsEnvelopeAndComparesBySwitches(t *testing.T) {
	d := doc("e", 3, ctl(TypeDirectRID, strp("rx-1"), false, "a"))
	raw, err := Encode(d, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if m["schema"] != Schema || m["producer"] != Producer || m["time_source"] != "system" {
		t.Fatalf("%s", raw)
	}
	back, err := Decode(raw)
	if err != nil || !back.Same(d) {
		t.Fatalf("%+v %v", back, err)
	}
	other := d
	other.Version = 4
	if other.Same(d) || !other.SameContent(d) {
		t.Fatal("version")
	}
	other.Controls = []Control{ctl(TypeDirectRID, strp("rx-1"), true, "a")}
	if other.SameContent(d) {
		t.Fatal("content")
	}
	empty, _ := Encode(Document{Epoch: "e"}, time.Now())
	if !bytes.Contains(empty, []byte(`"controls":[]`)) {
		t.Fatalf("%s", empty)
	}
}

type fakeKV struct {
	jetstream.KeyValue
	value []byte
	err   error
}

func (k *fakeKV) Get(context.Context, string) (jetstream.KeyValueEntry, error) {
	if k.err != nil {
		return nil, k.err
	}
	if k.value == nil {
		return nil, jetstream.ErrKeyNotFound
	}
	return entry{k.value}, nil
}

type entry struct{ v []byte }

func (e entry) Bucket() string                  { return "b" }
func (e entry) Key() string                     { return StateKey }
func (e entry) Value() []byte                   { return e.v }
func (e entry) Revision() uint64                { return 1 }
func (e entry) Created() time.Time              { return time.Time{} }
func (e entry) Delta() uint64                   { return 0 }
func (e entry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

func logs() (*slog.Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return slog.New(slog.NewJSONHandler(&b, nil)), &b
}

// SC-08 step 8, E-02: a follower started while the store is unreachable
// tries its attempts, then starts with every source enabled and says the
// switch state is unknown.
func TestStartWithTheStoreDownStartsEnabledAndSaysSo(t *testing.T) {
	kv := &fakeKV{err: errors.New("nats: timeout")}
	opens := 0
	logger, out := logs()
	f, _ := Start(context.Background(), Options{
		Source:   Source{Open: func(context.Context) (jetstream.KeyValue, error) { opens++; return kv, nil }},
		Attempts: 3, Backoff: time.Millisecond, Logger: logger,
	})
	if opens != 3 || f.Known() || !f.Query(TypeDirectRID, strp("rx-1")).Enabled {
		t.Fatalf("opens %d known %v", opens, f.Known())
	}
	if f.Counters().Get(CounterReadFailed) != 3 {
		t.Fatal(f.Counters().Snapshot())
	}
	s := out.String()
	if strings.Count(s, "source-control state not readable; retrying") != 2 || !strings.Contains(s, "source-control state unknown: every source is enabled") {
		t.Fatalf("log:\n%s", s)
	}
}

// E-01 twins: with the store up and nothing published, the follower says
// so; with a state published, it applies it and says which.
func TestStartReadsThePublishedStateOrSaysThereIsNone(t *testing.T) {
	kv := &fakeKV{}
	open := func(context.Context) (jetstream.KeyValue, error) { return kv, nil }
	logger, out := logs()
	f, _ := Start(context.Background(), Options{Source: Source{Open: open}, Attempts: 3, Logger: logger})
	if f.Known() || !strings.Contains(out.String(), "no source-control state published yet") || f.Counters().Get(CounterNotPublished) != 1 {
		t.Fatalf("nothing published: %s", out.String())
	}
	kv.value, _ = Encode(doc("e9", 7, ctl(TypeDirectRID, nil, false, "admin-1")), time.Now())
	logger, out = logs()
	f, _ = Start(context.Background(), Options{Source: Source{Open: open}, Attempts: 3, Logger: logger})
	if !f.Known() || f.Query(TypeDirectRID, nil).Enabled || !strings.Contains(out.String(), `"source_control_version":7`) {
		t.Fatalf("published: %s", out.String())
	}
	attrs := f.StatusAttrs()
	if len(attrs) != 4 || attrs[1].Value.String() != "e9" {
		t.Fatal(attrs)
	}
	if a := NewFollower().StatusAttrs(); len(a) != 1 || a[0].Value.Bool() {
		t.Fatal(a)
	}
}

func statusMsg(t *testing.T, typ, inst, state string, ageS *float64, lagging bool) []byte {
	t.Helper()
	body := StatusBody{Source: typ, SourceInstance: &inst, State: state, AgeS: ageS, Lagging: lagging, Counters: map[string]uint64{"accepted": 1, "refused": 2}}
	raw, err := json.Marshal(bus.SystemEnvelope("source/status/v1", "authority/test", time.Now(), body))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// E-10: the store holds at most Max sources; past it the one heard
// longest ago goes, counted; at the bound nothing goes.
func TestStatusStoreBoundIsExceededAndMet(t *testing.T) {
	now := time.Unix(1000, 0)
	s := NewStatusStore(2)
	s.Now = func() time.Time { return now }
	s.Offer(statusMsg(t, TypeDirectRID, "rx-1", "live", nil, false))
	now = now.Add(time.Second)
	s.Offer(statusMsg(t, TypeDirectRID, "rx-2", "live", nil, false))
	s.Offer(statusMsg(t, TypeDirectRID, "rx-2", "live", nil, false)) // an update is not a new source
	if s.Len() != 2 || s.Counters.Get(CounterStatusEvicted) != 0 {
		t.Fatal("at the bound")
	}
	now = now.Add(time.Second)
	s.Offer(statusMsg(t, TypeNetworkRID, "ussp-1", "live", nil, false))
	if s.Len() != 2 || s.Counters.Get(CounterStatusEvicted) != 1 {
		t.Fatal("past the bound")
	}
	if _, ok := s.Get(TypeDirectRID, strp("rx-1")); ok {
		t.Fatal("the oldest was kept")
	}
	if got := s.Instances(); len(got) != 2 || got[0] != [2]string{TypeDirectRID, "rx-2"} {
		t.Fatal(got)
	}
	s.Offer([]byte("{"))
	s.Offer(bytes.Replace(statusMsg(t, TypeDirectRID, "rx-1", "live", nil, false), []byte("source/status/v1"), []byte("x/y/v1"), 1))
	if s.Counters.Get(CounterStatusMalformed) != 2 || s.Counters.Get(CounterStatusReceived) != 4 {
		t.Fatal(s.Counters.Snapshot())
	}
}

// B-11, B-03: each health the console shows, from the adapter's status
// and the age of that status.
func TestHealthMapsEveryStatus(t *testing.T) {
	now := time.Unix(1000, 0)
	fresh, old := now.Add(-time.Second), now.Add(-time.Minute)
	age := func(v float64) *float64 { return &v }
	stale := 10 * time.Second
	for _, c := range []struct {
		st   Status
		have bool
		want string
	}{
		{Status{}, false, HealthNeverHeard},
		{Status{Body: StatusBody{State: "live"}, ReceivedAt: fresh}, true, HealthHealthy},
		{Status{Body: StatusBody{State: "live", Lagging: true}, ReceivedAt: fresh}, true, HealthLagging},
		{Status{Body: StatusBody{State: "live"}, ReceivedAt: old}, true, HealthStale},
		{Status{Body: StatusBody{State: "stale"}, ReceivedAt: fresh}, true, HealthStale},
		{Status{Body: StatusBody{State: "down"}, ReceivedAt: fresh}, true, HealthStale},
		{Status{Body: StatusBody{State: "unknown"}, ReceivedAt: fresh}, true, HealthNeverHeard},
		{Status{Body: StatusBody{State: "disabled"}, ReceivedAt: fresh}, true, HealthNeverHeard},
		{Status{Body: StatusBody{State: "disabled", AgeS: age(1)}, ReceivedAt: fresh}, true, HealthHealthy},
		{Status{Body: StatusBody{State: "disabled", AgeS: age(60)}, ReceivedAt: fresh}, true, HealthStale},
	} {
		if got := Health(c.st, c.have, now, stale); got != c.want {
			t.Errorf("%+v: %s, want %s", c.st.Body, got, c.want)
		}
	}
}
