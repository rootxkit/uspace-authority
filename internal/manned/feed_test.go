package manned

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// B-03, B-04, E-01: the feed is unavailable since start before its
// first connection, healthy once connected and fed, stale after
// StaleAfter without any frame (a status frame counts), healthy again on
// a frame, lagging while even the freshest live aircraft is older than
// LagAfter, and unavailable since the instant the socket went down
// (kept across reconnection attempts); disabled outranks the rest.
func TestFeedStates(t *testing.T) {
	f := NewFeed(FeedSettings{StaleAfter: 5 * time.Second, LagAfter: 15 * time.Second}, t0)
	if v := f.View(t0.Add(time.Minute)); v.State != FeedUnavailable || !v.UnavailableSince.Equal(t0) || v.Reason != ReasonNotConnected {
		t.Fatalf("before connecting: %+v", v)
	}
	f.Connected(t0.Add(time.Minute))
	f.Frame(t0.Add(61 * time.Second))
	if v := f.View(t0.Add(64 * time.Second)); v.State != FeedHealthy || v.AgeS == nil || *v.AgeS != 3 {
		t.Fatalf("connected: %+v", v)
	}
	if v := f.View(t0.Add(67 * time.Second)); v.State != FeedStale {
		t.Fatalf("silent 6 s: %+v", v)
	}
	f.Frame(t0.Add(67 * time.Second))
	f.LiveSample(20, t0.Add(67*time.Second))
	v := f.View(t0.Add(68 * time.Second))
	if v.State != FeedLagging || v.LagS == nil || *v.LagS != 20 {
		t.Fatalf("lagging: %+v", v)
	}
	f.LiveSample(1, t0.Add(68*time.Second))
	if v := f.View(t0.Add(69 * time.Second)); v.State != FeedHealthy {
		t.Fatalf("a fresh aircraft: %+v", v)
	}
	down := t0.Add(70 * time.Second)
	f.Down(down, ReasonClosed)
	f.Down(down.Add(10*time.Second), ReasonRefused)
	if v := f.View(down.Add(30 * time.Second)); v.State != FeedUnavailable || !v.UnavailableSince.Equal(down) || v.Reason != ReasonRefused {
		t.Fatalf("down: %+v", v)
	}
	f.SetDisabled(true)
	if v := f.View(down.Add(31 * time.Second)); v.State != FeedDisabled {
		t.Fatalf("disabled: %+v", v)
	}
}

// pubRec records core NATS publications.
type pubRec struct {
	mu   sync.Mutex
	msgs map[string][]byte
}

func (p *pubRec) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.msgs == nil {
		p.msgs = map[string][]byte{}
	}
	p.msgs[subject] = append([]byte(nil), data...)
	return nil
}

func (p *pubRec) body(t *testing.T, subject string) map[string]any {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, ok := p.msgs[subject]
	if !ok {
		t.Fatalf("nothing on %s (have %v)", subject, keysOf(p.msgs))
	}
	var env struct {
		Schema string         `json:"schema"`
		Body   map[string]any `json:"body"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.Schema != SchemaSource {
		t.Fatalf("%s: %v %s", subject, err, raw)
	}
	return env.Body
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// C-12, B-11, E-01: the feed's status says unavailable since T (down,
// never "lost") with its reason, and the aircraft held are aged stale;
// once connected it says live with the ANSP's degraded[]; switched off it
// says disabled by whom. Each ANSP adapter's own status is republished
// with this system's view laid over it.
func TestStatusOfTheFeedAndItsAdapters(t *testing.T) {
	in, sink := newTestIngest(t)
	g := &gate{}
	in.Gate = g
	pub := &pubRec{}
	who := "ops@example.test"
	st := &Status{Ingest: in, Pub: pub, Gate: g, MTLSMode: "off", Who: func(string, *string) *string { return &who }}
	in.HandleFrame(frame(t, t0, 0.3, nil), t0.Add(time.Second))

	st.Publish(t0.Add(2 * time.Second))
	b := pub.body(t, "src.v1.ansp_feed.ansp")
	if b["state"] != "down" || b["feed_state"] != FeedUnavailable || b["unavailable_since"] != stampOf(t0) || b["reason"] != ReasonNotConnected ||
		b["disabled_by"] != nil || b["mtls_mode"] != "off" || b["since"] != stampOf(t0) {
		t.Fatalf("unavailable: %v", b)
	}
	if strings.Contains(strings.ToLower(string(pub.msgs["src.v1.ansp_feed.ansp"])), "lost") {
		t.Fatal("unavailable worded as lost (C-12)")
	}
	if p := sink.published(); len(p) != 2 || p[1].Message.Body.State != StateStale {
		t.Fatalf("aircraft not aged while unavailable: %d", len(p))
	}
	c := b["counters"].(map[string]any)
	if c["accepted"] != 1.0 || c["refused"] != 0.0 || c[CounterFrames] != 1.0 {
		t.Fatalf("counters %v", c)
	}

	in.Feed.Connected(t0.Add(3 * time.Second))
	src := []map[string]any{
		{"source": "ansp_feed", "source_instance": "adsb-tbs", "state": "live", "since": stampOf(t0), "age_s": 0.4, "disabled_by": nil, "counters": map[string]any{"accepted": 3, "refused": 0}},
		{"source": "ansp_feed", "source_instance": "mlat-1", "state": "live", "since": stampOf(t0), "age_s": 0.4, "disabled_by": nil, "counters": map[string]any{"accepted": 3, "refused": 0}},
		{"source": "direct_rid", "source_instance": "rx-1", "state": "live"},
	}
	in.HandleFrame(statusFrame(t0.Add(3*time.Second), nil, src, "cis_stale"), t0.Add(3*time.Second))
	g.set("mlat-1", true)
	st.Publish(t0.Add(4 * time.Second))
	b = pub.body(t, "src.v1.ansp_feed.ansp")
	if b["state"] != "live" || b["feed_state"] != FeedHealthy || b["unavailable_since"] != nil || b["ansp_degraded"].([]any)[0] != "cis_stale" {
		t.Fatalf("healthy: %v", b)
	}
	a := pub.body(t, "src.v1.ansp_feed.adsb-tbs")
	if a["state"] != "live" || a["feed_state"] != FeedHealthy || a["via"] != "ansp_feed:ansp" {
		t.Fatalf("adapter: %v", a)
	}
	m := pub.body(t, "src.v1.ansp_feed.mlat-1")
	if m["state"] != "disabled" || m["disabled_by"] != "instance" || m["disabled_by_who"] != who {
		t.Fatalf("switched-off adapter: %v", m)
	}
	if _, ok := pub.msgs["src.v1.ansp_feed.rx-1"]; ok || in.Counters.Get(CounterAdaptersRefused) != 1 {
		t.Fatal("a status of another source type republished")
	}

	in.Feed.Down(t0.Add(5*time.Second), ReasonClosed)
	st.Publish(t0.Add(6 * time.Second))
	if a := pub.body(t, "src.v1.ansp_feed.adsb-tbs"); a["state"] != "down" || a["feed_state"] != FeedUnavailable {
		t.Fatalf("adapter behind an unavailable feed: %v", a)
	}
	g.set("*", true)
	in.Feed.SetDisabled(true)
	st.Publish(t0.Add(7 * time.Second))
	if b := pub.body(t, "src.v1.ansp_feed.ansp"); b["state"] != "disabled" || b["disabled_by"] != "type" || b["disabled_by_who"] != who {
		t.Fatalf("disabled: %v", b)
	}
	if p := sink.published(); p[len(p)-1].Message.Body.State != StateSourceDisabled {
		t.Fatalf("aircraft not aged source_disabled: %s", p[len(p)-1].Message.Body.State)
	}
}

// Fuzz the frame parser and dispatcher (lessons: fuzz parsers): no
// input panics, and whatever is published is a valid track/manned/v1
// body with a placement.
func FuzzHandleFrame(f *testing.F) {
	f.Add([]byte(`{"schema":"track/manned/v1","msg_id":"x","body":{}}`))
	f.Add([]byte(`{"schema":"console/status/v1","body":{"adapters":[{"id":"a","state":"stale","enabled":true}]}}`))
	f.Add([]byte(`{"schema":"console/snapshot/v1","body":{"manned":[{"schema":"track/manned/v1","body":{"icao24":"abcdef"}}]}}`))
	f.Add([]byte(`{"schema":"x/y/v1","body":{}}`))
	f.Add([]byte(`[]`))
	v, err := NewValidator()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		sink := &memSink{}
		in := &Ingest{V: v, Sink: sink, Feed: NewFeed(DefaultFeedSettings(), t0)}
		in.S.MaxFrameBytes = 1 << 16
		in.HandleFrame(data, t0)
		for _, p := range sink.published() {
			if p.Message.Schema != SchemaTrack || p.Message.CapturedAt == "" || !ValidInstance(p.Message.Body.SourceInstance) {
				t.Fatalf("published %+v", p.Message)
			}
		}
	})
}
