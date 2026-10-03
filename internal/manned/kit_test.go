package manned

import (
	"encoding/json"
	"io/fs"
	"sync"
	"testing"
	"time"

	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/api/clients"
)

// memSink records what the ingest publishes.
type memSink struct {
	mu   sync.Mutex
	pubs []Published
	rows []Row
}

func (m *memSink) Publish(p Published) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pubs = append(m.pubs, p)
	return nil
}

func (m *memSink) Rows(rows []Row) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows = append(m.rows, rows...)
}

func (m *memSink) published() []Published {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Published(nil), m.pubs...)
}

// gate is a source-control stand-in: instances listed are off.
type gate struct {
	mu  sync.Mutex
	off map[string]bool
}

func (g *gate) Query(_ string, instanceID *string) coresources.Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.off["*"] {
		why := coresources.WhyType
		return coresources.Decision{WhyDisabled: &why}
	}
	if instanceID != nil && g.off[*instanceID] {
		why := coresources.WhyInstance
		return coresources.Decision{WhyDisabled: &why}
	}
	return coresources.Decision{Enabled: true}
}

func (g *gate) set(instance string, off bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.off == nil {
		g.off = map[string]bool{}
	}
	g.off[instance] = off
}

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func newTestIngest(t *testing.T) (*Ingest, *memSink) {
	t.Helper()
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	in := &Ingest{V: v, Sink: sink, Feed: NewFeed(DefaultFeedSettings(), t0)}
	return in, sink
}

// example is one of the ANSP's pinned examples as a generic object.
func example(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := fs.ReadFile(clients.ANSPSchemas, "ansp-schemas/examples/track/manned/v1/"+name)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func stampOf(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// frame is the live-ads-b example captured at captured (ANSP clock),
// written ageS later, with set applied to the body and drop removed
// from the envelope.
func frame(t *testing.T, captured time.Time, ageS float64, set map[string]any, drop ...string) []byte {
	t.Helper()
	m := example(t, "live-ads-b.json")
	m["captured_at"], m["rx_ts"], m["ts"] = stampOf(captured), stampOf(captured.Add(180*time.Millisecond)), stampOf(captured)
	body := m["body"].(map[string]any)
	body["age_s"] = ageS
	for k, v := range set {
		if v == nil {
			body[k] = nil
			continue
		}
		body[k] = v
	}
	for _, k := range drop {
		delete(m, k)
	}
	b, _ := json.Marshal(m)
	return b
}

func envelopeFrame(schema string, now time.Time, body any) []byte {
	b, _ := json.Marshal(map[string]any{"schema": schema, "msg_id": "01K6N5SXS5AA819X9YP981068V", "producer": "ansp/manned-feed",
		"ts": nil, "rx_ts": stampOf(now), "captured_at": stampOf(now), "time_source": "system", "backlog": false, "body": body})
	return b
}

func statusFrame(now time.Time, adapters []map[string]any, sources []map[string]any, degraded ...string) []byte {
	if degraded == nil {
		degraded = []string{}
	}
	return envelopeFrame(SchemaStatus, now, map[string]any{"connection_id": "c", "server_ts": stampOf(now), "policy_version": "1",
		"stale_after_s": 5, "live_max_age_s": 3, "dropped_frames": 2, "degraded": degraded, "sources": sources, "adapters": adapters})
}

func decodeMsg(t *testing.T, p Published) map[string]any {
	t.Helper()
	b, _ := json.Marshal(p.Message)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
