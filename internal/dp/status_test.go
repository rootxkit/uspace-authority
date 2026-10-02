package dp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/track"
)

type pubs struct {
	mu   sync.Mutex
	subj []string
	data [][]byte
}

func (p *pubs) Publish(subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subj, p.data = append(p.subj, subject), append(p.data, data)
	return nil
}

// 04 §3.6: src.v1.network_rid.<uss_id> says live with the limits'
// counters and response times; down with unavailable_since once its
// polls fail (never removed); disabled by whom when switched off; unknown
// before its first answer.
func TestStatusStates(t *testing.T) {
	g := &gate{}
	e := engine(t, &fakeSP{}, &recorder{}, nil)
	e.Gate = g
	pub := &pubs{}
	who := "admin@example.test"
	st := &Status{Engine: e, Pub: pub, Who: func(string, *string) *string { return &who }}
	p := NewProvider("ussp-lab-01", spBase, false, t0)
	e.providers[p.BaseURL] = p
	now := t0.Add(time.Second)

	if b := st.Snapshot(p, now); b.State != StateUnknown || !b.ProviderUnknown || b.DSS != DSSUnconfigured {
		t.Fatalf("before an answer: %+v", b)
	}
	p.OK(400*time.Millisecond, now, 3)
	b := st.Snapshot(p, now)
	if b.State != StateLive || b.Flights != 3 || b.P99S != 0.4 || b.AgeS == nil || b.Counters[CounterPollsOK] != 1 {
		t.Fatalf("live: %+v", b)
	}
	p.Failed(time.Second, now.Add(time.Second), 10*time.Second)
	p.Failed(time.Second, now.Add(12*time.Second), 10*time.Second)
	b = st.Snapshot(p, now.Add(12*time.Second))
	if b.State != StateDown || b.UnavailableSince == nil || *b.UnavailableSince != bus.Stamp(now.Add(time.Second)) || b.Since != *b.UnavailableSince {
		t.Fatalf("down: %+v", b)
	}
	g.set("ussp-lab-01", true)
	b = st.Snapshot(p, now.Add(13*time.Second))
	if b.State != StateDisabled || b.DisabledBy == nil || *b.DisabledBy != "instance" || b.DisabledByWho == nil || *b.DisabledByWho != who {
		t.Fatalf("disabled: %+v", b)
	}
	if n := st.Publish(now); n != 1 || pub.subj[0] != "src.v1.network_rid.ussp-lab-01" {
		t.Fatalf("published %d %v", n, pub.subj)
	}
	var env bus.Envelope[StatusBody]
	if err := json.Unmarshal(pub.data[0], &env); err != nil || env.Schema != StatusSchema || env.Body.Source != SourceType {
		t.Fatalf("%v %+v", err, env)
	}
}

// fakeWriter is a ts.Writer that fails while failing is set.
type fakeWriter struct {
	mu      sync.Mutex
	failing bool
	rows    map[string]int
	gaps    []ts.GapMessage
	ids     []string
}

func (w *fakeWriter) Enqueue(_ context.Context, table string, rows any, msgID string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failing {
		return errors.New("jetstream unavailable")
	}
	raw, _ := json.Marshal(rows)
	var list []json.RawMessage
	_ = json.Unmarshal(raw, &list)
	if w.rows == nil {
		w.rows = map[string]int{}
	}
	w.rows[table] += len(list)
	w.ids = append(w.ids, msgID)
	return nil
}

func (w *fakeWriter) EnqueueGap(_ context.Context, g ts.GapMessage, _ string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gaps = append(w.gaps, g)
	return nil
}

// B-13, E-01: rows handed over are counted, each message with its own id
// and at most 100 rows; rows that cannot be handed over after the
// bounded retries are counted lost and recorded as a writer gap.
func TestBusSinkHandsOverOrRecordsTheGap(t *testing.T) {
	w := &fakeWriter{}
	cnt := &core.Counters{}
	s := &BusSink{Writer: w, Counters: cnt, Backoff: time.Millisecond}
	s.init()
	rows := make([]track.Row, 150)
	flights := make([]FlightRow, 150)
	for i := range flights {
		flights[i] = FlightRow{Flight: json.RawMessage(`{}`)}
	}
	s.write(context.Background(), batch{tracks: rows, flights: flights, at: t0})
	if w.rows[TableTracks] != 150 || w.rows[TableUSSPFlights] != 150 || len(w.ids) != 4 || cnt.Snapshot()[CounterRowsHandedOver] != 300 {
		t.Fatalf("rows %v ids %d counters %v", w.rows, len(w.ids), cnt.Snapshot())
	}
	w.failing = true
	s.write(context.Background(), batch{tracks: rows[:2], at: t0})
	s2 := cnt.Snapshot()
	if s2[CounterRowsLost] != 2 || s2[CounterRowsRetried] != 2 || len(w.gaps) != 1 || w.gaps[0].Cause != CauseHandOver || w.gaps[0].Count != 2 {
		t.Fatalf("counters %v gaps %+v", s2, w.gaps)
	}
}

// E-10: a full hand-over queue sheds the poll's rows, counted and
// recorded as a gap; a queue with room takes them.
func TestBusSinkQueueBound(t *testing.T) {
	w := &fakeWriter{}
	cnt := &core.Counters{}
	s := &BusSink{Writer: w, Counters: cnt}
	s.init()
	for range QueueSize {
		s.Rows([]track.Row{{}}, nil)
	}
	if s.Depth() != QueueSize || cnt.Snapshot()[CounterRowsShed] != 0 {
		t.Fatalf("depth %d counters %v", s.Depth(), cnt.Snapshot())
	}
	s.Rows([]track.Row{{}, {}}, nil)
	if cnt.Snapshot()[CounterRowsShed] != 2 || len(w.gaps) != 1 {
		t.Fatalf("counters %v gaps %d", cnt.Snapshot(), len(w.gaps))
	}
}

// E-10: the ISA store refuses a new ISA past its bound, counted; one it
// holds is updated in place.
func TestISAsBound(t *testing.T) {
	s := &ISAs{Max: 1, Counters: &core.Counters{}}
	s.FromSearch("k", []f3411.IdentificationServiceArea{isa("a", "o", spBase)})
	s.FromSearch("k", []f3411.IdentificationServiceArea{isa("a", "o", spBase), isa("b", "o", spBase)})
	if s.Len() != 1 || s.Counters.Snapshot()[CounterISAsRefused] != 1 {
		t.Fatalf("len %d counters %v", s.Len(), s.Counters.Snapshot())
	}
	s.FromSearch("k", nil)
	if s.Len() != 0 {
		t.Fatal("an ISA the tile no longer lists is kept")
	}
}

// E-10: the flight memory forgets the flight seen longest ago past its
// bound, counted.
func TestMemoryBound(t *testing.T) {
	m := NewMemory(1, &core.Counters{})
	m.Fresh(FlightKey{"u", "a"}, state(t0, baseLatDeg, baseLonDeg), t0)
	m.Fresh(FlightKey{"u", "b"}, state(t0, baseLatDeg, baseLonDeg), t0)
	if m.Len() != 1 || m.counters.Snapshot()[CounterFlightsEvicted] != 1 {
		t.Fatalf("len %d counters %v", m.Len(), m.counters.Snapshot())
	}
}

// api/clients/SOURCE names, for the two standards, exactly the file
// uspace-core generated its types from (core's f3411/SOURCE and
// f3548/SOURCE at the version go.mod pins), and the same uas_standards
// commit, so the generated clients and core's types are one contract.
func TestStandardCopiesAreCoresSources(t *testing.T) {
	coreDir := filepath.Dir(filepath.Dir(vectors.Dir()))
	src := read(t, "../../api/clients/SOURCE")
	for _, c := range []struct{ copy, pkg string }{{"dss-rid.yaml", "f3411"}, {"dss-utm.yaml", "f3548"}} {
		kv := map[string]string{}
		for _, l := range strings.Split(read(t, filepath.Join(coreDir, c.pkg, "SOURCE")), "\n") {
			if k, v, ok := strings.Cut(l, " = "); ok && !strings.HasPrefix(l, "#") {
				kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		repo := strings.TrimPrefix(kv["spec_repo"], "https://github.com/")
		want := c.copy + " " + repo + " " + kv["spec_commit"] + " " + kv["spec_path"]
		if !strings.Contains(src, "\n"+want+"\n") {
			t.Errorf("api/clients/SOURCE has no line %q", want)
		}
		if !strings.Contains(src, "uas_standards_commit = "+kv["uas_standards_commit"]) {
			t.Errorf("uas_standards commit %s of core's %s/SOURCE not recorded", kv["uas_standards_commit"], c.pkg)
		}
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}
