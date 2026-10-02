package picture

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/sources"
)

// fakeSwitches is a source-control state: off per key with who.
type fakeSwitches struct {
	mu    sync.Mutex
	off   map[string]coresources.Why
	who   map[string]string
	known bool
}

func (f *fakeSwitches) Query(t string, inst *string) coresources.Decision {
	f.mu.Lock()
	defer f.mu.Unlock()
	if w, ok := f.off[sourceKey(t, nil)]; ok {
		return coresources.Decision{WhyDisabled: &w}
	}
	if inst != nil {
		if w, ok := f.off[sourceKey(t, inst)]; ok {
			return coresources.Decision{WhyDisabled: &w}
		}
	}
	return coresources.Decision{Enabled: true}
}

func (f *fakeSwitches) DisabledByWho(t string, inst *string) *string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if w, ok := f.who[sourceKey(t, inst)]; ok {
		return &w
	}
	if w, ok := f.who[sourceKey(t, nil)]; ok {
		return &w
	}
	return nil
}

func (f *fakeSwitches) Known() bool { return f.known }

func (f *fakeSwitches) InstancesOff() []sources.Control {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sources.Control
	for k, why := range f.off {
		i := strings.IndexByte(k, 0)
		typ, inst := k[:i], k[i+1:]
		if inst == "*" || why != coresources.WhyInstance {
			continue
		}
		out = append(out, sources.Control{SourceType: typ, InstanceID: &inst, Actor: f.who[k], ChangedAt: time.Now()})
	}
	return out
}

func (f *fakeSwitches) switchOff(t string, inst *string, why coresources.Why, who string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.off == nil {
		f.off, f.who = map[string]coresources.Why{}, map[string]string{}
	}
	f.off[sourceKey(t, inst)] = why
	f.who[sourceKey(t, inst)] = who
}

// adapterStatus is one src.v1 message of rid-ingest for receiver id.
func adapterStatus(t *testing.T, id, state string, ageS float64, at time.Time) []byte {
	t.Helper()
	body := sources.StatusBody{
		Source: sources.TypeDirectRID, SourceInstance: &id, State: state, Since: bus.Stamp(at.Add(-time.Minute)), AgeS: &ageS,
		Counters: map[string]uint64{"accepted": 10, "refused": 1, "dropped_shed": 0},
	}
	raw, err := json.Marshal(bus.SystemEnvelope("source/status/v1", "authority/rid-ingest", at, body))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sourceRow(rows []SourceState, typ string, inst *string) (SourceState, bool) {
	for _, r := range rows {
		if r.Source == typ && eqStr(r.SourceInstance, inst) {
			return r, true
		}
	}
	return SourceState{}, false
}

// B-11, SC-08: a source switched off reads "disabled by <who>" at the
// next computation even while its adapter still says live; switched on
// again it is live with disabled_by null (E-01 pair). Each row is
// source/status/v1's body, and a change is reported once.
func TestSourceDisabledByWhoAtTheNextInterval(t *testing.T) {
	store := sources.NewStatusStore(10)
	sw := &fakeSwitches{known: true}
	v := &SourceView{Statuses: store, Switches: sw, StaleAfter: 10 * time.Second, Types: sources.Types}
	now := time.Now()
	store.Offer(adapterStatus(t, "rx-1", "live", 0.4, now))
	all, changed := v.Compute(now)
	rx := "rx-1"
	r, ok := sourceRow(all, sources.TypeDirectRID, &rx)
	if !ok || r.State != StateLive || r.DisabledBy != nil || len(changed) != len(all) {
		t.Fatalf("first: %+v changed %d of %d", r, len(changed), len(all))
	}
	for _, row := range all {
		raw, _ := json.Marshal(bus.SystemEnvelope(SchemaSource, Producer, now, row))
		validate(t, idSource, raw)
	}
	if typeRow, _ := sourceRow(all, sources.TypeDirectRID, nil); typeRow.State != StateLive || typeRow.Counters["accepted"] != 10 {
		t.Fatalf("type row %+v", typeRow)
	}
	if _, changed = v.Compute(now.Add(time.Second)); len(changed) != 0 {
		t.Fatalf("unchanged computed as changed: %+v", changed)
	}
	sw.switchOff(sources.TypeDirectRID, &rx, coresources.WhyInstance, "admin:n.beridze")
	all, changed = v.Compute(now.Add(2 * time.Second))
	r, _ = sourceRow(all, sources.TypeDirectRID, &rx)
	if r.State != StateDisabled || r.DisabledBy == nil || *r.DisabledBy != "instance" || r.DisabledByWho == nil || *r.DisabledByWho != "admin:n.beridze" {
		t.Fatalf("switched off: %+v", r)
	}
	if _, ok := sourceRow(changed, sources.TypeDirectRID, &rx); !ok || r.Since != bus.Stamp(now.Add(2*time.Second)) {
		t.Fatalf("changed %+v since %s", changed, r.Since)
	}
	if v.StateOf(sources.TypeDirectRID, rx) != StateDisabled {
		t.Fatal("source_state of the instance")
	}
	raw, _ := json.Marshal(bus.SystemEnvelope(SchemaSource, Producer, now, r))
	validate(t, idSource, raw)
}

// A type switched off disables its every instance by type; an adapter
// silent for longer than SOURCE_STATUS_STALE_S is stale whatever it said
// (it cannot say otherwise); a never-heard type is unknown with age null.
func TestSourceTypeOffSilentAdapterAndNeverHeard(t *testing.T) {
	store := sources.NewStatusStore(10)
	sw := &fakeSwitches{known: true}
	v := &SourceView{Statuses: store, Switches: sw, StaleAfter: 10 * time.Second, Types: sources.Types}
	now := time.Now()
	store.Offer(adapterStatus(t, "rx-1", "live", 0.4, now))
	rx := "rx-1"
	all, _ := v.Compute(now.Add(11 * time.Second))
	if r, _ := sourceRow(all, sources.TypeDirectRID, &rx); r.State != StateStale {
		t.Fatalf("silent adapter: %+v", r)
	}
	if r, _ := sourceRow(all, sources.TypeNetworkRID, nil); r.State != StateUnknown || r.AgeS != nil {
		t.Fatalf("never heard: %+v", r)
	}
	if v.TypeState(sources.TypeNetworkRID) != StateUnknown {
		t.Fatal("type state")
	}
	sw.switchOff(sources.TypeDirectRID, nil, coresources.WhyType, "admin:x")
	all, _ = v.Compute(now.Add(12 * time.Second))
	r, _ := sourceRow(all, sources.TypeDirectRID, &rx)
	tr, _ := sourceRow(all, sources.TypeDirectRID, nil)
	if r.State != StateDisabled || *r.DisabledBy != "type" || tr.State != StateDisabled || *tr.DisabledByWho != "admin:x" {
		t.Fatalf("type off: %+v / %+v", r, tr)
	}
	if got := v.StateOf(sources.TypeDirectRID, "rx-unseen"); got != StateDisabled {
		t.Fatalf("an unseen instance of a type switched off is %s", got)
	}
}

// An instance switched off whose adapter was never heard is listed as
// disabled by whom (B-11); one never heard and not switched off is not
// listed (only its type's row is).
func TestNeverHeardInstanceSwitchedOffIsListed(t *testing.T) {
	sw := &fakeSwitches{known: true}
	v := &SourceView{Statuses: sources.NewStatusStore(10), Switches: sw, StaleAfter: 10 * time.Second, Types: sources.Types}
	now := time.Now()
	all, _ := v.Compute(now)
	if len(all) != len(sources.Types) {
		t.Fatalf("rows %d", len(all))
	}
	quiet := "ussp-peer-ge-02"
	sw.switchOff(sources.TypeNetworkRID, &quiet, coresources.WhyInstance, "admin:n.beridze")
	all, changed := v.Compute(now.Add(time.Second))
	r, ok := sourceRow(all, sources.TypeNetworkRID, &quiet)
	if !ok || r.State != StateDisabled || r.DisabledByWho == nil || *r.DisabledByWho != "admin:n.beridze" || r.AgeS != nil {
		t.Fatalf("row %+v", r)
	}
	if _, ok := sourceRow(changed, sources.TypeNetworkRID, &quiet); !ok {
		t.Fatal("not announced")
	}
	raw, _ := json.Marshal(bus.SystemEnvelope(SchemaSource, Producer, now, r))
	validate(t, idSource, raw)
}

// The hub announces a source change to every console as a
// source/status/v1 frame within one status interval, and puts every
// source in its status.
func TestHubAnnouncesSourceChanges(t *testing.T) {
	store := sources.NewStatusStore(10)
	sw := &fakeSwitches{known: false}
	sv := &SourceView{Statuses: store, Switches: sw, StaleAfter: 10 * time.Second, Types: sources.Types}
	h := NewHub(Config{StatusInterval: time.Hour}, Inputs{SwitchesKnown: sw.Known}, sv, nil)
	t.Cleanup(h.Close)
	conn := connect(t, h, consoleSession(), nil)
	now := time.Now()
	store.Offer(adapterStatus(t, "rx-1", "live", 0.4, now))
	h.Tick(now)
	st := statusOf(t, mustUntil(t, conn, SchemaStatus))
	if !has(st.Degraded, DegradedSwitchesUnknown) || len(st.Sources) != 4 {
		t.Fatalf("degraded %v sources %d", st.Degraded, len(st.Sources))
	}
	conn.drain()
	rx := "rx-1"
	sw.switchOff(sources.TypeDirectRID, &rx, coresources.WhyInstance, "admin:n.beridze")
	h.Tick(now.Add(2 * time.Second))
	for {
		f, raw := conn.until(t, SchemaSource, time.Second)
		var s SourceState
		if err := json.Unmarshal(f.Body, &s); err != nil {
			t.Fatal(err)
		}
		if s.SourceInstance == nil {
			continue // the type row changed too (no instance live)
		}
		if s.State != StateDisabled || s.DisabledByWho == nil || *s.DisabledByWho != "admin:n.beridze" {
			t.Fatalf("source frame %s", raw)
		}
		return
	}
}
