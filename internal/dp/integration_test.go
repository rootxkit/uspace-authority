package dp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// syncBuf is a log buffer the process writes while the test reads.
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

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func eventually(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: not within %v", what, within)
}

// tracks collects the Display Provider's track messages from trk.v1.
type tracks struct {
	mu   sync.Mutex
	msgs []map[string]any
}

func (tr *tracks) add(m *nats.Msg) {
	var v map[string]any
	if json.Unmarshal(m.Data, &v) != nil || v["producer"] != dp.Producer {
		return
	}
	tr.mu.Lock()
	tr.msgs = append(tr.msgs, v)
	tr.mu.Unlock()
}

func (tr *tracks) bySource(instance string) []map[string]any {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	var out []map[string]any
	for _, m := range tr.msgs {
		if m["body"].(map[string]any)["source_instance"] == instance {
			out = append(out, m)
		}
	}
	return out
}

// dpStack is a dp-poller process against NATS, a migrated telemetry
// database, a fake DSS and two fake Service Providers.
type dpStack struct {
	t         *testing.T
	nc        *nats.Conn
	js        jetstream.JetStream
	dss       *fakedss.DSS
	sp, sp2   *fakedss.SP
	iss       *issuer
	addr      string
	srcBucket string
	engine    *dp.Engine
	tracks    *tracks
	statuses  sync.Map // uss id -> dp.StatusBody
	logs      *syncBuf
	exit      chan int
	cancel    context.CancelFunc
}

func startDP(t *testing.T, mutate func(map[string]string)) *dpStack {
	t.Helper()
	nc, js := bustest.Connect(t)
	ctx, cancel := context.WithCancel(context.Background())
	// The TSW stream the rows go to, as api provisions it.
	tsw, _ := bus.NewTopology(bus.DefaultLimits()).Stream(bus.StreamTSW)
	if _, err := bus.OpenStream(ctx, js, tsw); err != nil {
		t.Fatal(err)
	}
	s := &dpStack{t: t, nc: nc, js: js, dss: fakedss.NewDSS(), sp: fakedss.NewSP(), sp2: fakedss.NewSP(), iss: newIssuer(t),
		addr: freeAddr(t), srcBucket: bustest.Name("src"), tracks: &tracks{}, logs: &syncBuf{}, exit: make(chan int, 1), cancel: cancel}
	t.Cleanup(func() { s.dss.Close(); s.sp.Close(); s.sp2.Close() })
	sub, err := nc.Subscribe(bus.SubjectTrkAll, s.tracks.add)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	stat, err := nc.Subscribe("src.v1.network_rid.>", func(m *nats.Msg) {
		var env bus.Envelope[dp.StatusBody]
		if json.Unmarshal(m.Data, &env) == nil && env.Body.SourceInstance != nil {
			s.statuses.Store(*env.Body.SourceInstance, env.Body)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stat.Unsubscribe() })

	oversight := bustest.Name("dpo")
	env := map[string]string{
		"NATS_URL": bustest.URL(t), "TS_URL": storetest.Migrated(t, migrate.Timeseries), "AUTHORITY_PUBLIC_URL": "http://" + s.addr,
		"ISSUER_URL": issuerURL, "DP_ADDR": s.addr, "ADMIN_ADDR": "127.0.0.1:0", "DSS_BASE_URL": s.dss.URL(),
		"SOURCE_CONTROL_BUCKET": s.srcBucket, "SOURCE_CONTROL_REREAD_S": "1", "DP_OVERSIGHT_BUCKET": oversight,
		"DP_VIEWS_BUCKET": bustest.Name("dpv"), "DP_VIEWS_REREAD_S": "1", "DP_DISCOVERY_REREAD_S": "1",
		"DP_STATUS_INTERVAL_MS": "200", "DP_UNAVAILABLE_AFTER_S": "2", "DP_CERTIFIED_USSPS": "ussp-lab-01",
		"NATS_START_ATTEMPTS": "1", "SHUTDOWN_TIMEOUT_S": "5", "DP_PROJECTION_REFRESH_S": "1",
	}
	if mutate != nil {
		mutate(env)
	}
	// The oversight area, as api publishes it.
	kv, err := bus.OpenBucket(ctx, js, dpviews.OversightBucketConfig(oversight))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := dpviews.PutOversight(ctx, kv, dpviews.Oversight{Version: 1, Areas: []dpviews.Area{{ID: 1, Label: "base",
		BBox: dpviews.BBox{box.MinLon, box.MinLat, box.MaxLon, box.MaxLat}}}}, 3); err != nil || !ok {
		t.Fatalf("oversight %v %v", ok, err)
	}
	host, _, _ := net.SplitHostPort(s.addr)
	opts := dp.Options{Tokens: s.iss, Verifier: s.iss.verifier(t, host), Engine: func(e *dp.Engine) { s.engine = e }}
	cfg := &config.DPPoller{}
	spec := proc.Spec{Name: "dp-poller", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return dp.Run(ctx, rt, cfg, opts)
	}}
	go func() {
		s.exit <- proc.Main(ctx, spec, nil, s.logs, s.logs, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	}()
	t.Cleanup(s.stop)
	eventually(t, "the engine", 10*time.Second, func() bool { return s.engine != nil })
	return s
}

func (s *dpStack) stop() {
	s.cancel()
	select {
	case code := <-s.exit:
		if code != proc.ExitOK {
			s.t.Errorf("dp-poller exit %d\n%s", code, s.logs.String())
		}
	case <-time.After(15 * time.Second):
		s.t.Error("dp-poller did not stop")
	}
}

func (s *dpStack) status(id string) (dp.StatusBody, bool) {
	v, ok := s.statuses.Load(id)
	if !ok {
		return dp.StatusBody{}, false
	}
	return v.(dp.StatusBody), true
}

func (s *dpStack) provider(id string) *dp.Provider {
	for _, p := range s.engine.Providers() {
		if p.USSID == id {
			return p
		}
	}
	return nil
}

// moving keeps the Service Provider's flight moving one state a second,
// so every poll has a new state to publish.
func moving(ctx context.Context, sp *fakedss.SP, id, serial string, la, lo float64) {
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			now := time.Now()
			sp.SetFlights([]f3411.RIDFlight{ridFlight(id, now, la+float64(i%10)*1e-5, lo)},
				map[string]f3411.RIDFlightDetails{id: {Id: id, UasId: &f3411.UASID{SerialNumber: str(serial)}, OperatorId: str("GEOabcd1234efgh")}})
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// A-M4, 02 F7, E-01: the ISAs of the Service Provider are discovered
// through the DSS for the viewed tile and subscribed with this system's
// uss_base_url; /uss/flights is polled for the view with aud the
// Service Provider's host; its flights are published on trk.v1 as trust
// provider from source network_rid; with details (a tile within 2 km)
// the flight takes the track id of the direct broadcast of the same
// serial, and the position the direct pipeline gives the same frame
// agrees (SC-06 row 3); its rows reach tsdb-writer's subjects; a
// notification posted by the Service Provider is applied, one with
// another host's aud refused; the status says live.
func TestIntegrationDisplayProviderDiscoversPollsAndPublishes(t *testing.T) {
	s := startDP(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now()
	s.dss.PutISA("isa-1", "ussp-lab-01", s.sp.URL(), box, now.Add(-time.Minute), now.Add(time.Hour))
	moving(ctx, s.sp, "fl-1", "TESTA0000000001", lat, lon)

	eventually(t, "flights published as trust provider", 15*time.Second, func() bool { return len(s.tracks.bySource("ussp-lab-01")) >= 3 })
	subs := s.dss.Subscriptions()
	if len(subs) != 1 {
		t.Fatalf("subscriptions %v", subs)
	}
	for _, v := range subs {
		if v[2] != "http://"+s.addr {
			t.Fatalf("subscription uss_base_url %q", v[2])
		}
	}
	spHost := func() string { u, _ := url.Parse(s.sp.URL()); return u.Hostname() }()
	for _, c := range s.sp.Claims() {
		if c.Aud != spHost || c.Scope != string(f3411.ScopeDisplayProvider) || c.Sub != "authority-01" {
			t.Fatalf("SP call %s carried aud %q scope %q sub %q", c.Path, c.Aud, c.Scope, c.Sub)
		}
	}
	if views := s.sp.Views(); len(views) == 0 || views[0] != dp.ViewParam(box) {
		t.Fatalf("views polled %v", views)
	}
	want := rid.AircraftID(odid.IDTypeSerial, "TESTA0000000001")
	var last map[string]any
	eventually(t, "the flight with its serial's track id", 10*time.Second, func() bool {
		ms := s.tracks.bySource("ussp-lab-01")
		last = ms[len(ms)-1]
		return last["body"].(map[string]any)["track_id"] == want
	})
	b := last["body"].(map[string]any)
	if b["trust"] != "provider" || b["source"] != "network_rid" || b["identification"].(map[string]any)["basis"] != "provider" {
		t.Fatalf("track %v", b)
	}

	// SC-06 row 3: the direct broadcast of the same serial at the same
	// position, through the Remote ID pipeline, is the same track.
	pos := b["position"].(map[string]any)
	pla, plo := pos["lat"].(float64), pos["lng"].(float64)
	direct := directTrack(t, "TESTA0000000001", pla, plo)
	if direct.Body.TrackID != b["track_id"] {
		t.Fatalf("direct %s, network %s: two tracks for one serial", direct.Body.TrackID, b["track_id"])
	}
	if dla, dlo := direct.Body.Position.Lat, direct.Body.Position.Lng; abs(dla-pla) > 1e-6 || abs(dlo-plo) > 1e-6 {
		t.Fatalf("positions disagree: direct %v,%v network %v,%v", dla, dlo, pla, plo)
	}

	// The rows towards tsdb-writer.
	eventually(t, "ussp_flights rows on tsw.v1.ussp_flights", 10*time.Second, func() bool {
		st, err := s.js.Stream(ctx, bus.StreamTSW)
		if err != nil {
			return false
		}
		m, err := st.GetLastMsgForSubject(ctx, "tsw.v1.ussp_flights")
		return err == nil && strings.Contains(string(m.Data), `"ussp_id":"ussp-lab-01"`) && strings.Contains(string(m.Data), `"provider_unknown":false`)
	})

	// A notification from the Service Provider: applied; another
	// host's aud: refused.
	subscribers := s.dss.PutISA("isa-2", "ussp-lab-01", s.sp.URL(), box, now.Add(-time.Minute), now.Add(2*time.Hour))
	area, _ := s.dss.ISA("isa-2")
	ext := dp.Volume(box, now, now.Add(2*time.Hour))
	host, _, _ := net.SplitHostPort(s.addr)
	refused, err := fakedss.Notify(ctx, subscribers, "isa-2", &area, &ext, func(string) string {
		return s.iss.issue("ussp-lab-01", "other.example.test", string(f3411.ScopeServiceProvider))
	})
	if err != nil || refused["http://"+s.addr] != 401 {
		t.Fatalf("another host's aud: %v %v", refused, err)
	}
	ok, err := fakedss.Notify(ctx, subscribers, "isa-2", &area, &ext, func(string) string {
		return s.iss.issue("ussp-lab-01", host, string(f3411.ScopeServiceProvider))
	})
	if err != nil || ok["http://"+s.addr] != 204 {
		t.Fatalf("own aud: %v %v", ok, err)
	}
	eventually(t, "the status says live", 5*time.Second, func() bool {
		st, ok := s.status("ussp-lab-01")
		return ok && st.State == dp.StateLive && st.ISAs == 2 && st.Tiles == 1 && !st.ProviderUnknown && st.DSS == dp.DSSOK
	})
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

type trackRecorder struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (r *trackRecorder) Publish(subject string, data []byte) error {
	if strings.HasPrefix(subject, "trk.v1.") {
		r.mu.Lock()
		r.msgs = append(r.msgs, data)
		r.mu.Unlock()
	}
	return nil
}

// directTrack runs a broadcast of serial at (la, lo) through the Remote
// ID pipeline (internal/ridpipe, odid.EncodePack frames) and returns the
// track it publishes.
func directTrack(t *testing.T, serial string, la, lo float64) struct {
	Body struct {
		TrackID  string `json:"track_id"`
		Position struct {
			Lat float64 `json:"lat"`
			Lng float64 `json:"lng"`
		} `json:"position"`
	} `json:"body"`
} {
	t.Helper()
	rec := &trackRecorder{}
	set := ridpipe.DefaultSettings()
	set.Tracker.IdentifyWithinS = rid.IdentifyAtOnceS
	p := ridpipe.New(set, ridpipe.Deps{Publisher: rec})
	frame, err := odid.EncodePack([]odid.Message{
		odid.BasicID{IDType: odid.IDTypeSerial, UAID: serial},
		odid.Location{Status: odid.StatusAirborne, LatDeg: f64(la), LonDeg: f64(lo), AltHAEM: f64(600)},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sum := sha256.Sum256(frame)
	id := sha256.Sum256(fmt.Appendf(nil, "rx-1|TEST-TX|%x", sum))
	row := ridpipe.Row{FrameID: hex.EncodeToString(id[:16]), ReceiverID: "rx-1", Transmitter: "TEST-TX", ReceiverTS: &now,
		Payload: frame, PayloadSHA256: sum[:], Nonce: "n", IngestTS: now}
	if err := p.Observe(context.Background(), &ridpipe.Batch{ID: "rx-1:1", ReceiverID: "rx-1", IngestTS: now, Rows: []ridpipe.Row{row}}); err != nil {
		t.Fatal(err)
	}
	if len(rec.msgs) != 1 {
		t.Fatalf("%d direct tracks", len(rec.msgs))
	}
	var out struct {
		Body struct {
			TrackID  string `json:"track_id"`
			Position struct {
				Lat float64 `json:"lat"`
				Lng float64 `json:"lng"`
			} `json:"position"`
		} `json:"body"`
	}
	if err := json.Unmarshal(rec.msgs[0], &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// switchSource writes the source-control state as api publishes it.
func (s *dpStack) switchSource(t *testing.T, version uint64, ussID string, enabled bool) {
	t.Helper()
	ctx := context.Background()
	inst := ussID
	raw, err := sources.Encode(sources.Document{Epoch: "wp14", Version: version, Controls: []sources.Control{{
		SourceType: dp.SourceType, InstanceID: &inst, Enabled: enabled, Reason: "SC-16", Actor: "admin@example.test",
		ChangedAt: time.Now().UTC(), Version: version,
	}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kv, err := bus.OpenBucket(ctx, s.js, jetstream.KeyValueConfig{Bucket: s.srcBucket, History: bus.BucketHistory, MaxBytes: -1, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, sources.StateKey, raw); err != nil {
		t.Fatal(err)
	}
}

// SC-16: a Service Provider switched off is not polled from that moment
// (its poll count stops) and its status says disabled by whom; switched
// on again it is polled within a second.
func TestIntegrationSC16ProviderSwitchedOffStopsBeingPolled(t *testing.T) {
	s := startDP(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now()
	s.dss.PutISA("isa-1", "ussp-lab-01", s.sp.URL(), box, now.Add(-time.Minute), now.Add(time.Hour))
	moving(ctx, s.sp, "fl-1", "TESTA0000000001", lat, lon)
	eventually(t, "polled", 15*time.Second, func() bool { n, _ := s.sp.Counts(); return n >= 3 })

	s.switchSource(t, 1, "ussp-lab-01", false)
	var stopped int
	eventually(t, "polling stopped", 3*time.Second, func() bool {
		a, _ := s.sp.Counts()
		time.Sleep(1200 * time.Millisecond)
		b, _ := s.sp.Counts()
		stopped = b
		return a == b
	})
	time.Sleep(2 * time.Second)
	if n, _ := s.sp.Counts(); n != stopped {
		t.Fatalf("polled %d more times while disabled", n-stopped)
	}
	eventually(t, "status disabled by whom", 3*time.Second, func() bool {
		st, ok := s.status("ussp-lab-01")
		return ok && st.State == dp.StateDisabled && st.DisabledByWho != nil && *st.DisabledByWho == "admin@example.test"
	})

	switched := time.Now()
	s.switchSource(t, 2, "ussp-lab-01", true)
	eventually(t, "polling resumed", 3*time.Second, func() bool { n, _ := s.sp.Counts(); return n > stopped })
	if took := time.Since(switched); took > 2*time.Second {
		// Within 1 s of the follower taking the switch; the KV watch
		// adds its own delivery time.
		t.Fatalf("resumed after %v", took)
	}
}

// R-14, E-02: a 413 splits the tile and the quarters are polled; a
// Service Provider slower than 3 s is slow and polled at 0.5 Hz; one
// that is down is unavailable since T while the other Service Provider's
// flights keep being published; the DSS down leaves the known ISAs in
// use, and the status says dss_unavailable.
func TestIntegrationLimitsAndFailures(t *testing.T) {
	s := startDP(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	now := time.Now()
	s.dss.PutISA("isa-1", "ussp-lab-01", s.sp.URL(), box, now.Add(-time.Minute), now.Add(time.Hour))
	s.dss.PutISA("isa-9", "ussp-two-01", s.sp2.URL(), box, now.Add(-time.Minute), now.Add(time.Hour))
	moving(ctx, s.sp, "fl-1", "TESTA0000000001", lat, lon)
	moving(ctx, s.sp2, "fl-2", "TESTA0000000002", lat+0.001, lon)
	eventually(t, "both providers published", 15*time.Second, func() bool {
		return len(s.tracks.bySource("ussp-lab-01")) > 0 && len(s.tracks.bySource("ussp-two-01")) > 0
	})
	if st, ok := s.status("ussp-two-01"); ok && !st.ProviderUnknown {
		t.Fatal("an uncertified provider is not shown provider_unknown")
	}

	// 413: the tile is split and its quarters are polled.
	s.sp.SetStatus(413)
	eventually(t, "split after 413", 5*time.Second, func() bool { p := s.provider("ussp-lab-01"); return p != nil && p.IsSplit(dp.Tile{Box: box}.Key()) })
	s.sp.SetStatus(0)
	quarter := dp.ViewParam(dp.Tile{Box: box}.Split4()[0].Box)
	eventually(t, "a quarter polled", 5*time.Second, func() bool {
		for _, v := range s.sp.Views() {
			if v == quarter {
				return true
			}
		}
		return false
	})

	// Slow: past the F3411 p99 the provider is slow.
	s.sp.SetDelay(3200 * time.Millisecond)
	eventually(t, "slow", 15*time.Second, func() bool { st, ok := s.status("ussp-lab-01"); return ok && st.Slow && st.P99S > 3 })
	s.sp.SetDelay(0)

	// Down: unavailable since T, never removed; the other provider goes on.
	s.sp.SetDown(true)
	eventually(t, "unavailable since", 15*time.Second, func() bool {
		st, ok := s.status("ussp-lab-01")
		return ok && st.State == dp.StateDown && st.UnavailableSince != nil
	})
	before := len(s.tracks.bySource("ussp-two-01"))
	eventually(t, "the other provider still published", 5*time.Second, func() bool { return len(s.tracks.bySource("ussp-two-01")) > before })
	if s.provider("ussp-lab-01") == nil {
		t.Fatal("the unavailable provider was removed")
	}
	s.sp.SetDown(false)

	// The DSS down: the known ISAs stay in use and the status says so.
	s.dss.SetDown(true)
	eventually(t, "dss_unavailable", 10*time.Second, func() bool {
		st, ok := s.status("ussp-two-01")
		return ok && st.DSS == dp.DSSUnavailable && st.DSSSince != nil
	})
	before = len(s.tracks.bySource("ussp-two-01"))
	eventually(t, "polled with the DSS down", 5*time.Second, func() bool { return len(s.tracks.bySource("ussp-two-01")) > before })
	s.dss.SetDown(false)
}

// E-02: started with no DSS and no client secret, dp-poller starts,
// serves, says why nothing is discovered, and its notification route
// refuses without a token.
func TestIntegrationStartWithoutDSSSaysSo(t *testing.T) {
	bustest.Connect(t)
	logs := &syncBuf{}
	addr := freeAddr(t)
	env := map[string]string{
		"NATS_URL": bustest.URL(t), "TS_URL": storetest.Migrated(t, migrate.Timeseries), "AUTHORITY_PUBLIC_URL": "http://" + addr,
		"DP_ADDR": addr, "ADMIN_ADDR": "127.0.0.1:0", "SOURCE_CONTROL_BUCKET": bustest.Name("src"), "NATS_START_ATTEMPTS": "1",
		"DP_OVERSIGHT_BUCKET": bustest.Name("dpo"), "DP_VIEWS_BUCKET": bustest.Name("dpv"), "SHUTDOWN_TIMEOUT_S": "5",
	}
	cfg := &config.DPPoller{}
	iss := newIssuer(t)
	spec := proc.Spec{Name: "dp-poller", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return dp.Run(ctx, rt, cfg, dp.Options{Verifier: iss.verifier(t, "127.0.0.1")})
	}}
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() {
		exit <- proc.Main(ctx, spec, nil, logs, logs, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	}()
	eventually(t, "the start says why nothing is discovered", 10*time.Second, func() bool {
		l := logs.String()
		return strings.Contains(l, "no DSS: no identification service area is discovered") && strings.Contains(l, "no client secret") &&
			strings.Contains(l, "public listener open")
	})
	cancel()
	if code := <-exit; code != proc.ExitOK {
		t.Fatalf("exit %d\n%s", code, logs.String())
	}
}
