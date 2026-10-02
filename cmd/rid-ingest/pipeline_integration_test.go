package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers/ingest"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/tswriter"
)

// constGeoid stands in for WP-11's grid: one undulation everywhere (the
// subtraction is uspace-core's).
type constGeoid struct{ n float64 }

func (g constGeoid) UndulationM(core.LatLon) (float64, error) { return g.n, nil }

// startWriter runs tsdb-writer (WP-9) in this test against tsURL.
func startWriter(t *testing.T, tsURL string) {
	t.Helper()
	m := map[string]string{
		"NATS_URL": natsURL(t), "TS_URL": tsURL, "ADMIN_ADDR": "127.0.0.1:0", "STATUS_INTERVAL_S": "1",
		"SHUTDOWN_TIMEOUT_S": "10", "TSDB_WRITER_RETRY_MAX_MS": "500",
	}
	out := &lines{}
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	cfg := &config.TSDBWriter{}
	spec := proc.Spec{Name: "tsdb-writer", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return tswriter.Run(ctx, rt, cfg, tswriter.Options{DatabaseRetry: 200 * time.Millisecond})
	}}
	go func() {
		exit <- proc.Main(ctx, spec, nil, out, io.Discard, func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-exit:
			if code != proc.ExitOK {
				t.Errorf("tsdb-writer exit %d:\n%s", code, out.tail(40))
			}
		case <-time.After(30 * time.Second):
			t.Error("tsdb-writer did not stop")
		}
	})
	out.waitFor(t, "tsdb-writer consuming", nil)
}

// collector keeps the core NATS messages of a subject.
type collector struct {
	mu   sync.Mutex
	msgs []*nats.Msg
}

func collect(t *testing.T, nc *nats.Conn, subject string) *collector {
	t.Helper()
	c := &collector{}
	sub, err := nc.Subscribe(subject, func(m *nats.Msg) {
		c.mu.Lock()
		c.msgs = append(c.msgs, m)
		c.mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return c
}

func (c *collector) all() []*nats.Msg {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*nats.Msg(nil), c.msgs...)
}

func encode(t *testing.T, msgs ...odid.Message) string {
	t.Helper()
	if len(msgs) == 1 {
		b, err := odid.Encode(msgs[0])
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b[:])
	}
	b, err := odid.EncodePack(msgs)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func ptr(v float64) *float64 { return &v }

// WP-8 done-when: a simulated receiver's frames for three aircraft appear
// as trk.v1 messages with the right ids, altitudes, times and
// identification, ident.v1 announces each identification once, and the
// tracks rows and the decoded rid_observations columns are written
// through tsdb-writer (WP-9). The aircraft: A registered, geodetic
// altitude through the geoid; B broadcasting another operator's number
// with a poor geodetic fix (pressure altitude, mismatch); C a transmitter
// without a Basic ID (unidentified after 4 s).
func TestIntegrationThreeAircraftBecomeTracksAndRows(t *testing.T) {
	h := newHarness(t)
	r := newTestRx(t, "rx-int-wp8")
	h.put(r.entry)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	db := storetest.Open(t, tsURL)
	for _, q := range []string{
		`INSERT INTO proj_registry_operators VALUES ('op-1', 'GEOTEST00000001', 'active', now(), 1)`,
		`INSERT INTO proj_registry_uas VALUES ('uas-a', 'a', 'TESTREG0001', 'testreg0001', 'active', 'op-1', true, now(), 1)`,
		`INSERT INTO proj_registry_uas VALUES ('uas-b', 'b', 'TESTUNK0003', 'testunk0003', 'active', 'op-1', true, now(), 1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	startWriter(t, tsURL)
	trk := collect(t, h.nc, "trk.v1.>")
	idents := collect(t, h.nc, "ident.v1.>")
	h.start(map[string]string{"TS_URL": tsURL}, ingest.Options{Geoid: constGeoid{15.9}})
	h.stdout.waitFor(t, "registry projection loaded: Remote ID tracks are identified against it", nil)

	const txA, txB, txC = "AA:BB:CC:08:00:01", "AA:BB:CC:08:00:02", "AA:BB:CC:08:00:03"
	sent := map[string]time.Time{} // broadcast time (tenths) by the track it should carry
	for s := range 7 {
		heard := time.Now().UTC()
		sah := float64(heard.Sub(heard.Truncate(time.Hour))/(100*time.Millisecond)) / 10
		locAt := func(lat float64, code uint8) odid.Location {
			return odid.Location{Status: odid.StatusAirborne, LatDeg: ptr(lat), LonDeg: ptr(44.8271), AltHAEM: ptr(520), AltBaroM: ptr(507.5),
				VertAccuracy: code, SpeedHorizontalMS: ptr(10), DirectionDeg: ptr(90), SecondsAfterHour: &sah}
		}
		obs := func(tx, payload string) string {
			return fmt.Sprintf(`{"transmitter":%q,"payload_hex":%q,"rssi_dbm":-70,"rx_ts":%q}`, tx, payload, heard.Format("2006-01-02T15:04:05.000Z"))
		}
		code, a, _ := h.post(r, fmt.Sprintf("wp8-%d", s),
			obs(txA, encode(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTREG0001"}, locAt(41.7151, 4), odid.OperatorID{OperatorID: "GEOTEST00000001"})),
			obs(txB, encode(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTUNK0003"}, locAt(41.7251, 1), odid.OperatorID{OperatorID: "GEOTEST00000099"})),
			obs(txC, encode(t, locAt(41.7351, 4))))
		if code != http.StatusAccepted || a.Accepted != 3 {
			t.Fatalf("batch %d: %d %+v", s, code, a)
		}
		sent[fmt.Sprint(s)] = heard.Truncate(100 * time.Millisecond)
		time.Sleep(time.Second)
	}

	idA, idB, idC := rid.AircraftID(odid.IDTypeSerial, "TESTREG0001"), rid.AircraftID(odid.IDTypeSerial, "TESTUNK0003"), rid.UnidentifiedID(txC)
	byID := map[string][]track.Message{}
	waitUntil(t, 15*time.Second, func() bool {
		byID = map[string][]track.Message{}
		for _, m := range trk.all() {
			var tm track.Message
			if err := json.Unmarshal(m.Data, &tm); err != nil {
				t.Fatal(err)
			}
			if err := tm.Validate(); err != nil {
				t.Fatalf("invalid track on %s: %v", m.Subject, err)
			}
			if want, _ := track.SubjectOf(&tm); want != m.Subject {
				t.Fatalf("track on %s, want %s", m.Subject, want)
			}
			byID[tm.Body.TrackID] = append(byID[tm.Body.TrackID], tm)
		}
		return len(byID[idA]) == 7 && len(byID[idB]) == 7 && len(byID[idC]) > 0
	})
	if len(byID) != 3 {
		t.Fatalf("track ids %v", len(byID))
	}
	for _, m := range byID[idA] {
		b := m.Body
		if b.AltAMSLM == nil || math.Abs(*b.AltAMSLM-(520-15.9)) > 1e-9 || b.AltSource != core.AltGeodetic ||
			b.Identification.Status != core.IdentRegistered || b.Identification.Reason != core.ReasonMatched ||
			b.Trust != core.TrustBroadcast || b.Source != track.SourceDirectRID || b.SourceInstance != r.id || m.TimeSource != core.TimeBroadcast {
			t.Fatalf("A: %+v", m)
		}
	}
	for _, m := range byID[idB] {
		b := m.Body
		if b.AltAMSLM != nil || b.AltSource != core.AltPressure || b.AltPressureM == nil || *b.AltPressureM != 507.5 ||
			b.Identification.Reason != core.ReasonOperatorMismatch || !b.Identification.Mismatch ||
			b.Identification.RegisteredOperatorReg == nil || *b.Identification.RegisteredOperatorReg != "GEOTEST00000001" {
			t.Fatalf("B: %+v", m)
		}
	}
	for _, m := range byID[idC] {
		if m.Body.Identification.Status != core.IdentUnidentified || m.Body.Identification.Reason != core.ReasonNoSerial {
			t.Fatalf("C: %+v", m)
		}
	}
	// Times: every observation placed at its broadcast time, one of the
	// tenths the receiver's frames carried.
	stamps := map[string]bool{}
	for _, at := range sent {
		stamps[at.Format("2006-01-02T15:04:05.000Z")] = true
	}
	for _, m := range append(byID[idA], byID[idB]...) {
		if !stamps[m.CapturedAt] || m.TS == nil || *m.TS != m.CapturedAt {
			t.Fatalf("captured_at %s (ts %v) is not a broadcast time sent %v", m.CapturedAt, m.TS, stamps)
		}
	}
	ann := map[string]int{}
	for _, m := range idents.all() {
		ann[strings.TrimPrefix(m.Subject, "ident.v1.")]++
	}
	if ann[idA] != 1 || ann[idB] != 1 || ann[idC] != 1 || len(ann) != 3 {
		t.Fatalf("ident.v1 announcements %v", ann)
	}

	// Through tsdb-writer: one tracks row per published track, and the
	// raw rows with their decoded columns.
	published := len(byID[idA]) + len(byID[idB]) + len(byID[idC])
	count := func(q string, args ...any) int {
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	waitUntil(t, 20*time.Second, func() bool { return count(`SELECT count(*) FROM tracks`) >= published })
	if n := count(`SELECT count(*) FROM tracks`); n != published {
		t.Fatalf("%d tracks rows, %d published", n, published)
	}
	if count(`SELECT count(*) FROM tracks WHERE track_id = $1 AND ident_status = 'registered' AND alt_source = 'geodetic' AND alt_amsl_m IS NOT NULL`, idA) != 7 ||
		count(`SELECT count(*) FROM tracks WHERE track_id = $1 AND ident_mismatch AND alt_source = 'pressure' AND alt_amsl_m IS NULL AND alt_pressure_m = 507.5`, idB) != 7 ||
		count(`SELECT count(*) FROM tracks WHERE track_id = $1 AND ident_status = 'unidentified'`, idC) != len(byID[idC]) {
		t.Fatal("tracks rows do not hold what was published")
	}
	waitUntil(t, 20*time.Second, func() bool { return count(`SELECT count(*) FROM rid_observations`) == 21 })
	if count(`SELECT count(*) FROM rid_observations WHERE captured_at IS NULL OR time_source IS NULL`) != 0 ||
		count(`SELECT count(*) FROM rid_observations WHERE serial = 'TESTREG0001' AND operator_reg = 'GEOTEST00000001' AND id_type = 1 AND lat_deg IS NOT NULL`) != 7 ||
		count(`SELECT count(*) FROM rid_observations WHERE transmitter = $1 AND serial IS NULL AND alt_wgs84_m = 520 AND status = 'Airborne'`, txC) != 7 {
		t.Fatal("rid_observations rows lack their decoded columns")
	}
	t.Logf("three aircraft: %d, %d and %d tracks published and stored; ident.v1 %v", len(byID[idA]), len(byID[idB]), len(byID[idC]), ann)
}
