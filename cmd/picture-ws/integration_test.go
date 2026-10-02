package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/picture"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// Tbilisi.
const (
	latDeg = 41.7151
	lonDeg = 44.8271
)

// violationEnvelope is detect's violation/v1 message at at.
func violationEnvelope(t *testing.T, id string, state violation.State, at time.Time) bus.Envelope[violation.Body] {
	t.Helper()
	c5, err := cell.Of(core.LatLon{LatDeg: latDeg, LonDeg: lonDeg}, cell.Level5)
	if err != nil {
		t.Fatal(err)
	}
	b := violation.Body{
		ViolationID: id, Kind: violation.KindZoneIncursion, State: state, Severity: core.SeverityWarning, AlertKey: "zone:" + id,
		TrackRef: "trk-int", CapturedAt: bus.Stamp(at), OpenedAt: bus.Stamp(at), PolicyVersion: 1, Detail: map[string]any{},
		EvidenceTrust: core.TrustBroadcast, EvidenceRefs: []violation.EvidenceRef{}, EvidenceExcerpt: []violation.Sample{}, Cell5: c5.String(),
	}
	env := bus.Envelope[violation.Body]{Schema: violation.Schema, MsgID: bus.NewULID(at), Producer: violation.Producer,
		TS: bus.Stamp(at), RxTS: bus.Stamp(at), CapturedAt: bus.Stamp(at), TimeSource: "system", Body: b}
	if err := violation.Validate(&env); err != nil {
		t.Fatal(err)
	}
	return env
}

// The picture through the process against NATS and TimescaleDB: a
// violation raised before picture-ws started is replayed from ALRT to a
// console that connects later (C-08); two consoles with overlapping
// viewports receive a track once each; a source switched off reads
// "disabled by <who>" within one status interval (B-11, SC-08); the
// status frame carries the extras and the projection reads.
func TestIntegrationPictureReplayFanOutAndSources(t *testing.T) {
	nc, js := connectNATS(t)
	ensureALRT(t, js)
	now := time.Now()
	vid := bus.NewULID(now)
	ctx := context.Background()
	if _, err := bus.PublishJS(ctx, js, mustSubject(t, vid), violationEnvelope(t, vid, violation.StateRaised, now)); err != nil {
		t.Fatal(err)
	}
	api := newSessionAPI(t)
	bucket, subject := "sc_"+fmt.Sprint(time.Now().UnixNano()), "ctl.sources.test"+fmt.Sprint(time.Now().UnixNano())
	p := startPicture(t, api, natsURL(t), func(m map[string]string) {
		m["SOURCE_CONTROL_BUCKET"], m["SOURCE_CONTROL_SUBJECT"] = bucket, subject
	})
	p.out.waitFor(t, "active violations read back from ALRT")

	a := dialConsole(t, p.ws, api.session(t, "int-a"), 0)
	b := dialConsole(t, p.ws, api.session(t, "int-b"), 0)
	for _, c := range []*console{a, b} {
		st := statusBody(t, c.until(t, picture.SchemaStatus, 5*time.Second, nil))
		if !has(st.Degraded, picture.DegradedNoSubscription) || st.NATS != picture.NATSConnected {
			t.Fatalf("first status %+v", st)
		}
		c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
	}
	a.subscribe(t, 44.78, 41.69, 44.84, 41.73)
	b.subscribe(t, 44.81, 41.70, 44.88, 41.75)
	snap := snapshotBody(t, a.until(t, picture.SchemaSnapshot, 5*time.Second, nil))
	found := false
	for _, raw := range snap.Alerts {
		var v violation.Message
		if json.Unmarshal(raw, &v) == nil && v.Body.ViolationID == vid {
			found = true
		}
	}
	if !found {
		t.Fatalf("the violation raised before the start is not replayed: %d alerts", len(snap.Alerts))
	}
	b.until(t, picture.SchemaSnapshot, 5*time.Second, nil)

	publishTrack(t, nc, "int-overlap", latDeg, lonDeg, time.Now())
	for name, c := range map[string]*console{"a": a, "b": b} {
		e := c.until(t, picture.SchemaTrack, 5*time.Second, nil)
		raw, _ := json.Marshal(e)
		if tb := trackOf(t, raw); tb.TrackID != "int-overlap" {
			t.Fatalf("%s: track %s", name, tb.TrackID)
		}
		deadline := time.After(time.Second)
	more:
		for {
			select {
			case f := <-c.frames:
				var e envelope
				_ = json.Unmarshal(f, &e)
				if e.Schema == picture.SchemaTrack {
					t.Fatalf("%s received the track twice", name)
				}
			case <-deadline:
				break more
			}
		}
	}

	// The switch, written as api writes it (KV + push), by a person.
	inst := "rx-int-1"
	doc := sources.Document{Epoch: "e1", Version: 1, Controls: []sources.Control{{
		SourceType: sources.TypeDirectRID, InstanceID: &inst, Enabled: false, Reason: "maintenance", Actor: "admin:n.beridze",
		ChangedAt: time.Now().UTC(), Version: 1,
	}}}
	raw, err := sources.Encode(doc, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, mustBucket(t, bucket))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	switched := time.Now()
	if _, err := kv.Put(ctx, sources.StateKey, raw); err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish(subject, raw); err != nil {
		t.Fatal(err)
	}
	e := a.until(t, picture.SchemaSource, 5*time.Second, func(e envelope) bool {
		var s picture.SourceState
		return json.Unmarshal(e.Body, &s) == nil && s.SourceInstance != nil && *s.SourceInstance == inst && s.State == picture.StateDisabled
	})
	var s picture.SourceState
	_ = json.Unmarshal(e.Body, &s)
	if s.DisabledByWho == nil || *s.DisabledByWho != "admin:n.beridze" || s.DisabledBy == nil || *s.DisabledBy != "instance" {
		t.Fatalf("source %+v", s)
	}
	if took := time.Since(switched); took > 2*time.Second {
		t.Fatalf("disabled by <who> after %s, more than one status interval and the re-read", took)
	}
	t.Logf("source disabled by %s announced %s after the switch", *s.DisabledByWho, time.Since(switched).Round(time.Millisecond))

	// GET /v1/picture/sources and the projection reads.
	req, _ := http.NewRequest(http.MethodGet, p.base+"/v1/picture/sources", nil)
	req.Header.Set("Authorization", "Bearer "+api.session(t, "int-c"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		Sources []picture.SourceState `json:"sources"`
		NATS    string                `json:"nats"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || resp.StatusCode != http.StatusOK || body.NATS != picture.NATSConnected {
		t.Fatalf("sources: %d %v %+v", resp.StatusCode, err, body)
	}
	st := statusBody(t, a.until(t, picture.SchemaStatus, 5*time.Second, func(e envelope) bool {
		var b picture.StatusBody
		return json.Unmarshal(e.Body, &b) == nil && b.DegradedSince != nil
	}))
	if has(st.Degraded, picture.DegradedProjections) || !has(st.Degraded, picture.DegradedRegistryAbsent) {
		t.Fatalf("an empty scratch projection: degraded %v", st.Degraded)
	}
}

func mustSubject(t *testing.T, id string) string {
	t.Helper()
	c5, _ := cell.Of(core.LatLon{LatDeg: latDeg, LonDeg: lonDeg}, cell.Level5)
	s, err := bus.Subjects.Alrt(string(violation.KindZoneIncursion), cell.Token(c5), id)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustBucket(t *testing.T, name string) jetstream.KeyValueConfig {
	t.Helper()
	cfg, ok := bus.NewTopology(bus.Limits{SourceControlBucket: name}).Bucket(name)
	if !ok {
		t.Fatal("no bucket config")
	}
	return cfg
}

// E-02, 05 §5: the bus lost while consoles watch. Within 5 s every
// console is told nats_unavailable with since when, and nothing leaves
// the picture: a re-subscription's snapshot still holds the track,
// ageing. The bus back, the status says connected again.
func TestIntegrationBusOutageReportedWithinSecondsAndNothingDisappears(t *testing.T) {
	nc, _ := connectNATS(t)
	api := newSessionAPI(t)
	px := newProxy(t, natsHostPort(t, natsURL(t)))
	p := startPicture(t, api, "nats://"+px.addr, nil)
	c := dialConsole(t, p.ws, api.session(t, "outage"), 0)
	c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
	c.subscribe(t, 44.80, 41.70, 44.85, 41.73)
	c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
	publishTrack(t, nc, "int-outage", latDeg, lonDeg, time.Now())
	c.until(t, picture.SchemaTrack, 5*time.Second, nil)

	lost := time.Now()
	px.cut()
	e := c.until(t, picture.SchemaStatus, 5*time.Second, func(e envelope) bool {
		var b picture.StatusBody
		return json.Unmarshal(e.Body, &b) == nil && b.NATS == picture.NATSUnavailable
	})
	st := statusBody(t, e)
	took := time.Since(lost)
	if !has(st.Degraded, picture.DegradedNATS) || st.NATSSince == nil || st.DegradedSince[picture.DegradedNATS] == "" {
		t.Fatalf("outage status %+v", st)
	}
	t.Logf("nats_unavailable since %s reported %s after the bus was cut", *st.NATSSince, took.Round(time.Millisecond))
	if took > 5*time.Second {
		t.Fatalf("reported after %s", took)
	}
	c.subscribe(t, 44.80, 41.70, 44.85, 41.73)
	snap := snapshotBody(t, c.until(t, picture.SchemaSnapshot, 5*time.Second, nil))
	if len(snap.Tracks) != 1 || trackOf(t, snap.Tracks[0]).TrackID != "int-outage" {
		t.Fatalf("snapshot during the outage holds %d tracks", len(snap.Tracks))
	}

	px.restore(t)
	c.until(t, picture.SchemaStatus, 15*time.Second, func(e envelope) bool {
		var b picture.StatusBody
		return json.Unmarshal(e.Body, &b) == nil && b.NATS == picture.NATSConnected && !has(b.Degraded, picture.DegradedNATS)
	})
}

// E-02: started with the bus and the database unreachable, picture-ws
// serves and says so; nothing is shown as an empty sky.
func TestIntegrationStartsWithoutBusOrDatabase(t *testing.T) {
	natsURL(t)
	api := newSessionAPI(t)
	p := startPicture(t, api, "nats://127.0.0.1:1", func(m map[string]string) {
		m["TS_URL"] = "postgres://nobody:nothing@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"
	})
	c := dialConsole(t, p.ws, api.session(t, "nobus"), 0)
	st := statusBody(t, c.until(t, picture.SchemaStatus, 10*time.Second, func(e envelope) bool {
		var b picture.StatusBody
		return json.Unmarshal(e.Body, &b) == nil && has(b.Degraded, picture.DegradedNATS) && has(b.Degraded, picture.DegradedProjections)
	}))
	if st.NATS != picture.NATSUnavailable || st.ProjectionAgeS != nil {
		t.Fatalf("status %+v", st)
	}
}

// 05 §5: a 5000 msg/s flood for two seconds against a console that reads
// slowly: its dropped_frames rises, it stays connected and keeps
// receiving its status.
func TestIntegrationFloodRaisesDroppedFramesAndTheConsoleStays(t *testing.T) {
	nc, _ := connectNATS(t)
	api := newSessionAPI(t)
	p := startPicture(t, api, natsURL(t), func(m map[string]string) { m["PICTURE_SEND_BUFFER"] = "64" })
	c := dialConsole(t, p.ws, api.session(t, "flood"), 200*time.Microsecond)
	c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
	c.subscribe(t, 44.80, 41.70, 44.85, 41.73)
	c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
	start := time.Now()
	sent := 0
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for time.Since(start) < 2*time.Second {
		<-tick.C
		for i := range 50 {
			publishTrack(t, nc, fmt.Sprintf("flood-%02d", i), latDeg+float64(i)*1e-4, lonDeg, time.Now())
			sent++
		}
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	rate := float64(sent) / time.Since(start).Seconds()
	st := statusBody(t, c.until(t, picture.SchemaStatus, 30*time.Second, func(e envelope) bool {
		var b picture.StatusBody
		return json.Unmarshal(e.Body, &b) == nil && b.DroppedFrames > 0
	}))
	t.Logf("flood: %d messages at %.0f msg/s, dropped_frames %d, the console still connected", sent, rate, st.DroppedFrames)
	if rate < 4000 {
		t.Logf("the flood ran at %.0f msg/s on this machine", rate)
	}
	select {
	case err := <-c.errc:
		t.Fatalf("the console was closed: %v", err)
	default:
	}
}
