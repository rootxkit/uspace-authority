package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/picture"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// fixedProjection is a registry projection answering one read.
type fixedProjection struct{ l registry.Loaded }

func (f fixedProjection) LoadProjection(context.Context) (registry.Loaded, error) { return f.l, nil }

// constGeoid has one undulation everywhere (WP-11's grid stands aside;
// the subtraction is core's).
type constGeoid struct{ n float64 }

func (g constGeoid) UndulationM(core.LatLon) (float64, error) { return g.n, nil }

func odidFrame(t *testing.T, m odid.Message) []byte {
	t.Helper()
	b, err := odid.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return b[:]
}

// A-M2 (SC-06 rows 1, 2, 3 and 5 as the authority sees them, WP-8's
// scenario): four transmitters at once through WP-8's Remote ID pipeline
// publishing on the real bus, and a console of picture-ws sees four
// tracks, one per identification status (registered, suspended,
// unknown_operator, unidentified), each with trust broadcast and basis
// as_broadcast ("as broadcast and unverified", R-05), with its age and
// its source's state.
func TestIntegrationSC06FourIdentificationStatusesOnThePicture(t *testing.T) {
	nc, _ := connectNATS(t)
	api := newSessionAPI(t)
	p := startPicture(t, api, natsURL(t), nil)
	c := dialConsole(t, p.ws, api.session(t, "sc06"), 0)
	c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)

	owner := "00000000-0000-0000-0000-0000000000a1"
	reader := &registry.ProjectionReader{Source: fixedProjection{registry.Loaded{Version: 1,
		Operators: []identify.OperatorFacts{{OperatorID: owner, RegistrationNumber: "GEOTEST00000001", Status: identify.StatusActive}},
		UAS: []identify.UASFacts{
			{DroneID: "uas-reg", Serial: "TESTREG0001", RegistrationStatus: identify.StatusActive, OperatorID: &owner, InRegistry: true},
			{DroneID: "uas-sus", Serial: "TESTSUS0002", RegistrationStatus: identify.StatusSuspended, OperatorID: &owner, InRegistry: true},
			{DroneID: "uas-unk", Serial: "TESTUNK0003", RegistrationStatus: identify.StatusActive, OperatorID: &owner, InRegistry: true},
		}}}}
	if err := reader.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now().Add(-10 * time.Second).Truncate(time.Second)
	clock := t0
	pipe := ridpipe.New(ridpipe.DefaultSettings(), ridpipe.Deps{
		Registry: reader.Lookup, Geoid: constGeoid{15.9}, Publisher: nc,
		Limiter: logging.NewLimiter(logging.Discard(), time.Minute, 0, nil), Now: func() time.Time { return clock },
	})
	type transmitter struct{ addr, serial, operator string }
	txs := []transmitter{
		{"AA:BB:CC:00:06:01", "TESTREG0001", "GEOTEST00000001-x9z"},
		{"AA:BB:CC:00:06:02", "TESTSUS0002", "GEOTEST00000001"},
		{"AA:BB:CC:00:06:03", "TESTUNK0003", "GEOTEST00000099"},
		{"AA:BB:CC:00:06:05", "", ""},
	}
	for s := range 10 {
		for i, tx := range txs {
			now := t0.Add(time.Duration(s)*time.Second + time.Duration(i)*10*time.Millisecond)
			clock = now
			var msgs []odid.Message
			if s%3 == 0 && tx.serial != "" {
				msgs = append(msgs, odid.BasicID{IDType: odid.IDTypeSerial, UAID: tx.serial}, odid.OperatorID{OperatorID: tx.operator})
			}
			lat, lon, hae, baro := latDeg, lonDeg+float64(i%3)*1e-3, 520.0, 507.5
			speed, dir, vs := 10.0, 90.0, 1.5
			tenths := float64(now.Sub(now.Truncate(time.Hour))/(100*time.Millisecond)) / 10
			msgs = append(msgs, odid.Location{Status: odid.StatusAirborne, LatDeg: &lat, LonDeg: &lon, AltHAEM: &hae, AltBaroM: &baro,
				VertAccuracy: 4, SpeedHorizontalMS: &speed, DirectionDeg: &dir, SpeedVerticalMS: &vs, SecondsAfterHour: &tenths})
			var rows []ridpipe.Row
			for _, m := range msgs {
				payload := odidFrame(t, m)
				sum := sha256.Sum256(payload)
				heard := now
				mt := int(payload[0] >> 4)
				rows = append(rows, ridpipe.Row{
					FrameID: hex.EncodeToString(sum[:8]) + fmt.Sprint(now.UnixNano()), ReceiverID: "rx-sc06", Transmitter: tx.addr,
					ReceiverTS: &heard, MsgType: &mt, Payload: payload, PayloadSHA256: sum[:], Nonce: "n", IngestTS: now,
				})
			}
			b := &ridpipe.Batch{ID: fmt.Sprintf("rx-sc06:%d", now.UnixNano()), ReceiverID: "rx-sc06", IngestTS: now, Rows: rows}
			if err := pipe.Observe(context.Background(), b); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	want := map[string]core.IdentStatus{
		rid.AircraftID(odid.IDTypeSerial, "TESTREG0001"): core.IdentRegistered,
		rid.AircraftID(odid.IDTypeSerial, "TESTSUS0002"): core.IdentSuspended,
		rid.AircraftID(odid.IDTypeSerial, "TESTUNK0003"): core.IdentUnknownOperator,
		rid.UnidentifiedID("AA:BB:CC:00:06:05"):          core.IdentUnidentified,
	}
	c.subscribe(t, 44.80, 41.70, 44.85, 41.73)
	snap := snapshotBody(t, c.until(t, picture.SchemaSnapshot, 5*time.Second, nil))
	seen := map[string]core.IdentStatus{}
	for _, raw := range snap.Tracks {
		tb := trackOf(t, raw)
		w, ok := want[tb.TrackID]
		if !ok {
			continue
		}
		id := tb.Identification
		if id.Status != w || tb.Trust != core.TrustBroadcast || id.Basis != core.BasisAsBroadcast || tb.SourceState == "" {
			t.Fatalf("%s: %s trust %s basis %s source_state %q", tb.TrackID, id.Status, tb.Trust, id.Basis, tb.SourceState)
		}
		seen[tb.TrackID] = id.Status
		t.Logf("%s: %s (%s), trust %s, basis %s, age %.1f s, source %s", tb.TrackID, id.Status, id.Reason, tb.Trust, id.Basis, tb.AgeS, tb.SourceState)
	}
	if len(seen) != 4 {
		t.Fatalf("the picture shows %v, want the four statuses", seen)
	}
}
