package ingest

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/receivers"
)

var ulidPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func TestNewULIDMatchesTheEnvelopeSchema(t *testing.T) {
	now := time.Now()
	a, b := NewULID(now), NewULID(now)
	if !ulidPattern.MatchString(a) || a == b {
		t.Fatalf("%s %s", a, b)
	}
	if NewULID(time.UnixMilli(0))[:10] != "0000000000" {
		t.Fatal("the time is not in the first ten digits")
	}
}

// B-11, B-03: a receiver never heard is unknown; heard now, live; silent
// past the bound, stale with silent since; disabled by the registry says
// by whom; disabled by source control says how; replaying old backlog,
// lagging with lag_s.
func TestStatusStates(t *testing.T) {
	h := cheapHasher(t)
	r1, r2 := newRx(t, h, "rx-1", nil), newRx(t, h, "rx-2", nil)
	f := newFixture(t, r1, r2)
	s := f.status
	now := f.now
	if b := s.Snapshot("rx-1", now); b.State != "unknown" || b.AgeS != nil || b.DisabledBy != nil {
		t.Fatalf("never heard: %+v", b)
	}
	s.Accepted("rx-1", &Batch{}, 3, 1)
	s.Refused("rx-1", receivers.ReasonSkew)
	b := s.Snapshot("rx-1", now.Add(time.Second))
	if b.State != "live" || *b.AgeS != 1 || b.Counters["accepted"] != 3 || b.Counters["refused"] != 1 ||
		b.Counters[receivers.ReasonSkew] != 1 || b.Counters["duplicates"] != 1 {
		t.Fatalf("live: %+v", b)
	}
	b = s.Snapshot("rx-1", now.Add(20*time.Second))
	if b.State != "stale" || b.SilentSince == nil || *b.SilentSince != stamp(now) {
		t.Fatalf("stale: %+v", b)
	}
	e := r1.entry
	e.Status = receivers.StatusDisabled
	who := "admin:n.beridze"
	e.DisabledBy = &who
	if err := f.kr.Upsert(e); err != nil {
		t.Fatal(err)
	}
	if b := s.Snapshot("rx-1", now); b.State != "disabled" || *b.DisabledBy != "instance" || *b.DisabledByWho != who {
		t.Fatalf("registry disabled: %+v", b)
	}
	id := "rx-2"
	f.gate.Apply(sources.State{Controls: []sources.Control{{SourceType: SourceType, InstanceID: &id, Enabled: false}}, Version: 1, Epoch: "e"})
	if b := s.Snapshot("rx-2", now); b.State != "disabled" || *b.DisabledBy != "instance" || b.DisabledByWho != nil {
		t.Fatalf("source-control disabled: %+v", b)
	}
	f.gate.Apply(sources.State{Version: 2, Epoch: "e"})
	rxTS := time.UnixMilli(now.UnixMilli() - 40_000)
	s.Accepted("rx-2", &Batch{Backlog: true, SentAtMS: now.UnixMilli(), Observations: []Observation{{RxTS: &rxTS}}}, 1, 0)
	if b := s.Snapshot("rx-2", now); !b.Lagging || *b.LagS != 40 {
		t.Fatalf("lagging: %+v", b)
	}
	s.Accepted("rx-2", &Batch{SentAtMS: now.UnixMilli()}, 1, 0)
	if b := s.Snapshot("rx-2", now); b.Lagging {
		t.Fatalf("caught up: %+v", b)
	}
}

// E-10: status counters are kept for at most MaxReceivers receivers.
func TestStatusIsBounded(t *testing.T) {
	f := newFixture(t)
	f.status.MaxReceivers = 2
	for _, id := range []string{"a1", "a2", "a3"} {
		f.status.Refused(id, "x")
	}
	if len(f.status.stats) != 2 {
		t.Fatal(len(f.status.stats))
	}
}

// The status message is the envelope with source/status/v1 and is sent
// on src.v1.direct_rid.<receiver>; a publish failure is logged, not fatal.
func TestPublishSendsTheEnvelopePerReceiver(t *testing.T) {
	r := newRx(t, cheapHasher(t), "rx-1", nil)
	f := newFixture(t, r)
	pub := f.status.Pub.(*fakePub)
	f.status.Depth = func() uint64 { return 7 }
	if n := f.status.Publish(f.now); n != 1 {
		t.Fatal(n)
	}
	msgs := pub.msgs[StatusSubject("rx-1")]
	if len(msgs) != 1 {
		t.Fatalf("%v", pub.msgs)
	}
	var env map[string]any
	if err := json.Unmarshal(msgs[0], &env); err != nil {
		t.Fatal(err)
	}
	body := env["body"].(map[string]any)
	if env["schema"] != "source/status/v1" || env["producer"] != Producer || env["time_source"] != "system" ||
		!ulidPattern.MatchString(env["msg_id"].(string)) || body["source"] != "direct_rid" || body["queue_depth"] != 7.0 ||
		!strings.HasSuffix(env["ts"].(string), "Z") || body["state"] != "unknown" {
		t.Fatalf("%s", msgs[0])
	}
	if _, ok := body["disabled_by"]; !ok {
		t.Fatal("disabled_by must be present (null) when not disabled")
	}
	pub.err = errors.New("down")
	if n := f.status.Publish(f.now); n != 0 {
		t.Fatal(n)
	}
}

// The pipeline's thresholds are the configuration's, with the policy's
// defaults (INV-03).
func TestPipelineSettingsFromTheConfiguration(t *testing.T) {
	cfg := config.RIDPipelineTuning{IdentityTTLS: 15, MaxGapS: 3, IdentifyWithinS: 4, BroadcastToleranceS: 1, MaxLatencyS: 5,
		MinVerticalAccuracy: 2, PressureHoldS: 10, MaxBatchSpacingS: 120, MaxTransmitters: 7, MaxTracks: 9}
	s := PipelineSettings(cfg)
	if s.Tracker.IdentityTTLS != 15 || s.Tracker.MaxGapS != 3 || s.Tracker.IdentifyWithinS != 4 || s.Tracker.MaxTransmitters != 7 ||
		s.Broadcast.ToleranceS != 1 || s.Broadcast.MaxLatencyS != 5 || s.Altitude.MinVerticalAccuracy != 2 || !s.Altitude.HoldPressure ||
		s.Altitude.PressureHoldS != 10 || s.MaxBatchSpacing != 120*time.Second || s.MaxTracks != 9 || s.Producer != Producer {
		t.Fatalf("%+v", s)
	}
}
