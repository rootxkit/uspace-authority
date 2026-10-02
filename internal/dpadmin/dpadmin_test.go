package dpadmin

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

func status(id, state string, at time.Time) []byte {
	inst := id
	b := dp.StatusBody{Source: dp.SourceType, SourceInstance: &inst, State: state, Since: bus.Stamp(at), ISAs: 2, Tiles: 3,
		Flights: 4, P95S: 0.4, P99S: 0.9, Counters: map[string]uint64{"polls": 7}, DSS: dp.DSSOK, USSBaseURL: "https://sp.example.test"}
	raw, _ := json.Marshal(bus.SystemEnvelope(dp.StatusSchema, dp.Producer, at, b))
	return raw
}

// dp-poller's statuses are listed by provider with their extras; a
// status not repeated within StaleAfter is shown stale (dp-poller is
// silent); a malformed one is counted; past the bound the one heard
// longest ago is dropped and counted (E-10).
func TestProvidersFromTheStatuses(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	clock := now
	p := &Providers{Max: 2, Counters: &core.Counters{}, Now: func() time.Time { return clock }}
	p.Offer(status("ussp-a-01", dp.StateLive, now))
	p.Offer([]byte(`{"schema":"source/status/v1","body":{"source":"direct_rid"}}`))
	list := p.List(10 * time.Second)
	if len(list) != 1 || list[0].UssId != "ussp-a-01" || list[0].State != "live" || list[0].Tiles != 3 || *list[0].P99S != 0.9 ||
		(*list[0].Counters)["polls"] != 7 || *list[0].UssBaseUrl != "https://sp.example.test" {
		t.Fatalf("%+v", list)
	}
	if p.Counters.Snapshot()[CounterStatusMalformed] != 1 {
		t.Fatalf("counters %v", p.Counters.Snapshot())
	}
	clock = now.Add(11 * time.Second)
	if list := p.List(10 * time.Second); list[0].State != "stale" {
		t.Fatalf("silent dp-poller: %s", list[0].State)
	}
	p.Offer(status("ussp-b-01", dp.StateDown, clock))
	clock = clock.Add(time.Second)
	p.Offer(status("ussp-c-01", dp.StateLive, clock))
	list = p.List(time.Hour)
	if len(list) != 2 || list[0].UssId != "ussp-b-01" || p.Counters.Snapshot()[CounterStatusEvicted] != 1 {
		t.Fatalf("%+v %v", list, p.Counters.Snapshot())
	}
}

func adminCtx() context.Context {
	return apiserver.WithIdentity(context.Background(), apiserver.Identity{ActorType: "user", Subject: "admin-1",
		Roles: []string{apiserver.RoleAdmin}, Realm: apiserver.RealmConsole, Session: true})
}

func statusCode(err error) int {
	if err == nil {
		return 0
	}
	return httpx.ProblemFromError(err).Status
}

// The refusals that need nothing but the request: a bad area, a bad
// label, a bad USS id, an unknown availability, no reason; without a
// DSS the arbitration is refused with 503 before anything is recorded.
func TestRequestRefusals(t *testing.T) {
	s := &Service{Counters: &core.Counters{}}
	for name, body := range map[string]*gen.DPViewInput{
		"no body": nil, "no label": {Label: " ", Bbox: []float64{44.7, 41.6, 44.9, 41.8}},
		"three numbers": {Label: "a", Bbox: []float64{1, 2, 3}}, "antimeridian": {Label: "a", Bbox: []float64{179, 1, -179, 2}},
	} {
		if _, err := s.CreateDPView(adminCtx(), gen.CreateDPViewRequestObject{Body: body}); statusCode(err) != 400 {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, req := range map[string]gen.SetDPProviderAvailabilityRequestObject{
		"bad id":       {UssId: "../x", Body: &gen.SetDPProviderAvailabilityJSONRequestBody{Availability: "Down", Reason: "r"}},
		"no body":      {UssId: "ussp-a-01"},
		"unknown":      {UssId: "ussp-a-01", Body: &gen.SetDPProviderAvailabilityJSONRequestBody{Availability: "Gone", Reason: "r"}},
		"no reason":    {UssId: "ussp-a-01", Body: &gen.SetDPProviderAvailabilityJSONRequestBody{Availability: "Down", Reason: ""}},
		"unconfigured": {UssId: "ussp-a-01", Body: &gen.SetDPProviderAvailabilityJSONRequestBody{Availability: "Down", Reason: "r"}},
	} {
		want := 400
		if name == "unconfigured" {
			want = 503
		}
		if _, err := s.SetDPProviderAvailability(adminCtx(), req); statusCode(err) != want {
			t.Errorf("%s: %v (%d)", name, err, statusCode(err))
		}
	}
}
