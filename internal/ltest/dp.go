package ltest

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

// DPPoller is a running dp-poller and the buckets it follows.
type DPPoller struct {
	*Proc
	OversightBucket, ViewsBucket, CertificatesBucket string
}

// StartDPPoller runs dp-poller (WP-14) against the fake DSS dss, with
// tokens from tok (its own client at this system's token service, M24),
// the scratch telemetry database's registry projection, the test geoid
// and this run's buckets; its public listener is on a free loopback
// port named by host (the audience a Service Provider's notification
// carries, M18). It returns once the Display Provider's limits are
// logged (the engine runs).
func (s *Stack) StartDPPoller(dss *fakedss.DSS, tok *TokenServer, extra map[string]string) *DPPoller {
	s.T.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.T.Fatalf("ltest: free port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		s.T.Fatalf("ltest: free port: %v", err)
	}
	_, port, _ := net.SplitHostPort(addr)
	d := &DPPoller{OversightBucket: s.Unique("dp_oversight"), ViewsBucket: s.Unique("dp_views"), CertificatesBucket: s.Unique("certificates")}
	env := s.merge(map[string]string{
		"TS_URL": s.TSURL, "DP_ADDR": addr, "AUTHORITY_PUBLIC_URL": "http://localhost:" + port, "DSS_BASE_URL": HostURL(dss.URL()),
		"DP_TOKEN_URL": tok.URL(), "DP_CLIENT_SECRET_FILE": tok.SecretFile, "DP_CLIENT_ID": tok.ClientID, "GEOID_FILE": GeoidFile(),
		"DP_OVERSIGHT_BUCKET": d.OversightBucket, "DP_VIEWS_BUCKET": d.ViewsBucket, "CERTIFICATES_BUCKET": d.CertificatesBucket,
		"DP_VIEWS_REREAD_S": "1", "DP_DISCOVERY_REREAD_S": "1", "DP_CERTIFICATES_REREAD_S": "1", "DP_PROJECTION_REFRESH_S": "1",
		"DP_POLICY_REREAD_S": "1", "DP_STATUS_INTERVAL_MS": "500", "HTTP_RATE_LIMIT_RPS": "10000", "HTTP_RATE_LIMIT_BURST": "10000",
	}, extra)
	cfg := &config.DPPoller{}
	p := s.track(StartProc(s.T, proc.Spec{Name: "dp-poller", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return dp.Run(ctx, rt, cfg, dp.Options{})
	}}, env))
	p.WaitLine("Display Provider limits (R-14)", nil, 20*time.Second)
	d.Proc = p
	return d
}

// PutOversight publishes the oversight areas dp-poller polls, as api
// does (KV dp_oversight).
func (s *Stack) PutOversight(d *DPPoller, version int64, areas ...dpviews.Area) {
	s.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	kv, err := bus.OpenBucket(ctx, s.BP.JS, dpviews.OversightBucketConfig(d.OversightBucket))
	if err != nil {
		s.T.Fatalf("ltest: oversight bucket: %v", err)
	}
	if ok, err := dpviews.PutOversight(ctx, kv, dpviews.Oversight{Version: version, Areas: areas}, 3); err != nil || !ok {
		s.T.Fatalf("ltest: oversight areas: %v %v", ok, err)
	}
}

// PutCertified publishes the certified USSPs dp-poller follows, as api
// does (KV certificates, WP-16).
func (s *Stack) PutCertified(d *DPPoller, version int64, ussps ...certkv.USSP) {
	s.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	kv, err := bus.OpenBucket(ctx, s.BP.JS, certkv.BucketConfig(d.CertificatesBucket))
	if err != nil {
		s.T.Fatalf("ltest: certificates bucket: %v", err)
	}
	if ok, err := certkv.Put(ctx, kv, certkv.Register{Version: version, USSPs: ussps}, 3); err != nil || !ok {
		s.T.Fatalf("ltest: certified USSPs: %v %v", ok, err)
	}
}

// SPFlight is one flight a fake Service Provider serves: where it is at
// each moment, with the serial its details carry.
type SPFlight struct {
	ID     string
	Serial string
	// OperatorID is the operator registration number its details
	// carry ("" carries none).
	OperatorID string
	// At is the position and the WGS84 altitude (F3411's alt) at a
	// time.
	At func(now time.Time) (latDeg, lonDeg, altWGS84M float64)
}

// RIDFlight is the flight's F3411 record at now, airborne, in
// uas_standards' field names (uspace-core f3411).
func (f SPFlight) RIDFlight(now time.Time) f3411.RIDFlight {
	lat, lon, alt := f.At(now)
	st := f3411.Airborne
	alt32, speed, track := float32(alt), float32(0), float32(0)
	return f3411.RIDFlight{Id: f.ID, AircraftType: f3411.Helicopter, CurrentState: &f3411.RIDAircraftState{
		Timestamp: f3411.Time{Format: f3411.RFC3339, Value: now.UTC()}, TimestampAccuracy: 0.1, SpeedAccuracy: f3411.SA1mps,
		Position: f3411.RIDAircraftPosition{Lat: &lat, Lng: &lon, Alt: &alt32}, Speed: &speed, Track: &track,
		OperationalStatus: &st,
	}}
}

// ServeFlights keeps sp serving flights with a fresh state every 500 ms
// until the returned stop is called or the test ends.
func (s *Stack) ServeFlights(sp *fakedss.SP, flights ...SPFlight) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			now := time.Now()
			fl := make([]f3411.RIDFlight, 0, len(flights))
			details := make(map[string]f3411.RIDFlightDetails, len(flights))
			for _, f := range flights {
				fl = append(fl, f.RIDFlight(now))
				serial := f.Serial
				d := f3411.RIDFlightDetails{Id: f.ID, UasId: &f3411.UASID{SerialNumber: &serial}}
				if f.OperatorID != "" {
					op := f.OperatorID
					d.OperatorId = &op
				}
				details[f.ID] = d
			}
			sp.SetFlights(fl, details)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	s.T.Cleanup(stop)
	return stop
}

// NetworkSubject is the src.v1 subject of a Display Provider's status
// of the USSP ussID.
func NetworkSubject(ussID string) string { return fmt.Sprintf("src.v1.%s.%s", dp.SourceType, ussID) }
