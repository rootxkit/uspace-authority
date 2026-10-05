package ltest

import (
	"context"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/detectsvc"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers/ingest"
	"github.com/rootxkit/uspace-authority/internal/tswriter"
	"github.com/rootxkit/uspace-authority/internal/violations"
)

// The processes a scenario can run. Each is started through proc.Main
// with the Run its cmd/*/main.go hands to proc.Main, so a scenario runs
// the binary's wiring; extra overrides or adds environment variables.

func (s *Stack) merge(base, extra map[string]string) map[string]string {
	out := s.BusEnv()
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (s *Stack) track(p *Proc) *Proc {
	s.mu.Lock()
	s.procs = append(s.procs, p)
	s.mu.Unlock()
	return p
}

// RIDIngest is a running rid-ingest and its public base URL.
type RIDIngest struct {
	*Proc
	BaseURL string
	// registered counts the receivers registered for it (under the
	// stack's lock).
	registered int
}

// StartRIDIngest runs rid-ingest (WP-7, WP-8) on a free port with this
// run's key-set bucket, the telemetry database's registry projection,
// the test geoid, and lab headers admitted (the harness's receivers set
// X-Lab-Scenario, T11). It returns once the listener is open and the
// registry projection has been read.
func (s *Stack) StartRIDIngest(extra map[string]string) *RIDIngest {
	s.T.Helper()
	env := s.merge(map[string]string{
		"TS_URL": s.TSURL, "RID_KEYSET_BUCKET": s.RIDKeysBucket, "RID_INGEST_ADDR": "127.0.0.1:0",
		"GEOID_FILE": GeoidFile(), "LAB_HEADERS_ALLOWED": "true",
		"RID_INGEST_STATUS_INTERVAL_MS": "500", "RID_INGEST_STORAGE_RETRY_MS": "200", "RID_INGEST_KEYSET_REREAD_S": "1",
		"HTTP_RATE_LIMIT_RPS": "10000", "HTTP_RATE_LIMIT_BURST": "10000",
	}, extra)
	cfg := &config.RIDIngest{}
	p := s.track(StartProc(s.T, proc.Spec{Name: "rid-ingest", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return ingest.Run(ctx, rt, cfg, ingest.Options{})
	}}, env))
	l := p.WaitLine("public listener open", nil, 20*time.Second)
	addr, _ := l["addr"].(string)
	if env["TS_URL"] == s.TSURL {
		p.WaitLine("registry projection loaded: Remote ID tracks are identified against it", nil, 20*time.Second)
	}
	return &RIDIngest{Proc: p, BaseURL: "http://" + addr}
}

// StartTSDBWriter runs tsdb-writer (WP-9) against the scratch telemetry
// database and returns once it consumes.
func (s *Stack) StartTSDBWriter(extra map[string]string) *Proc {
	s.T.Helper()
	env := s.merge(map[string]string{"TS_URL": s.TSURL, "TSDB_WRITER_RETRY_MAX_MS": "500", "TSDB_WRITER_BATCH_MAX_WAIT_MS": "100"}, extra)
	cfg := &config.TSDBWriter{}
	p := s.track(StartProc(s.T, proc.Spec{Name: "tsdb-writer", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return tswriter.Run(ctx, rt, cfg, tswriter.Options{})
	}}, env))
	p.WaitLine("tsdb-writer consuming", nil, 30*time.Second)
	return p
}

// Detect is a running detect and the durable it reads trk.v1 through.
type Detect struct {
	*Proc
	WorkerID string
	Durable  string
}

// DetectDurable is the TRK durable of a detect worker judging every
// cell (internal/detectsvc's naming).
func DetectDurable(workerID string) string { return detectsvc.DurableOf(workerID, nil) }

// StartDetect runs detect (WP-12, WP-26) for every cell (CELLS=all) with
// the synthetic terrain and the test geoid, zones re-read every second
// besides zones.v1.changed, and returns once its durable on TRK exists:
// a track published after that is judged. extra overrides any of it
// (GROUND_DIR="" runs it without terrain, SC-13).
func (s *Stack) StartDetect(extra map[string]string) *Detect {
	s.T.Helper()
	worker := strings.ReplaceAll(s.Unique("det"), "_", "-")
	env := s.merge(map[string]string{
		"TS_URL": s.TSURL, "CELLS": "all", "DETECT_WORKER_ID": worker, "GROUND_DIR": GroundDir(), "GEOID_FILE": GeoidFile(),
		"DETECT_ZONES_REFRESH_S": "1", "DETECT_RESTRICTIONS_REFRESH_S": "1", "DETECT_POLICY_REREAD_S": "1",
	}, extra)
	for k, v := range env {
		if v == "" {
			delete(env, k)
		}
	}
	cfg := &config.Detect{}
	p := s.track(StartProc(s.T, proc.Spec{Name: "detect", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return detectsvc.RunProcess(ctx, rt, cfg)
	}}, env))
	p.WaitLine("detecting", nil, 20*time.Second)
	d := &Detect{Proc: p, WorkerID: worker, Durable: DetectDurable(worker)}
	s.Await("detect's TRK durable "+d.Durable, 20*time.Second, func() bool { return s.consumerExists(bus.StreamTRK, d.Durable) })
	return d
}

func (s *Stack) consumerExists(stream, durable string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := s.BP.JS.Consumer(ctx, stream, durable)
	return err == nil && c != nil
}

// Consumers are the durable names on stream.
func (s *Stack) Consumers(stream string) []string {
	s.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := s.BP.JS.Stream(ctx, stream)
	if err != nil {
		s.T.Fatalf("ltest: stream %s: %v", stream, err)
	}
	var out []string
	names := st.ConsumerNames(ctx)
	for n := range names.Name() {
		out = append(out, n)
	}
	if err := names.Err(); err != nil {
		s.T.Fatalf("ltest: consumers of %s: %v", stream, err)
	}
	return out
}

// StreamMessages is how many messages stream holds.
func (s *Stack) StreamMessages(stream string) uint64 {
	s.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := s.BP.JS.Stream(ctx, stream)
	if err != nil {
		s.T.Fatalf("ltest: stream %s: %v", stream, err)
	}
	info, err := st.Info(ctx)
	if err != nil {
		s.T.Fatalf("ltest: stream %s: %v", stream, err)
	}
	return info.State.Msgs
}

// StartViolationStore runs api's consumer of ALRT (internal/violations:
// persistence with an events row per transition) against the scratch
// relational database, from the new messages on, and returns once its
// durable exists. api's other duties are not part of the scenario
// stack: its binary needs keys and sessions no scenario judges.
func (s *Stack) StartViolationStore() *ViolationStore {
	s.T.Helper()
	db := s.PG()
	counters := &core.Counters{}
	svc := &violations.Service{DB: db, Audit: audit.NewWriter(db), MaxExcerptSamples: 600, WriteTimeout: 10 * time.Second,
		Counters: counters, Logger: logging.Discard()}
	durable := s.Unique("api_violations")
	cons := &violations.Consumer{Service: svc, BP: s.BP, Durable: durable, MaxAckPending: 256, AckWait: 30 * time.Second, FetchMax: 64,
		Timeout: 2 * time.Second, RetryDelay: 100 * time.Millisecond, DeliverPolicy: jetstream.DeliverNewPolicy}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); cons.Run(ctx) }()
	s.T.Cleanup(func() { cancel(); <-done })
	s.Await("api's ALRT durable "+durable, 20*time.Second, func() bool { return s.consumerExists(bus.StreamALRT, durable) })
	vs := &ViolationStore{s: s, Durable: durable, Counters: counters}
	s.mu.Lock()
	s.store = vs
	s.mu.Unlock()
	return vs
}
