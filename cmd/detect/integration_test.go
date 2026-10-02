package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

type buf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *buf) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }

func (b *buf) line(msg string) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	for l := range strings.SplitSeq(b.b.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["msg"] == msg {
			return m
		}
	}
	return nil
}

// run starts detect with extra and waits for msg, or for the exit.
func run(t *testing.T, extra map[string]string, msg string) (map[string]any, int, *buf) {
	t.Helper()
	m := map[string]string{
		"NATS_URL": bustest.URL(t), "TS_URL": "postgres://unused@127.0.0.1:1/unused", "ADMIN_ADDR": "127.0.0.1:0",
		"STATUS_INTERVAL_S": "1", "SHUTDOWN_TIMEOUT_S": "5", "NATS_START_BACKOFF_MS": "10",
	}
	for k, v := range extra {
		m[k] = v
	}
	out := &buf{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exit := make(chan int, 1)
	go func() {
		exit <- proc.Main(ctx, spec(&config.Detect{}), nil, out, out, func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	}()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case code := <-exit:
			l := out.line(msg)
			return l, code, out
		case <-deadline:
			t.Fatalf("no %q and no exit:\n%s", msg, out.b.String())
		case <-time.After(20 * time.Millisecond):
			if l := out.line(msg); l != nil {
				cancel()
				return l, <-exit, out
			}
		}
	}
}

// 05 §3: a worker judges the cells the map gives it; with none it
// refuses to start, naming what to do; CELLS=all (the demo) starts
// whatever the map says. Each outcome is read from the process.
func TestIntegrationDetectClaimsItsCellsOrRefusesToStart(t *testing.T) {
	bp, err := bus.OpenProcess(context.Background(), bustest.URL(t), config.Bus{BusTRKStorage: "file", SourceControlBucket: "source_control",
		SourceControlMaxValueBytes: 262144, NATSStartAttempts: 1, NATSStartBackoffMS: 10, NATSTimeoutMS: 2000}, "test", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bp.Close()
	st := cell.StoreOf(bp)
	worker := strings.ReplaceAll(bustest.Name("detect"), "_", "-")
	ctx := context.Background()
	cur, rev, _, err := st.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assignments := map[string]string{"c3:131:224": worker, "c3:131:225": worker}
	if err := st.Put(ctx, cell.Ownership{Version: cur.Version + 1, Assignments: assignments, UpdatedBy: "test", UpdatedAt: time.Now()}, rev); err != nil {
		t.Fatal(err)
	}

	l, code, out := run(t, map[string]string{"DETECT_WORKER_ID": worker}, "cells claimed")
	if code != proc.ExitOK || l == nil || l["all"] != false || len(l["cells"].([]any)) != 2 || l["cells"].([]any)[0] != "c3:131:224" {
		t.Fatalf("owned cells: exit %d %v\n%s", code, l, out.b.String())
	}

	l, code, out = run(t, map[string]string{"DETECT_WORKER_ID": "detect-nobody"}, "process failed")
	if code != proc.ExitFailed || l == nil || !strings.Contains(l["error"].(string), `"detect-nobody" owns no cell`) ||
		!strings.Contains(l["error"].(string), "CELLS=all") {
		t.Fatalf("no cells: exit %d %v\n%s", code, l, out.b.String())
	}

	l, code, out = run(t, map[string]string{"DETECT_WORKER_ID": "detect-nobody", "CELLS": "all"}, "cells claimed")
	if code != proc.ExitOK || l == nil || l["all"] != true {
		t.Fatalf("CELLS=all: exit %d %v\n%s", code, l, out.b.String())
	}
}

// E-02, Z-09, D-05: detect says at start what ground it has. With nothing
// configured both inputs are "not configured" and each is a warning that
// names what is not judged; with internal/ground's generated volume both
// are loaded and the start line carries the dataset and the Copernicus
// attribution.
func TestIntegrationDetectSaysWhatGroundItHas(t *testing.T) {
	l, code, out := run(t, map[string]string{"CELLS": "all"}, "cells claimed")
	if code != proc.ExitOK || l == nil {
		t.Fatalf("exit %d\n%s", code, out.b.String())
	}
	g := out.line("ground datasets")
	if g == nil || g["terrain"] != "not configured" || g["geoid"] != "not configured" ||
		out.line("terrain not configured: AGL zone limits are not judged (limit_not_judged) and the height limit is not evaluated") == nil {
		t.Fatalf("nothing configured: %v\n%s", g, out.b.String())
	}

	testdata := filepath.Join("..", "..", "internal", "ground", "testdata")
	_, code, out = run(t, map[string]string{
		"CELLS": "all", "GROUND_DIR": filepath.Join(testdata, "tiles"), "GEOID_FILE": filepath.Join(testdata, "geoid-constant.pgm"),
	}, "cells claimed")
	g = out.line("ground datasets")
	if code != proc.ExitOK || g == nil || g["terrain"] != "loaded" || g["geoid"] != "loaded" ||
		!strings.Contains(g["terrain_attribution"].(string), "Copernicus") || len(g["terrain_datasets"].([]any)) != 1 {
		t.Fatalf("loaded: exit %d %v\n%s", code, g, out.b.String())
	}
}

// E-02, Z-09, SC-22: detect with no zones projection (the telemetry
// database unreachable) and no ground says at error level that zone
// incursions and dynamic restrictions are not judged, and keeps every
// status line at error level; it never looks like an empty sky.
func TestIntegrationDetectSaysWhatItCannotJudge(t *testing.T) {
	l, code, out := run(t, map[string]string{"CELLS": "all"}, "violations not judged in full")
	if code != proc.ExitOK || l == nil || l["level"] != "ERROR" {
		t.Fatalf("exit %d %v\n%s", code, l, out.b.String())
	}
	nj, _ := l["not_judged"].([]any)
	joined := ""
	for _, s := range nj {
		joined += s.(string) + "\n"
	}
	if !strings.Contains(joined, "zones projection not loaded") || !strings.Contains(joined, "restrictions projection not loaded") {
		t.Fatalf("not_judged %v", nj)
	}
	out.mu.Lock()
	defer out.mu.Unlock()
	errorStatus := false
	for line := range strings.SplitSeq(out.b.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "status" && m["level"] == "ERROR" {
			errorStatus = true
		}
	}
	if !errorStatus {
		t.Fatalf("no status line at error level:\n%s", out.b.String())
	}
}
