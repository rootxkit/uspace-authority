package logging

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func TestNewWritesJSONWithProcessAndLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "warn", "api")
	l.Info("hidden")
	l.Warn("shown")
	Error(context.Background(), l, "failed", errors.New("boom"), slog.String("k", "v"))
	got := lines(t, &buf)
	if len(got) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(got), got)
	}
	if got[0]["process"] != "api" || got[0]["msg"] != "shown" {
		t.Errorf("line 0: %v", got[0])
	}
	if got[1]["error"] != "boom" || got[1]["k"] != "v" || got[1]["level"] != "ERROR" {
		t.Errorf("line 1: %v", got[1])
	}
	for in, want := range map[string]slog.Level{"debug": slog.LevelDebug, "INFO": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError, "other": slog.LevelInfo} {
		if ParseLevel(in) != want {
			t.Errorf("ParseLevel(%q) = %v", in, ParseLevel(in))
		}
	}
	Discard().Info("nothing")
}

func newTestLimiter(buf *bytes.Buffer, maxKeys int) (*Limiter, *time.Time, *core.Counters) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c := &core.Counters{}
	l := NewLimiter(New(buf, "info", "t"), 10*time.Second, maxKeys, c)
	l.now = func() time.Time { return now }
	return l, &now, c
}

func TestLimitedLogsFirstThenOncePerIntervalWithSuppressedCount(t *testing.T) {
	var buf bytes.Buffer
	l, now, c := newTestLimiter(&buf, 0)
	lg := l.Limited("receiver:rx-1")
	lg.Warn("bad signature")
	for range 5 {
		*now = now.Add(time.Second)
		lg.Warn("bad signature")
	}
	*now = now.Add(10 * time.Second)
	lg.With("extra", 1).WithGroup("g").Warn("bad signature")
	got := lines(t, &buf)
	if len(got) != 2 {
		t.Fatalf("got %d lines, want 2: %v", len(got), got)
	}
	if got[0]["suppressed"] != float64(0) || got[0]["limit_key"] != "receiver:rx-1" {
		t.Errorf("first line: %v", got[0])
	}
	if g, ok := got[1]["g"].(map[string]any); !ok || g["suppressed"] != float64(5) {
		t.Errorf("second line should carry suppressed=5: %v", got[1])
	}
	if c.Get(CounterLogSuppressed) != 5 {
		t.Errorf("suppressed counter = %d", c.Get(CounterLogSuppressed))
	}
	if !lg.Enabled(context.Background(), slog.LevelWarn) || lg.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("Enabled does not follow the base level")
	}
}

func TestLimitedKeysAreIndependent(t *testing.T) {
	var buf bytes.Buffer
	l, _, _ := newTestLimiter(&buf, 0)
	l.Limited("a").Warn("x")
	l.Limited("b").Warn("x")
	l.Limited("a").Warn("x")
	if n := len(lines(t, &buf)); n != 2 {
		t.Fatalf("got %d lines, want 2 (one per key)", n)
	}
}

// E-10: the key set is bounded; exceeding it evicts the least recently
// seen key and counts the eviction.
func TestLimiterEvictsBeyondItsBound(t *testing.T) {
	var buf bytes.Buffer
	l, _, c := newTestLimiter(&buf, 3)
	for i := range 3 {
		l.Limited(fmt.Sprint("k", i)).Warn("x")
	}
	l.Limited("k0").Warn("x") // k0 is now the most recent; k1 the oldest
	l.Limited("k3").Warn("x") // evicts k1
	if l.Len() != 3 {
		t.Fatalf("Len = %d, want 3", l.Len())
	}
	if c.Get(CounterLogKeysEvicted) != 1 {
		t.Fatalf("evicted = %d, want 1", c.Get(CounterLogKeysEvicted))
	}
	buf.Reset()
	l.Limited("k1").Warn("x") // forgotten: logged again as a first event
	l.Limited("k0").Warn("x") // remembered: suppressed
	if got := lines(t, &buf); len(got) != 1 || got[0]["limit_key"] != "k1" {
		t.Fatalf("after eviction: %v", got)
	}
}

func TestStatusEmitsEverySourceIncludingEmptyOnes(t *testing.T) {
	var buf bytes.Buffer
	busy := &core.Counters{}
	busy.Add("rejected_signature", 3)
	s := &Status{Logger: New(&buf, "info", "t"), Interval: time.Hour,
		Sources: []Source{{Name: "ingest", Counters: busy}},
		Extra:   func() []slog.Attr { return []slog.Attr{slog.Int("projection_age_s", 4)} }}
	s.Add(Source{Name: "idle", Counters: &core.Counters{}})
	s.Emit(context.Background())
	got := lines(t, &buf)
	if len(got) != 1 || got[0]["msg"] != "status" {
		t.Fatalf("got %v", got)
	}
	counters := got[0]["counters"].(map[string]any)
	if counters["ingest"].(map[string]any)["rejected_signature"] != float64(3) {
		t.Errorf("ingest counters: %v", counters)
	}
	if idle, ok := counters["idle"].(map[string]any); !ok || len(idle) != 0 {
		t.Errorf("an idle source must appear, empty: %v", counters)
	}
	if got[0]["projection_age_s"] != float64(4) {
		t.Errorf("extra missing: %v", got[0])
	}
}

func TestStatusRunEmitsAtOnceThenPerIntervalUntilCancelled(t *testing.T) {
	var buf safeBuffer
	s := &Status{Logger: New(&buf, "info", "t"), Interval: 20 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(70 * time.Millisecond)
	cancel()
	<-done
	b := buf.Bytes()
	if n := bytes.Count(b, []byte(`"msg":"status"`)); n < 2 {
		t.Fatalf("got %d status lines, want at least 2", n)
	}
}

func TestStatusCarriesEveryAddedExtra(t *testing.T) {
	var buf bytes.Buffer
	s := &Status{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}
	s.Emit(context.Background())
	s.AddExtra(func() []slog.Attr { return []slog.Attr{slog.Int64("policy_version", 2)} })
	s.AddExtra(func() []slog.Attr { return []slog.Attr{slog.Int64("projection_age_s", 5)} })
	s.Emit(context.Background())
	got := lines(t, &buf)
	if _, ok := got[0]["policy_version"]; ok {
		t.Fatalf("an extra appeared before it was added: %v", got[0])
	}
	if got[1]["policy_version"] != 2.0 || got[1]["projection_age_s"] != 5.0 {
		t.Fatalf("second line %v", got[1])
	}
}
