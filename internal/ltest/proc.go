package ltest

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/proc"
)

// DefaultMaxLines bounds the log lines a Proc keeps (E-10): past it the
// oldest is forgotten and counted in Lines.Dropped.
const DefaultMaxLines = 100_000

// Lines is a process's stdout read back as JSON log lines. Writers and
// waiters meet on a channel closed at every write, so waiting never
// sleeps.
type Lines struct {
	mu      sync.Mutex
	partial []byte
	lines   []map[string]any
	raw     []string
	max     int
	dropped int
	changed chan struct{}
}

// NewLines keeps at most limit lines (0 is DefaultMaxLines).
func NewLines(limit int) *Lines {
	if limit <= 0 {
		limit = DefaultMaxLines
	}
	return &Lines{max: limit, changed: make(chan struct{})}
}

// Write implements io.Writer.
func (l *Lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.partial = append(l.partial, p...)
	added := false
	for {
		i := bytes.IndexByte(l.partial, '\n')
		if i < 0 {
			break
		}
		line := string(l.partial[:i])
		l.partial = l.partial[i+1:]
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			m = map[string]any{"msg": line, "unparsed": true}
		}
		l.lines = append(l.lines, m)
		l.raw = append(l.raw, line)
		if len(l.lines) > l.max {
			l.lines, l.raw = l.lines[1:], l.raw[1:]
			l.dropped++
		}
		added = true
	}
	if added {
		close(l.changed)
		l.changed = make(chan struct{})
	}
	return len(p), nil
}

// Dropped is how many lines were forgotten past the bound.
func (l *Lines) Dropped() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// Find is the last line whose msg is msg and that ok accepts (nil
// accepts every one), or nil.
func (l *Lines) Find(msg string, ok func(map[string]any) bool) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.lines) - 1; i >= 0; i-- {
		if m := l.lines[i]; m["msg"] == msg && (ok == nil || ok(m)) {
			return m
		}
	}
	return nil
}

// All is every kept line whose msg is msg.
func (l *Lines) All(msg string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, m := range l.lines {
		if m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

// Tail is the last n raw lines.
func (l *Lines) Tail(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	from := max(len(l.raw)-n, 0)
	return strings.Join(l.raw[from:], "\n")
}

// Wait returns the first line Find gives within d, or nil at the
// deadline.
func (l *Lines) Wait(msg string, ok func(map[string]any) bool, d time.Duration) map[string]any {
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	for {
		l.mu.Lock()
		ch := l.changed
		l.mu.Unlock()
		if m := l.Find(msg, ok); m != nil {
			return m
		}
		select {
		case <-ch:
		case <-deadline.C:
			return l.Find(msg, ok)
		}
	}
}

// Proc is one process of the system run in the test binary through
// proc.Main, exactly as its cmd runs it, with its configuration from an
// environment map and its stdout kept as Lines.
type Proc struct {
	Name string
	Out  *Lines
	// Env is the environment the process was started with.
	Env map[string]string

	t        testing.TB
	cancel   context.CancelFunc
	exit     chan int
	stopOnce sync.Once
	code     int
	stopped  time.Time
}

// ProcStopTimeout bounds a process's drain at Stop.
const ProcStopTimeout = 30 * time.Second

// StartProc runs spec with env until Stop or the end of the test, and
// fails the test when it exits non-zero (its last lines in the log).
func StartProc(t testing.TB, spec proc.Spec, env map[string]string) *Proc {
	t.Helper()
	base := map[string]string{"ADMIN_ADDR": "127.0.0.1:0", "STATUS_INTERVAL_S": "1", "SHUTDOWN_TIMEOUT_S": "10", "LOG_LEVEL": "info"}
	for k, v := range env {
		base[k] = v
	}
	p := &Proc{Name: spec.Name, Out: NewLines(0), Env: base, t: t, exit: make(chan int, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go func() {
		p.exit <- proc.Main(ctx, spec, nil, p.Out, p.Out, func(k string) (string, bool) { v, ok := base[k]; return v, ok })
	}()
	t.Cleanup(func() {
		if code := p.Stop(); code != proc.ExitOK {
			t.Errorf("%s exited %d; last lines:\n%s", p.Name, code, p.Out.Tail(40))
		}
	})
	if p.Out.Wait("started", nil, 20*time.Second) == nil {
		t.Fatalf("%s did not start; last lines:\n%s", p.Name, p.Out.Tail(40))
	}
	return p
}

// Stop ends the process and returns its exit code (-1 when it did not
// stop within ProcStopTimeout). It may be called more than once.
func (p *Proc) Stop() int {
	p.stopOnce.Do(func() {
		p.cancel()
		select {
		case p.code = <-p.exit:
		case <-time.After(ProcStopTimeout):
			p.code = -1
		}
		p.stopped = time.Now()
	})
	return p.code
}

// WaitLine waits up to d for a line, failing the test without one.
func (p *Proc) WaitLine(msg string, ok func(map[string]any) bool, d time.Duration) map[string]any {
	p.t.Helper()
	m := p.Out.Wait(msg, ok, d)
	if m == nil {
		p.t.Fatalf("%s: no %q line in %v; last lines:\n%s", p.Name, msg, d, p.Out.Tail(40))
	}
	return m
}

// Counters are the counters of the process's last status line, by
// component, or nil before one.
func (p *Proc) Counters() map[string]map[string]uint64 {
	m := p.Out.Find("status", nil)
	if m == nil {
		return nil
	}
	return countersOf(m)
}

// Counter is one counter of the last status line (0 when absent).
func (p *Proc) Counter(component, name string) uint64 {
	return p.Counters()[component][name]
}

// countersOf reads the counters member of a status line.
func countersOf(m map[string]any) map[string]map[string]uint64 {
	raw, ok := m["counters"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]map[string]uint64, len(raw))
	for comp, v := range raw {
		cs, ok := v.(map[string]any)
		if !ok {
			continue
		}
		out[comp] = make(map[string]uint64, len(cs))
		for k, n := range cs {
			if f, ok := n.(float64); ok {
				out[comp][k] = uint64(f)
			}
		}
	}
	return out
}

// statusAfter waits for a status line written after since (the status
// interval is 1 s), so a counter read from it includes everything done
// before since.
func (p *Proc) statusAfter(since time.Time, d time.Duration) map[string]any {
	return p.Out.Wait("status", func(m map[string]any) bool {
		ts, _ := m["time"].(string)
		at, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return false
		}
		return at.After(since)
	}, d)
}
