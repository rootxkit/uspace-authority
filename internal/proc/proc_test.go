package proc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/config"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines(t *testing.T) []map[string]any {
	t.Helper()
	s.mu.Lock()
	data := bytes.Clone(s.b.Bytes())
	s.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not a JSON line: %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func (s *syncBuffer) find(t *testing.T, msg string) map[string]any {
	t.Helper()
	for _, l := range s.lines(t) {
		if l["msg"] == msg {
			return l
		}
	}
	return nil
}

func apiEnv(extra map[string]string) config.LookupFunc {
	m := map[string]string{
		"PG_URL":               "postgres://u:pw@db:5432/rel",
		"TS_URL":               "postgres://u:pw@db:5432/ts",
		"NATS_URL":             "nats://nats:4222",
		"AUTHORITY_PUBLIC_URL": "https://authority.example.test",
		"ADMIN_ADDR":           "127.0.0.1:0",
		"API_ADDR":             "127.0.0.1:0",
		"STATUS_INTERVAL_S":    "1",
		"SHUTDOWN_TIMEOUT_S":   "2",
		"SIGNING_KEY_FILES":    "/run/keys/token-1.pem",
	}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestHelpPrintsEveryVariable(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Main(context.Background(), Spec{Name: "api", Config: &config.API{}}, []string{"--help"}, &out, &errOut, apiEnv(nil))
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"usage: uspace-authority api", "PG_URL (required; secret)", "ADMIN_ADDR"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

func TestUnknownArgumentIsAConfigError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Main(context.Background(), Spec{Name: "api", Config: &config.API{}}, []string{"--port=1"}, &out, &errOut, apiEnv(nil)); code != ExitConfig {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errOut.String(), "unknown argument") {
		t.Errorf("stderr: %s", errOut.String())
	}
}

// E-02: run the failure. Without PG_URL the process exits non-zero and
// its one line names the variable.
func TestMissingPGURLExitsNonZeroNamingIt(t *testing.T) {
	env := apiEnv(nil)
	lookup := func(k string) (string, bool) {
		if k == "PG_URL" {
			return "", false
		}
		return env(k)
	}
	var out, errOut bytes.Buffer
	code := Main(context.Background(), Spec{Name: "api", Config: &config.API{}, Run: Idle("x")}, nil, &out, &errOut, lookup)
	if code != ExitConfig {
		t.Fatalf("exit %d, want %d", code, ExitConfig)
	}
	var m map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &m); err != nil {
		t.Fatalf("stderr is not one JSON line: %q", errOut.String())
	}
	if m["msg"] != "configuration invalid" || !strings.Contains(m["error"].(string), "PG_URL: required") {
		t.Errorf("line: %v", m)
	}
	if f, _ := m["fields"].([]any); len(f) != 1 || f[0] != "PG_URL" {
		t.Errorf("fields: %v", m["fields"])
	}
	if out.Len() != 0 {
		t.Errorf("stdout written before the config was valid: %s", out.String())
	}
}

func waitFor(t *testing.T, buf *syncBuffer, msg string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if l := buf.find(t, msg); l != nil {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q line", msg)
	return nil
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// E-02: run the success. The process starts, serves the health paths
// and /metrics, logs a status line, and exits 0 when the context ends.
func TestRunServesHealthLogsStatusAndExitsZeroOnSignal(t *testing.T) {
	var out, errOut syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	ready := false
	var mu sync.Mutex
	spec := Spec{Name: "api", Config: &config.API{}, Run: func(ctx context.Context, rt *Runtime) error {
		rt.Ready.Add("db", func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			if !ready {
				return errors.New("not yet")
			}
			return nil
		})
		rt.Counters.Inc("example_refusal")
		return Idle("WP-test")(ctx, rt)
	}}
	done := make(chan int, 1)
	go func() { done <- Main(ctx, spec, nil, &out, &errOut, apiEnv(nil)) }()

	started := waitFor(t, &out, "started")
	if !strings.Contains(started["config"].(string), "PG_URL=<redacted>") || started["tracing"] != false {
		t.Errorf("started line: %v", started)
	}
	base := "http://" + started["admin_addr"].(string)
	waitFor(t, &out, "no work yet: this process is a scaffold")

	if code, body := get(t, base+"/healthz"); code != 200 || !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("/healthz: %d %s", code, body)
	}
	if code, body := get(t, base+"/readyz"); code != 503 || !strings.Contains(body, `"error":"not yet"`) {
		t.Errorf("/readyz before ready: %d %s", code, body)
	}
	mu.Lock()
	ready = true
	mu.Unlock()
	if code, body := get(t, base+"/readyz"); code != 200 || !strings.Contains(body, `"db":{"ok":true}`) {
		t.Errorf("/readyz when ready: %d %s", code, body)
	}
	if code, body := get(t, base+"/metrics"); code != 200 || !strings.Contains(body, `uspace_authority_example_refusal{component="process"} 1`) ||
		!strings.Contains(body, `route="GET /healthz"`) {
		t.Errorf("/metrics: %d %s", code, body)
	}
	if code, body := get(t, base+"/nothing"); code != 404 || !strings.Contains(body, "problems/not_found") {
		t.Errorf("unknown admin path: %d %s", code, body)
	}
	status := waitFor(t, &out, "status")
	if c, ok := status["counters"].(map[string]any); !ok || c["process"] == nil {
		t.Errorf("status line: %v", status)
	}

	cancel()
	if code := <-done; code != ExitOK {
		t.Fatalf("exit %d, want 0; stderr %s", code, errOut.b.String())
	}
	stopped := waitFor(t, &out, "stopped")
	if stopped["exit_code"] != float64(0) {
		t.Errorf("stopped line: %v", stopped)
	}
	waitFor(t, &out, "shutting down")
}

func TestServePublicAnswersWithProblems(t *testing.T) {
	var out, errOut syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &config.API{}
	spec := Spec{Name: "api", Config: cfg, Run: func(ctx context.Context, rt *Runtime) error {
		return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, http.NewServeMux())
	}}
	done := make(chan int, 1)
	go func() { done <- Main(ctx, spec, nil, &out, &errOut, apiEnv(nil)) }()
	open := waitFor(t, &out, "public listener open")
	code, body := get(t, "http://"+open["addr"].(string)+"/v1/registry/operators")
	if code != 404 || !strings.Contains(body, `"type":"https://schemas.uspace.ge/problems/not_found"`) || !strings.Contains(body, `"errors":[]`) {
		t.Errorf("public 404: %d %s", code, body)
	}
	if l := waitFor(t, &out, "http request"); l["route"] != "/" {
		t.Errorf("access line route: %v", l)
	}
	if _, body := get(t, "http://"+started2(t, &out)+"/metrics"); !strings.Contains(body, `route="/",server="public"`) {
		t.Errorf("public route label missing: %s", body)
	}
	cancel()
	if code := <-done; code != ExitOK {
		t.Fatalf("exit %d", code)
	}
}

func started2(t *testing.T, out *syncBuffer) string {
	t.Helper()
	return waitFor(t, out, "started")["admin_addr"].(string)
}

func TestPublicBindFailureEndsTheProcessNonZero(t *testing.T) {
	var out, errOut syncBuffer
	cfg := &config.API{}
	spec := Spec{Name: "api", Config: cfg, Run: func(ctx context.Context, rt *Runtime) error {
		return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, http.NewServeMux())
	}}
	code := Main(context.Background(), spec, nil, &out, &errOut, apiEnv(map[string]string{"API_ADDR": "256.0.0.1:1"}))
	if code != ExitFailed {
		t.Fatalf("exit %d", code)
	}
	if l := out.find(t, "process failed"); l == nil || !strings.Contains(l["error"].(string), "public listener") {
		t.Errorf("no failure line naming the listener: %v", out.lines(t))
	}
}

func TestAdminBindFailureExitsNonZero(t *testing.T) {
	var out, errOut syncBuffer
	code := Main(context.Background(), Spec{Name: "api", Config: &config.API{}, Run: Idle("x")}, nil, &out, &errOut, apiEnv(map[string]string{"ADMIN_ADDR": "256.0.0.1:1"}))
	if code != ExitFailed || out.find(t, "admin listener failed") == nil {
		t.Fatalf("exit %d, lines %v", code, out.lines(t))
	}
}

func TestDrainOverrunExitsNonZero(t *testing.T) {
	var out, errOut syncBuffer
	block := make(chan struct{})
	defer close(block)
	ctx, cancel := context.WithCancel(context.Background())
	spec := Spec{Name: "api", Config: &config.API{}, Run: func(context.Context, *Runtime) error {
		<-block // ignores the context: never drains
		return nil
	}}
	done := make(chan int, 1)
	go func() {
		done <- Main(ctx, spec, nil, &out, &errOut, apiEnv(map[string]string{"SHUTDOWN_TIMEOUT_S": "1"}))
	}()
	waitFor(t, &out, "started")
	cancel()
	select {
	case code := <-done:
		if code != ExitFailed {
			t.Fatalf("exit %d, want %d", code, ExitFailed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the drain bound was not enforced")
	}
	if l := out.find(t, "drain exceeded its bound; exiting with work in flight"); l == nil || l["process_drained"] != false {
		t.Errorf("no overrun line: %v", out.lines(t))
	}
}

func TestRunErrorExitsNonZero(t *testing.T) {
	var out, errOut syncBuffer
	spec := Spec{Name: "api", Config: &config.API{}, Run: func(context.Context, *Runtime) error { return errors.New("bus unreachable") }}
	if code := Main(context.Background(), spec, nil, &out, &errOut, apiEnv(nil)); code != ExitFailed {
		t.Fatalf("exit %d", code)
	}
	if l := out.find(t, "process failed"); l == nil || l["error"] != "bus unreachable" {
		t.Errorf("lines: %v", out.lines(t))
	}
}

func TestTracingSetupFailureExitsNonZero(t *testing.T) {
	var out, errOut syncBuffer
	code := Main(context.Background(), Spec{Name: "api", Config: &config.API{}, Run: Idle("x")}, nil, &out, &errOut,
		apiEnv(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://[::1"}))
	// A malformed URL is refused by the config first, naming the variable.
	if code != ExitConfig || !strings.Contains(errOut.b.String(), "OTEL_EXPORTER_OTLP_ENDPOINT") {
		t.Fatalf("exit %d stderr %s", code, errOut.b.String())
	}
}
