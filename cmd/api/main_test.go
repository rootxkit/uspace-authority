package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

func TestSpecNamesTheProcessAndRefusesAnEmptyEnvironment(t *testing.T) {
	s := spec(&config.API{})
	if s.Name != "api" || s.Run == nil {
		t.Fatalf("spec %+v", s)
	}
	var out, errOut bytes.Buffer
	code := proc.Main(context.Background(), s, nil, &out, &errOut, func(string) (string, bool) { return "", false })
	if code != proc.ExitConfig || !strings.Contains(errOut.String(), "NATS_URL: required") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	out.Reset()
	if code := proc.Main(context.Background(), spec(&config.API{}), []string{"--help"}, &out, &errOut, nil); code != proc.ExitOK ||
		!strings.Contains(out.String(), "usage: uspace-authority api") {
		t.Fatalf("help: %d %s", code, out.String())
	}
}

// E-02: started with the relational database absent, api exits non-zero
// and says which dependency failed, rather than serving an empty API.
func TestStartWithoutTheDatabaseFailsAndSaysWhich(t *testing.T) {
	m := map[string]string{
		"PG_URL": "postgres://u:p@127.0.0.1:1/absent?connect_timeout=2", "TS_URL": "postgres://u:p@127.0.0.1:1/ts",
		"NATS_URL": "nats://127.0.0.1:1", "AUTHORITY_PUBLIC_URL": "http://localhost:8080",
		"API_ADDR": "127.0.0.1:0", "ADMIN_ADDR": "127.0.0.1:0", "SHUTDOWN_TIMEOUT_S": "2",
		"SIGNING_KEY_FILES": "/nonexistent/token-1.pem",
	}
	var out, errOut bytes.Buffer
	code := proc.Main(context.Background(), spec(&config.API{}), nil, &out, &errOut, func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	if code != proc.ExitFailed || !strings.Contains(out.String(), "relational database") || !strings.Contains(out.String(), "process failed") {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if strings.Contains(out.String(), "u:p@") {
		t.Fatalf("the URL with its password reached the log: %s", out.String())
	}
}

// E-02: the issuer with no key configured refuses to start, naming the
// variable, before it touches anything.
func TestStartWithoutASigningKeyNamesTheVariable(t *testing.T) {
	m := map[string]string{
		"PG_URL": "postgres://u:p@127.0.0.1:1/absent", "TS_URL": "postgres://u:p@127.0.0.1:1/ts",
		"NATS_URL": "nats://127.0.0.1:1", "AUTHORITY_PUBLIC_URL": "http://localhost:8080",
	}
	var out, errOut bytes.Buffer
	code := proc.Main(context.Background(), spec(&config.API{}), nil, &out, &errOut, func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	if code != proc.ExitConfig || !strings.Contains(errOut.String(), "SIGNING_KEY_FILES: required") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}
