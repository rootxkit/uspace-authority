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
	s := spec(&config.Detect{})
	if s.Name != "detect" || s.Run == nil {
		t.Fatalf("spec %+v", s)
	}
	var out, errOut bytes.Buffer
	code := proc.Main(context.Background(), s, nil, &out, &errOut, func(string) (string, bool) { return "", false })
	if code != proc.ExitConfig || !strings.Contains(errOut.String(), "NATS_URL: required") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	out.Reset()
	if code := proc.Main(context.Background(), spec(&config.Detect{}), []string{"--help"}, &out, &errOut, nil); code != proc.ExitOK ||
		!strings.Contains(out.String(), "usage: uspace-authority detect") {
		t.Fatalf("help: %d %s", code, out.String())
	}
}
