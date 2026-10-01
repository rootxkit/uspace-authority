package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/proc"
)

func noEnv(string) (string, bool) { return "", false }

func TestUsageAndHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch(context.Background(), nil, &out, &errOut, noEnv); code != proc.ExitConfig || !strings.Contains(errOut.String(), "processes: api, rid-ingest") {
		t.Fatalf("no args: %d %q", code, errOut.String())
	}
	out.Reset()
	if code := dispatch(context.Background(), []string{"--help"}, &out, &errOut, noEnv); code != proc.ExitOK || !strings.Contains(out.String(), "uspace-authority migrate") {
		t.Fatalf("--help: %d %q", code, out.String())
	}
	errOut.Reset()
	if code := dispatch(context.Background(), []string{"nope"}, &out, &errOut, noEnv); code != proc.ExitConfig || !strings.Contains(errOut.String(), "unknown process nope") {
		t.Fatalf("unknown: %d %q", code, errOut.String())
	}
	out.Reset()
	if code := dispatch(context.Background(), []string{"version"}, &out, &errOut, noEnv); code != proc.ExitOK || strings.TrimSpace(out.String()) != proc.Version {
		t.Fatalf("version: %d %q", code, out.String())
	}
}

func TestMigrateHelpAndConfigErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch(context.Background(), []string{"migrate", "--help"}, &out, &errOut, noEnv); code != proc.ExitOK || !strings.Contains(out.String(), "TS_URL (required; secret)") {
		t.Fatalf("help: %d %q", code, out.String())
	}
	if code := dispatch(context.Background(), []string{"migrate", "down"}, &out, &errOut, noEnv); code != proc.ExitConfig {
		t.Fatalf("extra argument: %d", code)
	}
	errOut.Reset()
	code := dispatch(context.Background(), []string{"migrate"}, &out, &errOut, noEnv)
	if code != proc.ExitConfig || !strings.Contains(errOut.String(), `"fields":["PG_URL","TS_URL"]`) {
		t.Fatalf("no config: %d %q", code, errOut.String())
	}
}

func TestMigrateReportsAnUnreachableDatabase(t *testing.T) {
	env := map[string]string{"PG_URL": "postgres://u:p@127.0.0.1:1/rel?connect_timeout=2", "TS_URL": "postgres://u:p@127.0.0.1:1/ts?connect_timeout=2"}
	var out, errOut bytes.Buffer
	code := dispatch(context.Background(), []string{"migrate"}, &out, &errOut, func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if code != proc.ExitFailed || !strings.Contains(out.String(), `"msg":"migrate failed"`) || !strings.Contains(out.String(), `"tree":"relational"`) {
		t.Fatalf("got %d %q", code, out.String())
	}
	if strings.Contains(out.String(), "u:p@") {
		t.Errorf("the database URL leaked into the log: %s", out.String())
	}
}

func TestProcessThatIsNotInstalledFailsNamingIt(t *testing.T) {
	prev := libexecDir
	t.Cleanup(func() { libexecDir = prev })
	libexecDir = t.TempDir()
	var out, errOut bytes.Buffer
	if code := dispatch(context.Background(), []string{"detect"}, &out, &errOut, noEnv); code != proc.ExitFailed || !strings.Contains(errOut.String(), "cannot start detect") {
		t.Fatalf("got %d %q", code, errOut.String())
	}
}

func TestProcessPathDefaultsToTheExecutableDirectory(t *testing.T) {
	prev := libexecDir
	t.Cleanup(func() { libexecDir = prev })
	libexecDir = ""
	p, err := processPath("api")
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if filepath.Dir(p) != filepath.Dir(exe) || filepath.Base(p) != "api" {
		t.Fatalf("got %s", p)
	}
	if runtime.GOOS == "windows" {
		t.Log("on Windows the process is run as a child; the image is Linux and uses exec(2)")
	}
}
