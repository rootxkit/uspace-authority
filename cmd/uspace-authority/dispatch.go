package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
)

// Processes are the seven long-running processes (docs/PLAN.md §2.1).
var Processes = []string{"api", "rid-ingest", "dp-poller", "manned-ingest", "detect", "tsdb-writer", "picture-ws"}

// libexecDir is where the process binaries are; set at link time in the
// image (-X main.libexecDir=...). Empty means the directory of this
// executable.
var libexecDir = ""

func usage() string {
	return "usage: uspace-authority <process> [--help]\n" +
		"       uspace-authority migrate [--help]\n" +
		"       uspace-authority version\n\n" +
		"processes: " + strings.Join(Processes, ", ") + "\n"
}

func dispatch(ctx context.Context, args []string, stdout, stderr io.Writer, lookup config.LookupFunc) int {
	if len(args) == 0 || slices.Contains([]string{"-h", "--help", "help"}, args[0]) {
		w := stdout
		code := proc.ExitOK
		if len(args) == 0 {
			w, code = stderr, proc.ExitConfig
		}
		_, _ = io.WriteString(w, usage())
		return code
	}
	switch name := args[0]; {
	case name == "version":
		_, _ = io.WriteString(stdout, proc.Version+"\n")
		return proc.ExitOK
	case name == "migrate":
		return runMigrate(ctx, args[1:], stdout, stderr, lookup)
	case slices.Contains(Processes, name):
		return execProcess(name, args[1:], stderr)
	default:
		_, _ = io.WriteString(stderr, "unknown process "+name+"\n\n"+usage())
		return proc.ExitConfig
	}
}

func processPath(name string) (string, error) {
	dir := libexecDir
	if dir == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		dir = filepath.Dir(exe)
	}
	return filepath.Join(dir, name), nil
}

// runMigrate applies both trees, relational first, each under its
// advisory lock, and reports the version each database is at. It is
// the only path that migrates (D7); no long-running process does.
func runMigrate(ctx context.Context, args []string, stdout, stderr io.Writer, lookup config.LookupFunc) int {
	cfg := &config.Migrate{}
	if len(args) > 0 {
		if slices.Contains([]string{"-h", "--help", "help"}, args[0]) {
			_, _ = io.WriteString(stdout, proc.Usage("migrate", cfg))
			return proc.ExitOK
		}
		_, _ = io.WriteString(stderr, "migrate takes no arguments\n")
		return proc.ExitConfig
	}
	if err := config.Load(cfg, lookup); err != nil {
		var fields []string
		for _, fe := range config.FieldErrors(err) {
			fields = append(fields, fe.Field)
		}
		logging.New(stderr, "info", "migrate").Error("configuration invalid",
			slog.Any("fields", fields), slog.String("error", strings.ReplaceAll(err.Error(), "\n", "; ")))
		return proc.ExitConfig
	}
	logger := logging.New(stdout, cfg.LogLevel, "migrate")
	urls := map[string]string{migrate.Relational.Name: cfg.PGURL, migrate.Timeseries.Name: cfg.TSURL}
	for _, tree := range migrate.Trees() {
		db, err := migrate.Open(urls[tree.Name])
		if err != nil {
			logging.Error(ctx, logger, "migrate failed", err, slog.String("tree", tree.Name))
			return proc.ExitFailed
		}
		v, err := migrate.Up(ctx, db, tree, logger)
		_ = db.Close()
		if err != nil {
			logging.Error(ctx, logger, "migrate failed", err, slog.String("tree", tree.Name))
			return proc.ExitFailed
		}
		logger.Info("tree at version", slog.String("tree", tree.Name), slog.String("version_table", tree.VersionTable), slog.Int64("version", v))
	}
	logger.Info("migrations applied")
	return proc.ExitOK
}
