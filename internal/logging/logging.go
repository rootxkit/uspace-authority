package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// New returns a JSON logger writing to w at level ("debug", "info",
// "warn", "error"; anything else is info) with the process name on every
// line.
func New(w io.Writer, level, process string) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: ParseLevel(level)})
	return slog.New(h).With(slog.String("process", process))
}

// ParseLevel maps a configuration value onto a slog level.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Discard is a logger that writes nothing, for tests and defaults.
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// errorAttr is the conventional attribute for an error.
func errorAttr(err error) slog.Attr { return slog.String("error", err.Error()) }

// Error logs msg at error level with err.
func Error(ctx context.Context, l *slog.Logger, msg string, err error, attrs ...slog.Attr) {
	l.LogAttrs(ctx, slog.LevelError, msg, append([]slog.Attr{errorAttr(err)}, attrs...)...)
}
