package bus

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Defaults of Options.
const (
	DefaultStartAttempts = 3
	DefaultStartBackoff  = 500 * time.Millisecond
	DefaultDialTimeout   = 2 * time.Second
	DefaultReconnectWait = time.Second
)

// Options configure Connect.
type Options struct {
	// URL is NATS_URL.
	URL string
	// Creds is NATS_CREDS, the process's credentials file; empty in the
	// development stack.
	Creds string
	// Name names the connection on the server (uspace-authority-<process>).
	Name string
	// StartAttempts and StartBackoff bound the attempts at start; the
	// backoff doubles after each.
	StartAttempts int
	StartBackoff  time.Duration
	// DialTimeout bounds one attempt.
	DialTimeout time.Duration
	Logger      *slog.Logger
}

func (o Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return logging.Discard()
}

// Connect opens the process's NATS connection (LESSONS B-08): it
// reconnects for ever with jitter; at start it tries StartAttempts times
// with a doubling backoff and then, rather than fail, returns a
// connection that keeps connecting in the background and logs a warning
// that the process starts degraded. It fails only on what no retry
// mends: an unreadable credentials file or a URL the client refuses.
func Connect(ctx context.Context, o Options) (*nats.Conn, error) {
	attempts, backoff, dial := o.StartAttempts, o.StartBackoff, o.DialTimeout
	if attempts <= 0 {
		attempts = DefaultStartAttempts
	}
	if backoff <= 0 {
		backoff = DefaultStartBackoff
	}
	if dial <= 0 {
		dial = DefaultDialTimeout
	}
	logger := o.logger()
	opts := []nats.Option{
		nats.Name(o.Name),
		nats.Timeout(dial),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(DefaultReconnectWait),
		nats.ReconnectJitter(500*time.Millisecond, time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Warn("NATS disconnected; reconnecting", slog.String("error", err.Error()))
			}
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			logger.Info("NATS reconnected", slog.String("server", c.ConnectedUrlRedacted()))
		}),
		nats.ClosedHandler(func(*nats.Conn) { logger.Debug("NATS connection closed") }),
	}
	if o.Creds != "" {
		if _, err := os.Stat(o.Creds); err != nil {
			return nil, &core.FieldError{Field: "NATS_CREDS", Reason: "credentials file unreadable: " + err.Error()}
		}
		opts = append(opts, nats.UserCredentials(o.Creds))
	}
	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		nc, err := nats.Connect(o.URL, opts...)
		if err == nil {
			logger.Info("NATS connected", slog.String("server", nc.ConnectedUrlRedacted()), slog.Int("attempt", attempt))
			return nc, nil
		}
		last = err
		if attempt == attempts {
			break
		}
		logger.Warn("NATS not reachable at start; retrying", slog.Int("attempt", attempt), slog.Int("attempts", attempts),
			slog.Duration("backoff", backoff), slog.String("error", err.Error()))
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	nc, err := nats.Connect(o.URL, append(opts, nats.RetryOnFailedConnect(true))...)
	if err != nil {
		return nil, fmt.Errorf("NATS: %w", err)
	}
	logger.Warn("NATS unreachable at start; starting degraded and reconnecting in the background (B-08)",
		slog.Int("attempts", attempts), slog.String("error", last.Error()))
	return nc, nil
}

// Ready is the readiness check of a connection: an error unless it is
// connected.
func Ready(nc *nats.Conn) func(context.Context) error {
	return func(context.Context) error {
		if s := nc.Status(); s != nats.CONNECTED {
			return fmt.Errorf("NATS %s", s)
		}
		return nil
	}
}

// StatusAttrs puts the connection state on every status line (E-09):
// nats=CONNECTED, RECONNECTING, ...
func StatusAttrs(nc *nats.Conn) func() []slog.Attr {
	return func() []slog.Attr { return []slog.Attr{slog.String("nats", nc.Status().String())} }
}
