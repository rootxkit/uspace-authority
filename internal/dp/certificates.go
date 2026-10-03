package dp

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of the certificate reader (E-09).
const (
	CounterCertificatesReadFailed   = "certificates_read_failed"
	CounterCertificatesMalformed    = "certificates_value_malformed"
	CounterCertificatesUnpublished  = "certificates_not_published"
	CounterCertificatesOlderIgnored = "certificates_older_version_ignored"
)

// CertificateReader follows the certified USSPs api publishes to KV
// bucket certificates (internal/certkv, WP-16). A failed read keeps the
// set held (G-08), counted and logged once a minute; a malformed value
// or an older version is counted and ignored. Until a value is read,
// every Service Provider is provider_unknown, and the status line says
// the register was not read (an empty set never looks like a read one).
type CertificateReader struct {
	Open     func(ctx context.Context) (jetstream.KeyValue, error)
	Timeout  time.Duration
	Counters *core.Counters
	Limiter  *logging.Limiter

	mu   sync.Mutex
	reg  certkv.Register
	set  map[string]bool
	read bool
}

func (c *CertificateReader) inc(name string) {
	if c.Counters != nil {
		c.Counters.Inc(name)
	}
}

// Refresh reads the bucket once.
func (c *CertificateReader) Refresh(ctx context.Context) {
	if c.Open == nil {
		return
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	fail := func(err error) {
		c.inc(CounterCertificatesReadFailed)
		if c.Limiter != nil {
			c.Limiter.Limited("dp_certificates_read").Warn("certified USSPs not read; keeping the set held", slog.String("error", err.Error()))
		}
	}
	kv, err := c.Open(ctx)
	if err != nil {
		fail(err)
		return
	}
	e, err := kv.Get(ctx, certkv.Key)
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound):
		c.inc(CounterCertificatesUnpublished)
		return
	case err != nil:
		fail(err)
		return
	}
	reg, err := certkv.Decode(e.Value())
	if err != nil {
		c.inc(CounterCertificatesMalformed)
		return
	}
	c.Apply(reg)
}

// Apply takes reg unless a higher version is held.
func (c *CertificateReader) Apply(reg certkv.Register) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.read && reg.Version < c.reg.Version {
		c.inc(CounterCertificatesOlderIgnored)
		return false
	}
	c.reg, c.set, c.read = reg, reg.ClientIDs(), true
	return true
}

// Certified is the set of certified owners and whether one was read
// (Engine.Certified).
func (c *CertificateReader) Certified() (map[string]bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.set, c.read
}

// StatusAttrs are the status line's attributes.
func (c *CertificateReader) StatusAttrs() []slog.Attr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.read {
		return []slog.Attr{slog.Bool("certificate_register_read", false)}
	}
	return []slog.Attr{slog.Bool("certificate_register_read", true), slog.Int64("certificate_register_version", c.reg.Version),
		slog.Int("certified_ussps", len(c.reg.USSPs))}
}

// Run refreshes every interval until ctx ends.
func (c *CertificateReader) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		c.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
