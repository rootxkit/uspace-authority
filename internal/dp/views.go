package dp

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of the view reader (E-09).
const (
	CounterViewsReadFailed = "views_read_failed"
	CounterViewsMalformed  = "views_value_malformed"
	CounterConsolesCapped  = "console_keys_over_cap"
)

// ViewReader reads the areas to display from the two buckets
// (internal/dpviews): the oversight areas api publishes and the console
// viewports picture-ws reports. A failed read keeps what it holds
// (G-08), counted and logged once a minute; a malformed value is
// counted and skipped. The console bucket's TTL drops a viewport no
// console reports any more, so an idle console stops polling.
type ViewReader struct {
	Oversight func(ctx context.Context) (jetstream.KeyValue, error)
	Consoles  func(ctx context.Context) (jetstream.KeyValue, error)
	// MaxConsoles bounds the console keys read (E-10).
	MaxConsoles int
	Timeout     time.Duration
	Counters    *core.Counters
	Limiter     *logging.Limiter

	mu        sync.Mutex
	oversight dpviews.Oversight
	consoles  []dpviews.Console
	read      bool
}

func (v *ViewReader) inc(name string) {
	if v.Counters != nil {
		v.Counters.Inc(name)
	}
}

func (v *ViewReader) warn(msg string, err error) {
	v.inc(CounterViewsReadFailed)
	if v.Limiter != nil {
		v.Limiter.Limited("dp_views_read").Warn(msg, slog.String("error", err.Error()))
	}
}

// Refresh reads both buckets once.
func (v *ViewReader) Refresh(ctx context.Context) {
	if v.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, v.Timeout)
		defer cancel()
	}
	if o, ok := v.readOversight(ctx); ok {
		v.mu.Lock()
		v.oversight, v.read = o, true
		v.mu.Unlock()
	}
	if c, ok := v.readConsoles(ctx); ok {
		v.mu.Lock()
		v.consoles = c
		v.mu.Unlock()
	}
}

func (v *ViewReader) readOversight(ctx context.Context) (dpviews.Oversight, bool) {
	if v.Oversight == nil {
		return dpviews.Oversight{}, false
	}
	kv, err := v.Oversight(ctx)
	if err != nil {
		v.warn("oversight areas not read; keeping the areas held", err)
		return dpviews.Oversight{}, false
	}
	e, err := kv.Get(ctx, dpviews.OversightKey)
	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound):
		return dpviews.Oversight{}, true
	case err != nil:
		v.warn("oversight areas not read; keeping the areas held", err)
		return dpviews.Oversight{}, false
	}
	o, err := dpviews.DecodeOversight(e.Value())
	if err != nil {
		v.inc(CounterViewsMalformed)
		return dpviews.Oversight{}, false
	}
	return o, true
}

func (v *ViewReader) readConsoles(ctx context.Context) ([]dpviews.Console, bool) {
	if v.Consoles == nil {
		return nil, false
	}
	kv, err := v.Consoles(ctx)
	if err != nil {
		v.warn("console viewports not read; keeping the viewports held", err)
		return nil, false
	}
	lister, err := kv.ListKeys(ctx)
	if err != nil {
		v.warn("console viewports not listed; keeping the viewports held", err)
		return nil, false
	}
	var keys []string
	for k := range lister.Keys() {
		if !strings.HasPrefix(k, dpviews.ConsoleKeyPrefix) {
			continue
		}
		if v.MaxConsoles > 0 && len(keys) >= v.MaxConsoles {
			v.inc(CounterConsolesCapped)
			continue
		}
		keys = append(keys, k)
	}
	if err := lister.Stop(); err != nil && !errors.Is(err, jetstream.ErrNoKeysFound) {
		v.warn("console viewports not listed; keeping the viewports held", err)
		return nil, false
	}
	var out []dpviews.Console
	for _, k := range keys {
		e, err := kv.Get(ctx, k)
		if err != nil {
			continue // expired between the listing and the read
		}
		c, err := dpviews.DecodeConsole(e.Value())
		if err != nil {
			v.inc(CounterViewsMalformed)
			continue
		}
		out = append(out, c)
	}
	return out, true
}

// Boxes are the areas to display, oversight first.
func (v *ViewReader) Boxes() []Box {
	v.mu.Lock()
	defer v.mu.Unlock()
	boxes := dpviews.Boxes(v.oversight, v.consoles)
	out := make([]Box, 0, len(boxes))
	for _, b := range boxes {
		out = append(out, Box{MinLat: b[1], MinLon: b[0], MaxLat: b[3], MaxLon: b[2]})
	}
	return out
}

// Counts are the oversight areas and console viewports held.
func (v *ViewReader) Counts() (oversight, consoles int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, c := range v.consoles {
		consoles += len(c.BBoxes)
	}
	return len(v.oversight.Areas), consoles
}

// Run refreshes every interval until ctx ends.
func (v *ViewReader) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		v.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
