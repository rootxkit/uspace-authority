package violations

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
)

// Setup is what api hands to Assemble.
type Setup struct {
	DB          *pg.DB
	Audit       *audit.Writer
	BP          *bus.Process
	Config      config.Violations
	NATSTimeout time.Duration
	Logger      *slog.Logger
	Limiter     *logging.Limiter
}

// Parts are the assembled component.
type Parts struct {
	Service  *Service
	Consumer *Consumer
	Handler  Handler
	Counters *core.Counters
	silent   func(ctx context.Context)
}

// Assemble builds the service, the alrt.v1 consumer and the handler.
func Assemble(s Setup) *Parts {
	counters := &core.Counters{}
	c := s.Config
	svc := &Service{DB: s.DB, Audit: s.Audit, MaxExcerptSamples: c.ViolationsExcerptMaxSamples,
		WriteTimeout: time.Duration(c.ViolationsWriteTimeoutS) * time.Second, Counters: counters, Logger: s.Logger}
	cons := &Consumer{Service: svc, BP: s.BP, Durable: DefaultDurable, MaxAckPending: c.ViolationsMaxAckPending,
		AckWait: time.Duration(c.ViolationsAckWaitS) * time.Second, FetchMax: c.ViolationsFetchMax, Timeout: s.NATSTimeout,
		RetryDelay: time.Duration(c.ViolationsRetryMS) * time.Millisecond, Limiter: s.Limiter}
	p := &Parts{Service: svc, Consumer: cons, Handler: Handler{Service: svc}, Counters: counters}
	p.silent = func(ctx context.Context) {
		RunSilent(ctx, svc, cons, time.Duration(c.ViolationsSilentCheckS)*time.Second,
			time.Duration(c.ViolationsSilentAfterS)*time.Second, c.ViolationsSilentBatch)
	}
	return p
}

// Run consumes alrt.v1 and runs the silent job until ctx ends.
func (p *Parts) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { p.Consumer.Run(ctx) })
	wg.Go(func() { p.silent(ctx) })
	wg.Wait()
}
