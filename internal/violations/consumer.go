package violations

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// Consumer applies alrt.v1 to the violations table: a durable JetStream
// pull consumer (explicit ack, bounded pending, every message the stream
// holds at its creation), acknowledging a message only after its
// transaction committed (write to the bus or the database, then ack). A
// message that does not decode is terminated and counted; a write that
// fails is redelivered after RetryDelay.
type Consumer struct {
	Service       *Service
	BP            *bus.Process
	Durable       string
	MaxAckPending int
	AckWait       time.Duration
	FetchMax      int
	Timeout       time.Duration
	RetryDelay    time.Duration
	Limiter       *logging.Limiter
	// DeliverPolicy is where a new durable starts: the zero value is
	// every message ALRT holds (7 d), so nothing raised while api was
	// away is lost.
	DeliverPolicy jetstream.DeliverPolicy
}

// DefaultDurable is api's consumer of ALRT.
const DefaultDurable = "api_violations"

func (c *Consumer) warn(key, msg string, attrs ...any) {
	if c.Limiter != nil {
		c.Limiter.Limited(key).Warn(msg, attrs...)
	}
}

func (c *Consumer) consumer(ctx context.Context) (jetstream.Consumer, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	cfg, _ := c.BP.Topology.Stream(bus.StreamALRT)
	s, err := bus.OpenStream(ctx, c.BP.JS, cfg)
	if err != nil {
		return nil, err
	}
	return bus.PullConsumer(ctx, s, bus.PullSpec{Durable: c.Durable, FilterSubject: bus.SubjectAlrtAll,
		MaxAckPending: c.MaxAckPending, AckWait: c.AckWait, DeliverPolicy: c.DeliverPolicy})
}

// CaughtUp reports whether the consumer has nothing pending: the silent
// job closes a violation only when every message detect sent has been
// applied, so a backlog after an api outage is never taken for silence.
func (c *Consumer) CaughtUp(ctx context.Context) (bool, error) {
	cons, err := c.consumer(ctx)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	info, err := cons.Info(ctx)
	if err != nil {
		return false, err
	}
	return info.NumPending == 0 && info.NumAckPending == 0, nil
}

// Handle applies one message's data and settles it.
func (c *Consumer) Handle(ctx context.Context, m jetstream.Msg) {
	v, err := violation.Decode(m.Data())
	if err != nil {
		c.Service.inc(CounterMalformed)
		c.warn("violations_malformed", "alrt.v1 message refused: not stored", slog.String("subject", m.Subject()),
			slog.String("error", err.Error()))
		_ = m.Term()
		return
	}
	if _, err := c.Service.Apply(ctx, v); err != nil {
		c.Service.inc(CounterApplyFailed)
		c.warn("violations_apply_failed", "violation not stored; redelivered", slog.String("violation_id", v.Body.ViolationID),
			slog.String("error", err.Error()))
		_ = m.NakWithDelay(c.RetryDelay)
		return
	}
	_ = m.Ack()
}

// Run consumes until ctx ends, re-establishing the consumer after a
// failure and saying so at a bounded rate (B-08).
func (c *Consumer) Run(ctx context.Context) {
	for ctx.Err() == nil {
		cons, err := c.consumer(ctx)
		if err == nil {
			var it jetstream.MessagesContext
			it, err = cons.Messages(jetstream.PullMaxMessages(max(c.FetchMax, 1)))
			if err == nil {
				stop := context.AfterFunc(ctx, it.Stop)
				for {
					m, nerr := it.Next()
					if nerr != nil {
						err = nerr
						break
					}
					c.Handle(ctx, m)
				}
				stop()
				it.Stop()
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.warn("violations_consumer", "alrt.v1 consumer interrupted; violations wait in JetStream until it is back",
				slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// RunSilent closes, every period, the open violations detect has not
// republished for silentAfter, while the consumer is caught up.
func RunSilent(ctx context.Context, s *Service, c *Consumer, every, silentAfter time.Duration, limit int) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ok, err := c.CaughtUp(ctx)
		if err != nil || !ok {
			continue
		}
		n, err := s.CloseSilent(ctx, silentAfter, limit)
		switch {
		case err != nil && ctx.Err() == nil:
			c.warn("violations_silent", "silent violations not closed; retried next period", slog.String("error", err.Error()))
		case n > 0:
			s.logger().Warn("violations closed detector_silent: detect stopped republishing them", slog.Int("closed", n),
				slog.Float64("silent_after_s", silentAfter.Seconds()))
		}
	}
}
