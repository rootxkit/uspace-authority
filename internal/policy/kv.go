package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// The active policy on the bus (docs/PLAN.md §6, INV-03): KV bucket
// policy, key "active", pushed on ctl.policy, in the 04 §2 envelope with
// body policy/active/v1 (schemas/policy/active/v1.json). api writes it;
// detect follows it (WP-12).
const (
	ActiveSchema = "policy/active/v1"
	ActiveKey    = "active"
)

// Counters of the bus side.
const (
	CounterKVPublished    = "policy_kv_published"     // the active policy written to KV policy
	CounterKVRepaired     = "policy_kv_repaired"      // the bucket held another version and was rewritten
	CounterKVMalformed    = "policy_kv_malformed"     // a value or push that does not decode; the policy held stays
	CounterKVReadFailed   = "policy_kv_read_failed"   // the bucket could not be read; the policy held stays
	CounterKVNotPublished = "policy_kv_not_published" // the bucket holds no policy yet
)

// ActiveBody is the body of policy/active/v1: the version and every
// threshold of the active policy.
type ActiveBody struct {
	Version int64 `json:"version"`
	Thresholds
	ActivatedAt *time.Time `json:"activated_at"`
}

// Encode wraps p for the bucket and the push.
func Encode(p Policy, producer string, now time.Time) ([]byte, error) {
	return json.Marshal(bus.SystemEnvelope(ActiveSchema, producer, now, ActiveBody{
		Version: p.Version, Thresholds: p.Thresholds, ActivatedAt: p.ActivatedAt,
	}))
}

// Decode reads a value of the bucket or the push. A value of another
// schema, a version below 1 or thresholds that do not validate are
// refused, naming the field: a follower never takes them (E-15).
func Decode(raw []byte) (Policy, error) {
	var env bus.Envelope[ActiveBody]
	// A value an api older than WP-26 wrote has no no_authorisation
	// members: it carries their defaults, as migration 00024 gave every
	// stored version, rather than being refused for a zero grace.
	env.Body.NoAuthorisationGraceS = DefaultNoAuthorisationGraceS
	env.Body.NoAuthorisationSeverity = DefaultNoAuthorisationSeverity
	if err := json.Unmarshal(raw, &env); err != nil {
		return Policy{}, &core.FieldError{Field: "body", Reason: "not a policy/active/v1 message"}
	}
	if env.Schema != ActiveSchema {
		return Policy{}, core.Fieldf("schema", "%q, want %s", env.Schema, ActiveSchema)
	}
	if env.Body.Version < 1 {
		return Policy{}, &core.FieldError{Field: "body.version", Reason: "must be at least 1"}
	}
	if err := env.Body.Validate(); err != nil {
		return Policy{}, err
	}
	return Policy{Version: env.Body.Version, Thresholds: env.Body.Thresholds, Active: true, ActivatedAt: env.Body.ActivatedAt}, nil
}

// KV is where the active policy lives on the bus.
type KV struct {
	// Open returns the bucket (bus.OpenBucket of the policy bucket).
	Open func(ctx context.Context) (jetstream.KeyValue, error)
	// Conn and Subject are the push (ctl.policy); a nil Conn has none.
	Conn    *nats.Conn
	Subject string
	// Timeout bounds one read or write.
	Timeout  time.Duration
	Producer string
	Counters *core.Counters
	Now      func() time.Time
}

// KVOf is the policy bucket and push of a process's bus.
func KVOf(bp *bus.Process, timeout time.Duration, producer string, counters *core.Counters) KV {
	cfg, _ := bp.Topology.Bucket(bus.BucketPolicy)
	return KV{
		Open:    func(ctx context.Context) (jetstream.KeyValue, error) { return bus.OpenBucket(ctx, bp.JS, cfg) },
		Conn:    bp.NC,
		Subject: bus.SubjectCtlPolicy,
		Timeout: timeout, Producer: producer, Counters: counters,
	}
}

func (k KV) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

func (k KV) inc(name string) {
	if k.Counters != nil {
		k.Counters.Inc(name)
	}
}

func (k KV) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if k.Timeout > 0 {
		return context.WithTimeout(ctx, k.Timeout)
	}
	return context.WithCancel(ctx)
}

// Read is the policy the bucket holds; published is false when it holds
// none.
func (k KV) Read(ctx context.Context) (p Policy, published bool, err error) {
	ctx, cancel := k.bounded(ctx)
	defer cancel()
	kv, err := k.Open(ctx)
	if err != nil {
		return Policy{}, false, err
	}
	e, err := kv.Get(ctx, ActiveKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, err
	}
	p, err = Decode(e.Value())
	if err != nil {
		k.inc(CounterKVMalformed)
		return Policy{}, false, err
	}
	return p, true, nil
}

// PublishPolicy writes p to the bucket, then pushes it on the subject
// (the write first: a follower that misses the push finds it on its
// re-read). It is a Publisher.
func (k KV) PublishPolicy(ctx context.Context, p Policy) error {
	data, err := Encode(p, k.Producer, k.now())
	if err != nil {
		return err
	}
	ctx, cancel := k.bounded(ctx)
	defer cancel()
	kv, err := k.Open(ctx)
	if err != nil {
		return fmt.Errorf("policy bucket: %w", err)
	}
	if _, err := kv.Put(ctx, ActiveKey, data); err != nil {
		return fmt.Errorf("policy bucket: %w", err)
	}
	k.inc(CounterKVPublished)
	if k.Conn != nil && k.Subject != "" {
		if err := k.Conn.Publish(k.Subject, data); err != nil {
			return fmt.Errorf("policy push: %w", err)
		}
	}
	return nil
}

// Repair writes p when the bucket holds another version or none (G-08:
// the projection is repaired periodically, so a lost bucket or a failed
// publish at activation is put right within one period).
func (k KV) Repair(ctx context.Context, p Policy) error {
	held, published, err := k.Read(ctx)
	if err == nil && published && held.Version == p.Version {
		return nil
	}
	if err := k.PublishPolicy(ctx, p); err != nil {
		return err
	}
	k.inc(CounterKVRepaired)
	return nil
}

// Publishers announces to each in turn and returns every error.
type Publishers []Publisher

// PublishPolicy implements Publisher.
func (ps Publishers) PublishPolicy(ctx context.Context, p Policy) error {
	var errs []error
	for _, pub := range ps {
		if err := pub.PublishPolicy(ctx, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RunRepair writes the policy f holds to the bucket at once and every
// period until ctx ends, whenever the bucket holds another (api).
func (k KV) RunRepair(ctx context.Context, f *Follower, every time.Duration, lim *logging.Limiter) {
	// repair reports whether the bucket holds the policy f holds; until
	// it does (no policy read yet, the bus down) it is tried every second.
	repair := func() bool {
		p, ok := f.Current()
		if !ok {
			return false
		}
		if err := k.Repair(ctx, p); err != nil {
			if ctx.Err() == nil && lim != nil {
				lim.Limited("policy_kv_repair").Warn("active policy not written to the policy bucket; followers keep the one they hold",
					slog.Int64("policy_version", p.Version), slog.String("error", err.Error()))
			}
			return false
		}
		return true
	}
	for {
		wait := every
		if !repair() {
			wait = min(every, time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Follow keeps f on the bucket's policy by the watch, the push and a
// re-read every period, until ctx ends (G-08, INV-03). A value that does
// not decode, or validate, is counted and the policy held stays; a
// lower version is ignored by f.
func (k KV) Follow(ctx context.Context, f *Follower, every time.Duration, logger *slog.Logger) {
	if logger == nil {
		logger = logging.Discard()
	}
	apply := func(p Policy) {
		if f.Apply(p) {
			logger.Info("policy applied", slog.Int64("policy_version", p.Version))
		}
	}
	reload := func(ctx context.Context) {
		p, published, err := k.Read(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				k.inc(CounterKVReadFailed)
				logger.Debug("policy bucket not read; keeping the policy held", slog.String("error", err.Error()))
			}
		case !published:
			k.inc(CounterKVNotPublished)
		default:
			apply(p)
		}
	}
	reload(ctx)
	bus.Follow{
		Open: k.Open, Key: ActiveKey, Conn: k.Conn, Subject: k.Subject,
		OnValue: func(raw []byte) {
			p, err := Decode(raw)
			if err != nil {
				k.inc(CounterKVMalformed)
				return
			}
			apply(p)
		},
		Reload: reload, Reread: every, Logger: logger,
	}.Run(ctx)
}
