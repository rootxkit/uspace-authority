package ingest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
	"github.com/rootxkit/uspace-authority/internal/sources"
)

// Options are what Run needs beyond the configuration. A nil Sink is
// the Remote ID pipeline (WP-8, ridpipe.Pipeline); a nil Gate is the
// process's internal/sources follower of the published switches (tests
// give their own). Geoid is the pipeline's geoid; nil is GEOID_FILE's
// grid (internal/ground), and without one the process says its aircraft
// have no AMSL altitude and are not judged vertically.
type Options struct {
	Sink  ridpipe.Sink
	Gate  Gate
	Geoid geoid.Undulator
}

// KeysReady is the readiness check of the receiver key set. With no
// keys the ingest still listens on its configured address (never on a
// loopback no receiver can reach) and refuses every batch; this check
// fails then, naming the refusals counted since start, and passes as
// soon as the key set follower loads a key: no restart is needed.
func KeysReady(kr *receivers.Keyring, counters *core.Counters) func(context.Context) error {
	return func(context.Context) error {
		if kr.Len() > 0 {
			return nil
		}
		return fmt.Errorf("no receiver keys: every batch is refused (%d batches refused with no keys since start); "+
			"a receiver registered in api is accepted without a restart", counters.Get(CounterRefusedNoKeys))
	}
}

// Run is rid-ingest's process body.
func Run(ctx context.Context, rt *proc.Runtime, cfg *config.RIDIngest, o Options) error {
	t := cfg.RIDIngestTuning
	timeout := time.Duration(t.NATSTimeoutMS) * time.Millisecond
	bp, err := bus.OpenProcess(ctx, cfg.NATSURL, cfg.Bus, "rid-ingest", t.KeysetBucket, rt.Logger)
	if err != nil {
		return err
	}
	defer bp.Close()
	conn, js, limits, topo := bp.NC, bp.JS, bp.Limits, bp.Topology
	rt.Ready.Add("nats", bus.Ready(conn))
	kv := receivers.NewKV(js, limits, timeout)

	krCounters := &core.Counters{}
	rt.AddCounters("keyring", krCounters)
	// The parameters come from each stored hash; the defaults size only
	// the dummy of an unknown key.
	hasher, err := passhash.New(passhash.Default())
	if err != nil {
		return err
	}
	kr, err := receivers.NewKeyring(receivers.KeyringOptions{
		MaxSkew: receivers.MaxSkew, NonceMemory: t.NonceMemory,
		MaxDatagramBytes: receivers.MaxDatagramBytes(receivers.MaxBatchBytes),
		HashSlots:        t.KeyCheckSlots, HashWait: 250 * time.Millisecond, BadCache: 4096,
	}, hasher, krCounters)
	if err != nil {
		return err
	}
	n, err := LoadKeyring(ctx, kv, kr)
	switch {
	case errors.Is(err, ErrKeySetInvalid):
		// B-14: an empty or duplicate id, or an entry that does not
		// parse, stops the process rather than serving a partial set.
		return err
	case err != nil:
		rt.Logger.Warn("receiver key set unreadable at start; no receiver can be authenticated until it is",
			slog.String("bucket", t.KeysetBucket), slog.String("error", err.Error()))
	}
	if n == 0 {
		// WP-L6 finding 5: the configured address always. A receiver
		// registered later is picked up by FollowKeySet below; until
		// then every batch is refused, counted and failing /readyz.
		rt.Logger.Warn("no receiver keys: every batch is refused until a receiver is registered; the key set is followed, no restart needed",
			slog.String("addr", cfg.Addr), slog.String("bucket", t.KeysetBucket))
	} else {
		rt.Logger.Info("receiver key set loaded", slog.Int("receivers", n))
	}

	sink, gate := o.Sink, o.Gate
	var runPipeline func(context.Context)
	if sink == nil {
		sink, runPipeline = startPipeline(rt, cfg, bp, o)
	}
	// Source control (WP-10): the follower of the published switches,
	// fed by the KV watch, the push subject and the re-read; with the
	// state unreadable at start every receiver is enabled and the start
	// says so (B-09, SC-08 step 8).
	var followSources func(context.Context)
	if gate == nil {
		var f *sources.Follower
		f, followSources = sources.Follow(ctx, rt, bp, cfg.Bus)
		gate = f
	}

	counters := &core.Counters{}
	rt.AddCounters("rid_ingest", counters)
	rt.Ready.Add("receiver_keys", KeysReady(kr, counters))
	dedupe, err := NewDedupe(time.Duration(t.DedupeWindowS)*time.Second, t.DedupeMaxPerRx, t.MaxReceivers, counters)
	if err != nil {
		return err
	}
	qcfg := QueueConfig{
		MaxBatches: t.QueueMaxBatches, MaxAge: time.Duration(t.QueueMaxAgeS) * time.Second,
		MaxAckPending: t.QueueMaxAckPending, PublishTimeout: timeout,
	}
	ingestStream, _ := topo.Stream(bus.StreamINGEST)
	queue := &JetQueue{JS: js, Config: qcfg, Stream: ingestStream}
	if have, want, ok, err := queue.CheckBound(ctx); err == nil && !ok {
		rt.Logger.Warn("the INGEST stream's hard bound is below the shedding bound plus the batches in flight; receivers are told queue_full before anything is shed",
			slog.Int64("stream_max_msgs", have), slog.Int64("needed", want), slog.String("variable", "BUS_INGEST_MAX_MSGS"))
	}
	status := &Status{
		Keyring: kr, Gate: gate, Pub: conn, StaleAfter: time.Duration(t.StaleAfterS) * time.Second,
		LagAfter: time.Duration(t.LagAfterS) * time.Second, Logger: rt.Logger, Limiter: rt.Limiter, MaxReceivers: t.MaxReceivers,
	}
	worker := &Worker{
		Sink: sink, Store: JetRows{JS: js, Timeout: timeout}, Config: qcfg, Counters: counters, Logger: rt.Logger,
		Limiter: rt.Limiter, Retry: time.Duration(t.StorageRetryMS) * time.Millisecond, OnShed: status.Shed, OnStored: status.Stored,
	}
	status.Depth = worker.Depth
	rt.AddStatus(func() []slog.Attr {
		return []slog.Attr{
			slog.Int("receivers", kr.Len()), slog.Uint64("queue_depth", worker.Depth()),
			slog.Uint64("nonces_evicted", kr.NoncesEvicted()),
		}
	})
	h := &Handler{
		Keyring: kr, Gate: gate, Dedupe: dedupe, Queue: queue, Status: status,
		DisabledRetryAfter: time.Duration(t.DisabledRetryAfterS) * time.Second,
		QueueRetryAfter:    time.Duration(t.QueueRetryAfterS) * time.Second,
		LabHeadersAllowed:  t.LabHeadersAllowed,
		Counters:           counters, Limiter: rt.Limiter,
	}
	if t.LabHeadersAllowed {
		rt.Logger.Warn("lab scenario batches are admitted (LAB_HEADERS_ALLOWED=true); allowed only in the lab and the scenario harness",
			slog.String("header", receivers.LabScenarioHeader))
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() {
		FollowKeySet(ctx, kv, kr, time.Duration(t.KeysetRereadS)*time.Second, rt.Logger, rt.Limiter)
	})
	if followSources != nil {
		wg.Go(func() { followSources(ctx) })
	}
	if runPipeline != nil {
		wg.Go(func() { runPipeline(ctx) })
	}
	wg.Go(func() { worker.Run(ctx, queue.EnsureQueue) })
	wg.Go(func() { status.Run(ctx, time.Duration(t.StatusIntervalMS)*time.Millisecond) })

	mux := http.NewServeMux()
	h.Mount(mux)
	return rt.ServePublic(ctx, cfg.HTTP, cfg.Addr, mux)
}
