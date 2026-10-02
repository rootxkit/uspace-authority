package ingest

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// Options are what Run needs beyond the configuration: the decode
// pipeline (WP-8) and the source-control follower (WP-10). Nil members
// take the stand-ins this work package ships: ridpipe.Undecoded, and a
// sources.Follower that nothing feeds, so every receiver is enabled by
// source control (B-09: never fail closed) and the start line says so.
type Options struct {
	Sink ridpipe.Sink
	Gate Gate
}

// LoopbackAddr replaces addr's host with 127.0.0.1 (R-06: an ingest
// without receiver keys can authenticate nobody and listens on loopback).
func LoopbackAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = "0"
	}
	return net.JoinHostPort("127.0.0.1", port)
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
	addr := cfg.Addr
	if n == 0 {
		addr = LoopbackAddr(cfg.Addr)
		rt.Logger.Warn("no receiver keys: listening on loopback only (R-06); restart once receivers are registered",
			slog.String("configured_addr", cfg.Addr), slog.String("addr", addr))
	} else {
		rt.Logger.Info("receiver key set loaded", slog.Int("receivers", n))
	}

	sink, gate := o.Sink, o.Gate
	if sink == nil {
		c := &core.Counters{}
		rt.AddCounters("pipeline", c)
		sink = ridpipe.Undecoded{Counters: c}
		rt.Logger.Warn("no decode pipeline in this build (WP-8): observations are stored raw and no track is published")
	}
	if gate == nil {
		f := sources.NewFollower()
		rt.AddCounters("source_control", f.Counters())
		gate = f
		rt.Logger.Warn("source control state unknown: no follower feed in this build (WP-10); every receiver is enabled by source control, registry disables still apply",
			slog.String("source_type", SourceType))
	}

	counters := &core.Counters{}
	rt.AddCounters("rid_ingest", counters)
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
		Counters:           counters, Limiter: rt.Limiter,
	}

	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() {
		FollowKeySet(ctx, kv, kr, time.Duration(t.KeysetRereadS)*time.Second, rt.Logger, rt.Limiter)
	})
	wg.Go(func() { worker.Run(ctx, queue.EnsureQueue) })
	wg.Go(func() { status.Run(ctx, time.Duration(t.StatusIntervalMS)*time.Millisecond) })

	mux := http.NewServeMux()
	h.Mount(mux)
	return rt.ServePublic(ctx, cfg.HTTP, addr, mux)
}
