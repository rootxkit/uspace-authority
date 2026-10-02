// Command rid-ingest is the F9 Remote ID receiver ingest (WP-7): it
// authenticates signed observation batches from the receivers registered
// in api (bearer key, then uspace-core's HMAC, 30 s window and nonce
// memory), refuses a disabled receiver with 503 and Retry-After, keeps a
// 60 s dedupe window per receiver, acknowledges a batch (202) only after
// it is written to the JetStream work queue ingest.v1.<cell3>, drains
// that queue into the Remote ID pipeline (WP-8: decode, identity, time,
// altitude, identification against the registry projection, tracks on
// trk.v1 and ident.v1) and hands every raw frame to tsdb-writer
// (tsw.v1.rid_observations, the tracks on tsw.v1.tracks), shedding the
// oldest with a writer_gaps record when the queue is past its bound, and
// publishes src.v1.direct_rid.<receiver> every 2 s. With no receiver keys it listens
// on loopback only. It is started as `uspace-authority rid-ingest`;
// --help lists the configuration variables, and
// docs/runbooks/receivers.md is the receiver contract.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers/ingest"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.RIDIngest{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.RIDIngest) proc.Spec {
	return specWith(cfg, ingest.Options{})
}

// specWith is spec with the decode pipeline and the source-control gate
// given (tests).
func specWith(cfg *config.RIDIngest, o ingest.Options) proc.Spec {
	return proc.Spec{Name: "rid-ingest", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return ingest.Run(ctx, rt, cfg, o)
	}}
}
