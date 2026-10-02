// Command tsdb-writer is the only writer of the telemetry hypertables
// (WP-9, spec 05 §5). For every table it writes (rid_observations, and
// the tables later WPs register in internal/store/ts) it reads
// tsw.v1.<table> with a durable JetStream pull consumer (explicit ack,
// bounded max_ack_pending), queues the rows in a bounded in-memory queue
// (10 s of rows), writes batches of at most 1000 rows or every 500 ms
// with COPY into a staging table and INSERT .. ON CONFLICT DO NOTHING on
// the table's dedupe key, and acknowledges each message only after its
// transaction commits (B-05). At the queue's bound it stops pulling and
// the status line says spilling; the rows wait in the TSW stream. It
// records every hole it knows of in writer_gaps: rid-ingest's shed
// batches (tsw.v1.writer_gaps), TSW messages the stream aged out before
// they were written, unreadable messages and rows the database refused.
// It starts with NATS or the database down and says so; it stops on a
// schema older than it needs. Every hour it checks that the tables with
// a retention period hold nothing older. It is started as
// `uspace-authority tsdb-writer`; --help lists the configuration
// variables, and docs/runbooks/tsdb-writer.md says what an operator does
// about each state.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/tswriter"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := proc.Main(ctx, spec(&config.TSDBWriter{}), os.Args[1:], os.Stdout, os.Stderr, os.LookupEnv)
	stop()
	os.Exit(code)
}

func spec(cfg *config.TSDBWriter) proc.Spec {
	return specWith(cfg, tswriter.Options{})
}

// specWith is spec with the tables and retention checks given (tests).
func specWith(cfg *config.TSDBWriter, o tswriter.Options) proc.Spec {
	return proc.Spec{Name: "tsdb-writer", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return tswriter.Run(ctx, rt, cfg, o)
	}}
}
