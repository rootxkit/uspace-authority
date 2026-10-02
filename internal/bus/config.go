package bus

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/config"
)

// ConnectProcess is Connect with a process's configuration: the
// connection is named uspace-authority-<process>.
func ConnectProcess(ctx context.Context, url string, c config.Bus, process string, logger *slog.Logger) (*nats.Conn, error) {
	return Connect(ctx, Options{
		URL: url, Creds: c.NATSCreds, Name: "uspace-authority-" + process,
		StartAttempts: c.NATSStartAttempts, StartBackoff: time.Duration(c.NATSStartBackoffMS) * time.Millisecond,
		DialTimeout: time.Duration(c.NATSTimeoutMS) * time.Millisecond, Logger: logger,
	})
}

// LimitsOf are the topology bounds of a process's configuration;
// ridKeysBucket is RID_KEYSET_BUCKET where the process reads it (empty
// is the default name).
func LimitsOf(c config.Bus, ridKeysBucket string) (Limits, error) {
	storage, err := ParseStorage(c.BusTRKStorage)
	if err != nil {
		return Limits{}, err
	}
	return Limits{
		TRKStorage: storage, IngestMaxMsgs: int64(c.BusIngestMaxMsgs),
		SourceControlBucket: c.SourceControlBucket, SourceControlValueBytes: int32(c.SourceControlMaxValueBytes),
		RIDReceiverKeysBucket: ridKeysBucket,
	}, nil
}

// Process is a process's bus: its connection, JetStream, and the
// topology under its configuration.
type Process struct {
	NC       *nats.Conn
	JS       jetstream.JetStream
	Limits   Limits
	Topology Topology
}

// OpenProcess connects (ConnectProcess) and binds JetStream and the
// topology; ridKeysBucket is RID_KEYSET_BUCKET where the process reads it.
func OpenProcess(ctx context.Context, url string, c config.Bus, process, ridKeysBucket string, logger *slog.Logger) (*Process, error) {
	limits, err := LimitsOf(c, ridKeysBucket)
	if err != nil {
		return nil, err
	}
	nc, err := ConnectProcess(ctx, url, c, process, logger)
	if err != nil {
		return nil, err
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	return &Process{NC: nc, JS: js, Limits: limits, Topology: NewTopology(limits)}, nil
}

// Close closes the connection.
func (p *Process) Close() { p.NC.Close() }
