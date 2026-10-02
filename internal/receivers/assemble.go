package receivers

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Setup is what api hands Assemble.
type Setup struct {
	DB         *pg.DB
	Audit      *audit.Writer
	Hasher     *passhash.Hasher
	PIIKeyID   string
	PIIKeyFile string
	// JS is api's JetStream (internal/bus); the connection is api's.
	JS jetstream.JetStream
	// Limits name the key set's KV bucket (RID_KEYSET_BUCKET).
	Limits bus.Limits
	// KVTimeout bounds every key-set operation.
	KVTimeout time.Duration
	TSURL     string
	// TSRole is the role of the raw-frame reads (SELECT only).
	TSRole           string
	TSMaxConns       int
	StatementTimeout time.Duration
	Defaults         Defaults
	RotationGrace    time.Duration
	FramesMaxWindow  time.Duration
	Logger           *slog.Logger
	Limiter          *logging.Limiter
}

// Assembly is the receiver registry of api.
type Assembly struct {
	Service  *Service
	Handler  Handler
	Receiver *ReceiverAPI
	Counters *core.Counters
	// KeyringCounters are the bearer and verifier counters of the two
	// receiver endpoints.
	KeyringCounters *core.Counters
	Readers         *ts.Reader
}

// Close releases the telemetry pool.
func (a *Assembly) Close() {
	if a.Readers != nil {
		a.Readers.Close()
	}
}

// Assemble builds the registry, its key-set projection and the raw-frame
// reads. An unreachable bus does not stop api (B-08): every receiver
// change is then refused with 503 until it returns.
func Assemble(ctx context.Context, s Setup) (*Assembly, error) {
	if err := s.Defaults.Validate(); err != nil {
		return nil, err
	}
	sealer, err := pii.LoadSealer(s.PIIKeyID, s.PIIKeyFile)
	if err != nil {
		return nil, err
	}
	kv := NewKV(s.JS, s.Limits, s.KVTimeout)
	readers, err := ts.OpenReader(ctx, store.PoolOptions{
		URL: s.TSURL, MaxConns: s.TSMaxConns, StatementTimeout: s.StatementTimeout,
		ApplicationName: "uspace-authority-api-rid-frames", Role: s.TSRole,
	})
	if err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	svc := &Service{
		DB: s.DB, Audit: s.Audit, Sealer: sealer, Hasher: s.Hasher, Keys: kv, Defaults: s.Defaults,
		RotationGrace: s.RotationGrace, Counters: counters, Logger: s.Logger,
	}
	krCounters := &core.Counters{}
	kr, err := NewKeyring(KeyringOptions{
		MaxSkew: MaxSkew, NonceMemory: 1024, MaxDatagramBytes: MaxDatagramBytes(MaxHeartbeatBytes),
		HashSlots: 2, HashWait: 250 * time.Millisecond, BadCache: 4096,
	}, s.Hasher, krCounters)
	if err != nil {
		readers.Close()
		return nil, err
	}
	return &Assembly{
		Service:         svc,
		Handler:         Handler{Service: svc, Frames: &Frames{Reader: readers, DB: s.DB, Audit: s.Audit, MaxWindow: s.FramesMaxWindow}},
		Receiver:        &ReceiverAPI{Service: svc, Keyring: kr, Counters: counters, Limiter: s.Limiter},
		Counters:        counters,
		KeyringCounters: krCounters,
		Readers:         readers,
	}, nil
}
