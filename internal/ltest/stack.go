package ltest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/sources/switches"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Options configure a Stack.
type Options struct {
	// Name is the scenario's id (SC-07, smoke, ...): the results file is
	// named after it, and every bucket, durable and receiver of the run
	// carries it.
	Name string
	// Policy, when set, is created and activated as a new policy version
	// before any process starts; nil publishes the active version the
	// migration seeds (version 1, policy.Defaults(): the documented
	// defaults, pending GCAA where the plan says so). A scenario never
	// relaxes a threshold to pass (INV-03).
	Policy *policy.Thresholds
	// NoPolicy publishes no policy at all (the processes judge with the
	// defaults as policy_version 0 and say so).
	NoPolicy bool
}

// Stack is one scenario's world: scratch databases of both trees
// migrated from scratch on the service containers (PG_URL, TS_URL), the
// bus provisioned on NATS (NATS_URL) with every stream of the topology
// recreated empty, a policy, and the processes the scenario starts. It
// runs only with INTEGRATION=1 and otherwise skips, saying why. Stacks
// of one package run one after another (the streams are shared).
type Stack struct {
	T    testing.TB
	Name string
	// NATSURL, PGURL and TSURL are the bus and the scratch databases.
	NATSURL, PGURL, TSURL string
	// BP is the harness's own connection (provisioning, publishing the
	// projection versions, the recorder's subscriptions).
	BP *bus.Process
	// PGAdmin and TSAdmin are superuser handles on the scratch
	// databases, for reading back what the processes wrote.
	PGAdmin, TSAdmin *sql.DB
	// RIDKeysBucket and SourceBucket are this run's buckets.
	RIDKeysBucket, SourceBucket string
	// Rec records trk.v1, man.v1, alrt.v1 and src.v1 from the start.
	Rec *Recorder

	busCfg   config.Bus
	started  time.Time
	unique   string
	mu       sync.Mutex
	zonesVer int64
	regVer   int64
	pg       *pgstore.DB
	proj     *ts.Projector
	switches *switches.Service
	procs    []*Proc
	sims     []*Receiver
	store    *ViolationStore
	expected []Expect
	verified *Report
	extra    map[string]any
}

// New builds the stack, or skips the test without INTEGRATION=1.
func New(t testing.TB, o Options) *Stack {
	t.Helper()
	if o.Name == "" {
		t.Fatal("ltest.New: a scenario needs a name")
	}
	natsURL := bustest.URL(t)
	s := &Stack{T: t, Name: o.Name, NATSURL: natsURL, started: time.Now().UTC(), extra: map[string]any{}}
	s.unique = strings.ToLower(token(o.Name)) + "_" + bustest.Name("r")
	s.RIDKeysBucket = "rid_keys_" + s.unique
	s.SourceBucket = "source_control_" + s.unique
	s.busCfg = config.Bus{
		BusTRKStorage: "memory", BusIngestMaxMsgs: bus.DefaultIngestMaxMsgs, SourceControlBucket: s.SourceBucket,
		SourceControlSubject: bus.SubjectCtlSources, SourceControlMaxValueBytes: bus.DefaultSourceControlValueBytes,
		SourceControlRereadS: 1, NATSStartAttempts: 3, NATSStartBackoffMS: 100, NATSTimeoutMS: 2000,
	}

	// Both trees from scratch (D7: nothing migrates at start).
	s.PGURL = storetest.Migrated(t, migrate.Relational)
	s.TSURL = storetest.Migrated(t, migrate.Timeseries)
	s.PGAdmin = storetest.Open(t, s.PGURL)
	s.TSAdmin = storetest.Open(t, s.TSURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bp, err := bus.OpenProcess(ctx, natsURL, s.busCfg, "ltest", s.RIDKeysBucket, nil)
	if err != nil {
		t.Fatalf("ltest: bus: %v", err)
	}
	t.Cleanup(bp.Close)
	s.BP = bp
	// Every stream recreated empty: a batch, a track or a violation
	// left by an earlier scenario must never be read as this one's.
	for i := range bp.Topology.Streams {
		name := bp.Topology.Streams[i].Name
		if err := bp.JS.DeleteStream(ctx, name); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
			t.Fatalf("ltest: delete stream %s: %v", name, err)
		}
	}
	if _, err := bus.Ensure(ctx, bp.JS, bp.Topology, nil); err != nil {
		t.Fatalf("ltest: provision the bus: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		_ = bp.JS.DeleteKeyValue(dctx, s.RIDKeysBucket)
		_ = bp.JS.DeleteKeyValue(dctx, s.SourceBucket)
	})
	s.Rec = NewRecorder(t, bp.NC, DefaultRecorderMax)

	switch {
	case o.NoPolicy:
	case o.Policy != nil:
		s.SetPolicy(*o.Policy)
	default:
		s.publishActivePolicy()
	}
	// Results are written whatever the outcome; registered first, so it
	// runs after every process has stopped and been read (cleanups run
	// last-in first-out).
	t.Cleanup(s.writeResults)
	return s
}

// token is s reduced to one bus-name token.
func token(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Unique is a name unique to this run with prefix, valid as a bus token.
func (s *Stack) Unique(prefix string) string { return token(prefix) + "_" + s.unique }

// ReceiverID is a receiver id unique to this run with prefix, valid as
// a receiver id (lower case, digits and hyphens, at most 63).
func (s *Stack) ReceiverID(prefix string) string {
	id := strings.ToLower(strings.ReplaceAll(token(prefix)+"-"+s.unique, "_", "-"))
	if len(id) > 63 {
		id = id[len(id)-63:]
		id = strings.TrimLeft(id, "-")
	}
	return id
}

// BusEnv is the bus configuration every process of the stack starts
// with: this run's NATS and buckets.
func (s *Stack) BusEnv() map[string]string {
	return map[string]string{
		"NATS_URL": s.NATSURL, "BUS_TRK_STORAGE": s.busCfg.BusTRKStorage,
		"SOURCE_CONTROL_BUCKET": s.SourceBucket, "SOURCE_CONTROL_REREAD_S": "1",
		"NATS_START_ATTEMPTS": "3", "NATS_START_BACKOFF_MS": "100",
	}
}

// PG is api's pool on the relational database (the application role),
// opened on first use.
func (s *Stack) PG() *pgstore.DB {
	s.T.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pg == nil {
		db, err := pgstore.Open(context.Background(), store.PoolOptions{URL: s.PGURL, Role: pgstore.AppRole, ApplicationName: "uspace-authority-ltest-api"})
		if err != nil {
			s.T.Fatalf("ltest: relational pool: %v", err)
		}
		s.T.Cleanup(db.Close)
		s.pg = db
	}
	return s.pg
}

// projector is api's pool on the projection tables, opened on first use.
func (s *Stack) projector() *ts.Projector {
	s.T.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.proj == nil {
		p, err := ts.OpenProjector(context.Background(), store.PoolOptions{URL: s.TSURL, ApplicationName: "uspace-authority-ltest-projector"})
		if err != nil {
			s.T.Fatalf("ltest: projector pool: %v", err)
		}
		s.T.Cleanup(p.Close)
		s.proj = p
	}
	return s.proj
}

// policyService is api's policy service on the stack's relational
// database, publishing to KV policy and ctl.policy.
func (s *Stack) policyService() *policy.Service {
	db := s.PG()
	kv := policy.KVOf(s.BP, 5*time.Second, "authority/api", &core.Counters{})
	return &policy.Service{DB: db, Audit: audit.NewWriter(db), Publisher: kv, Logger: logging.Discard(), Counters: &core.Counters{}}
}

// publishActivePolicy publishes the active version (the migration's
// seeded version 1, the documented defaults) to KV policy, as api's
// repair loop does at its start.
func (s *Stack) publishActivePolicy() {
	s.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	svc := s.policyService()
	p, err := svc.Active(ctx)
	if err != nil {
		s.T.Fatalf("ltest: active policy: %v", err)
	}
	if err := svc.Publisher.PublishPolicy(ctx, p); err != nil {
		s.T.Fatalf("ltest: publish policy version %d: %v", p.Version, err)
	}
	s.Note(fmt.Sprintf("policy_v%d", p.Version), p.Thresholds)
}

// SetPolicy creates th as a new policy version and activates it through
// api's policy service (internal/policy: the row, its events rows, then
// the KV publication), and returns the version. Thresholds are a
// scenario's subject, never loosened to make it pass (INV-03).
func (s *Stack) SetPolicy(th policy.Thresholds) int64 {
	s.T.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	svc := s.policyService()
	actor := audit.Actor{Type: audit.ActorUser, ID: "ltest-admin", Realm: "console"}
	p, err := svc.Create(ctx, th, "scenario "+s.Name, actor)
	if err != nil {
		s.T.Fatalf("ltest: create policy: %v", err)
	}
	if _, err := svc.Activate(ctx, p.Version, actor); err != nil {
		s.T.Fatalf("ltest: activate policy version %d: %v", p.Version, err)
	}
	s.Note(fmt.Sprintf("policy_v%d", p.Version), th)
	return p.Version
}

// Switch sets a source type (instance nil) or an instance on or off
// through api's switch service (internal/sources/switches): the row, its
// events row and the KV state in one transaction, then the push.
func (s *Stack) Switch(sourceType string, instance *string, enabled bool, reason string) {
	s.T.Helper()
	s.mu.Lock()
	if s.switches == nil {
		s.mu.Unlock()
		svc := switches.NewService(s.PG(), audit.NewWriter(s.PG()), s.BP, s.busCfg, config.Sources{}, logging.Discard(), nil)
		s.mu.Lock()
		s.switches = svc
	}
	svc := s.switches
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := svc.Switch(ctx, audit.Actor{Type: audit.ActorUser, ID: "ltest-admin", Realm: "console"}, sourceType, instance, enabled, reason); err != nil {
		s.T.Fatalf("ltest: switch %s %v to %v: %v", sourceType, instance, enabled, err)
	}
}

// Note records a value in the results file under name.
func (s *Stack) Note(name string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.extra[name] = v
}

// repoRoot is the module's root directory, from this file's path.
func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// GroundDir is internal/ground's synthetic terrain (N41E044: 422 m at
// 41.50 N 44.50 E, dataset COP-DEM GLO-30); GeoidFile its constant
// geoid (N = 15.9 m everywhere). Every process and the simulated
// receiver read the same files (R-16).
func GroundDir() string {
	return filepath.Join(repoRoot(), "internal", "ground", "testdata", "tiles")
}

// GeoidFile is the constant test geoid.
func GeoidFile() string {
	return filepath.Join(repoRoot(), "internal", "ground", "testdata", "geoid-constant.pgm")
}

// resultsDir is SCENARIO_RESULTS_DIR, or a directory under the system's
// temporary directory, said in the log.
func resultsDir() string {
	if d := os.Getenv("SCENARIO_RESULTS_DIR"); d != "" {
		return d
	}
	return filepath.Join(os.TempDir(), "uspace-authority-scenarios")
}
