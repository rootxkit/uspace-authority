package proc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/metrics"
	"github.com/rootxkit/uspace-authority/internal/tracing"
)

// Version is set at link time (-ldflags "-X .../internal/proc.Version=...").
var Version = "dev"

// Exit codes of Main.
const (
	ExitOK     = 0
	ExitFailed = 1 // a runtime failure or a drain that overran its bound
	ExitConfig = 2 // the configuration is invalid; the variable is named
)

// Spec describes one process.
type Spec struct {
	Name string
	// Config is a pointer to the process's config struct; Main loads it
	// before Run is called, so Run may close over the same pointer.
	Config interface {
		config.CommonConfig
		fmt.Stringer
	}
	// Run is the process body. It returns nil when ctx is cancelled and
	// it has drained, or an error that ends the process.
	Run func(ctx context.Context, rt *Runtime) error
}

// Runtime is what Main hands to Run.
type Runtime struct {
	Name     string
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	Counters *core.Counters // component "process"
	Registry *prometheus.Registry
	Ready    *Readiness
	Common   *config.Common

	status *logging.Status
}

// AddCounters puts a component's counters on the status line and on
// /metrics.
func (rt *Runtime) AddCounters(component string, c *core.Counters) {
	rt.status.Add(logging.Source{Name: component, Counters: c})
	rt.Registry.MustRegister(metrics.NewCountersCollector(component, c))
}

// AddStatus puts attributes on every later status line (E-09): the
// version of a followed policy, the age of a projection.
func (rt *Runtime) AddStatus(fn func() []slog.Attr) { rt.status.AddExtra(fn) }

// DrainTimeout is the bound on the drain after the context ends.
func (rt *Runtime) DrainTimeout() time.Duration {
	return time.Duration(rt.Common.ShutdownTimeoutS) * time.Second
}

// Main runs spec and returns the exit code. args are the command-line
// arguments after the program name; --help prints every variable the
// process reads. ctx ends on SIGTERM or SIGINT (cmd/*/main.go).
func Main(ctx context.Context, spec Spec, args []string, stdout, stderr io.Writer, lookup config.LookupFunc) int {
	if len(args) > 0 {
		if slices.Contains([]string{"-h", "--help", "-help", "help"}, args[0]) {
			_, _ = io.WriteString(stdout, Usage(spec.Name, spec.Config))
			return ExitOK
		}
		boot := logging.New(stderr, "info", spec.Name)
		boot.Error("unknown argument", slog.String("argument", args[0]), slog.String("hint", "--help lists the configuration variables"))
		return ExitConfig
	}
	if err := config.Load(spec.Config, lookup); err != nil {
		boot := logging.New(stderr, "info", spec.Name)
		var fields []string
		for _, fe := range config.FieldErrors(err) {
			fields = append(fields, fe.Field)
		}
		boot.Error("configuration invalid", slog.Any("fields", fields), slog.String("error", strings.ReplaceAll(err.Error(), "\n", "; ")))
		return ExitConfig
	}
	common := spec.Config.CommonBlock()
	logger := logging.New(stdout, common.LogLevel, spec.Name)
	return run(ctx, spec, common, logger)
}

// Usage is the --help text.
func Usage(name string, cfg any) string {
	return "usage: uspace-authority " + name + " [--help]\n\n" +
		"Configuration is read from the environment only:\n\n" + config.Help(cfg)
}

func run(ctx context.Context, spec Spec, common *config.Common, logger *slog.Logger) int {
	counters := &core.Counters{}
	reg := metrics.NewRegistry()
	interval := time.Duration(common.StatusIntervalS) * time.Second
	rt := &Runtime{
		Name:     spec.Name,
		Logger:   logger,
		Limiter:  logging.NewLimiter(logger, interval, logging.DefaultLimiterKeys, counters),
		Counters: counters,
		Registry: reg,
		Ready:    &Readiness{},
		Common:   common,
		status:   &logging.Status{Logger: logger, Interval: interval},
	}
	rt.AddCounters("process", counters)

	_, tracingOn, stopTracing, err := tracing.Setup(ctx, tracing.Config{Endpoint: common.OTLPEndpoint, ServiceName: "uspace-authority-" + spec.Name, Version: Version})
	if err != nil {
		logging.Error(ctx, logger, "tracing setup failed", err)
		return ExitFailed
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stopTracing(sctx); err != nil {
			logging.Error(sctx, logger, "tracing shutdown failed", err)
		}
	}()

	admin := httpx.NewServer(httpx.ServerOptions{
		Name: "admin", Addr: common.AdminAddr, Logger: logger,
		Handler: metrics.NewHTTP(reg, "admin").Middleware(AdminHandler(rt.Ready, reg)),
	})
	adminLn, err := admin.Listen()
	if err != nil {
		logging.Error(ctx, logger, "admin listener failed", err)
		return ExitFailed
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "started",
		slog.String("version", Version),
		slog.String("admin_addr", adminLn.Addr().String()),
		slog.Bool("tracing", tracingOn),
		slog.String("config", spec.Config.String()),
	)

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	statusDone := make(chan struct{})
	go func() { defer close(statusDone); rt.status.Run(runCtx) }()
	adminErr := make(chan error, 1)
	go func() { adminErr <- admin.Serve(runCtx, adminLn, rt.DrainTimeout()) }()
	runErr := make(chan error, 1)
	go func() { runErr <- spec.Run(runCtx, rt) }()

	code := ExitOK
	var drainDeadline <-chan time.Time
	select {
	case <-ctx.Done():
		logger.Info("shutting down", slog.String("cause", "signal"), slog.Int("drain_timeout_s", common.ShutdownTimeoutS))
		drainDeadline = time.After(rt.DrainTimeout())
	case err := <-runErr:
		runErr = nil
		if err != nil {
			logging.Error(ctx, logger, "process failed", err)
			code = ExitFailed
		}
		drainDeadline = time.After(rt.DrainTimeout())
	case err := <-adminErr:
		adminErr = nil
		logging.Error(ctx, logger, "admin server failed", err)
		code = ExitFailed
		drainDeadline = time.After(rt.DrainTimeout())
	}
	cancelRun()

	for runErr != nil || adminErr != nil {
		select {
		case err := <-runErr:
			runErr = nil
			if err != nil && !errors.Is(err, context.Canceled) {
				logging.Error(ctx, logger, "process drain failed", err)
				code = ExitFailed
			}
		case err := <-adminErr:
			adminErr = nil
			if err != nil {
				logging.Error(ctx, logger, "admin drain failed", err)
				code = ExitFailed
			}
		case <-drainDeadline:
			logger.Error("drain exceeded its bound; exiting with work in flight",
				slog.Int("drain_timeout_s", common.ShutdownTimeoutS),
				slog.Bool("process_drained", runErr == nil),
				slog.Bool("admin_drained", adminErr == nil))
			runErr, adminErr = nil, nil
			code = ExitFailed
		}
	}
	<-statusDone
	rt.status.Emit(context.Background())
	logger.Info("stopped", slog.Int("exit_code", code))
	return code
}

// Idle is the Run of a process whose work package has not landed yet:
// it says so once and waits for the signal.
func Idle(owner string) func(context.Context, *Runtime) error {
	return func(ctx context.Context, rt *Runtime) error {
		rt.Logger.Info("no work yet: this process is a scaffold", slog.String("filled_by", owner))
		<-ctx.Done()
		return nil
	}
}

// ServePublic serves mux on addr behind the httpx baseline (request id,
// access log, recovery, per-client rate limit, body cap) until ctx ends,
// then drains within the runtime's bound. Unmatched paths answer with a
// not_found problem.
func (rt *Runtime) ServePublic(ctx context.Context, cfg config.HTTP, addr string, mux *http.ServeMux) error {
	proxies, err := httpx.ParseTrustedProxies(cfg.TrustedProxies)
	if err != nil {
		return &core.FieldError{Field: "AUTHORITY_TRUSTED_PROXIES", Reason: err.Error()}
	}
	counters := &core.Counters{}
	rt.AddCounters("http", counters)
	mux.HandleFunc("/", httpx.NotFound)
	rl := httpx.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst, cfg.RateLimitMaxClients, counters)
	h := httpx.Baseline(mux, rt.Logger, httpx.BaselineDeps{Counters: counters, RateLimiter: rl, MaxBodyBytes: int64(cfg.MaxBodyBytes), TrustedProxies: proxies})
	srv := httpx.NewServer(httpx.ServerOptions{
		Name: "public", Addr: addr, Logger: rt.Logger,
		Handler:           httpx.TrackRoute(metrics.NewHTTP(rt.Registry, "public").Middleware(h)),
		ReadHeaderTimeout: time.Duration(cfg.ReadHeaderTimeoutS) * time.Second,
	})
	ln, err := srv.Listen()
	if err != nil {
		return err
	}
	rt.Logger.Info("public listener open", slog.String("addr", ln.Addr().String()))
	return srv.Serve(ctx, ln, rt.DrainTimeout())
}
