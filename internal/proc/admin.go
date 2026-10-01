package proc

import (
	"context"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/metrics"
)

// CheckTimeout bounds one readiness check.
const CheckTimeout = 2 * time.Second

// Readiness is the set of checks /readyz runs. A process with no check
// registered is ready and says so with an empty map; a check never
// counts as passing because it was not run.
type Readiness struct {
	mu     sync.Mutex
	checks map[string]func(context.Context) error
}

// Add registers a named check.
func (r *Readiness) Add(name string, check func(context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checks == nil {
		r.checks = make(map[string]func(context.Context) error)
	}
	r.checks[name] = check
}

// Run runs every check and reports whether all passed.
func (r *Readiness) Run(ctx context.Context) (bool, map[string]gen.Check) {
	r.mu.Lock()
	names := make([]string, 0, len(r.checks))
	for n := range r.checks {
		names = append(names, n)
	}
	checks := make(map[string]func(context.Context) error, len(r.checks))
	for n, c := range r.checks {
		checks[n] = c
	}
	r.mu.Unlock()
	sort.Strings(names)

	ok := true
	out := make(map[string]gen.Check, len(names))
	for _, n := range names {
		cctx, cancel := context.WithTimeout(ctx, CheckTimeout)
		err := checks[n](cctx)
		cancel()
		if err != nil {
			ok = false
			msg := err.Error()
			out[n] = gen.Check{Ok: false, Error: &msg}
			continue
		}
		out[n] = gen.Check{Ok: true}
	}
	return ok, out
}

// health implements the generated strict server for the health paths.
type health struct{ ready *Readiness }

// GetHealthz answers 200 while the process runs.
func (h health) GetHealthz(context.Context, gen.GetHealthzRequestObject) (gen.GetHealthzResponseObject, error) {
	return gen.GetHealthz200JSONResponse{Status: gen.HealthStatusOk}, nil
}

// GetReadyz runs every readiness check.
func (h health) GetReadyz(ctx context.Context, _ gen.GetReadyzRequestObject) (gen.GetReadyzResponseObject, error) {
	ok, checks := h.ready.Run(ctx)
	if !ok {
		return gen.GetReadyz503JSONResponse{Status: gen.ReadinessStatusNotReady, Checks: checks}, nil
	}
	return gen.GetReadyz200JSONResponse{Status: gen.ReadinessStatusReady, Checks: checks}, nil
}

// AdminHandler serves /healthz and /readyz through the handlers
// generated from api/openapi.yaml, and /metrics.
func AdminHandler(ready *Readiness, reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	apiserver.Mount(mux, apiserver.Server{HealthHandler: health{ready: ready}}, apiserver.Options{
		Keep: func(pattern string) bool { return pattern == "GET /healthz" || pattern == "GET /readyz" },
	})
	mux.Handle("GET /metrics", metrics.Handler(reg))
	mux.HandleFunc("/", httpx.NotFound)
	return mux
}
