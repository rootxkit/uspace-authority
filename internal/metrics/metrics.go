package metrics

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// Namespace prefixes every metric of this system.
const Namespace = "uspace_authority"

// NewRegistry returns a registry with the Go runtime and process
// collectors.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return reg
}

// Handler serves reg in the Prometheus text format.
func Handler(reg *prometheus.Registry) http.Handler {
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg})
}

// CountersCollector exposes a core.Counters as gauges named
// uspace_authority_<counter> with a constant "component" label. Counter
// names are snake_case and stable by core's contract; a character
// Prometheus does not accept is replaced by "_" so a malformed name is
// still visible rather than dropped. It is an unchecked collector:
// the set of names grows as counters are first incremented.
type CountersCollector struct {
	component string
	counters  *core.Counters
}

// NewCountersCollector returns a collector over counters.
func NewCountersCollector(component string, counters *core.Counters) *CountersCollector {
	return &CountersCollector{component: component, counters: counters}
}

// Describe sends nothing: the collector is unchecked.
func (c *CountersCollector) Describe(chan<- *prometheus.Desc) {}

// Collect sends one gauge per counter.
func (c *CountersCollector) Collect(ch chan<- prometheus.Metric) {
	for name, v := range c.counters.Snapshot() {
		desc := prometheus.NewDesc(
			MetricName(name),
			"core.Counters value "+name+" (E-09).",
			nil, prometheus.Labels{"component": c.component},
		)
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(v))
	}
}

var invalidMetricChars = regexp.MustCompile(`[^a-z0-9_]`)

// MetricName is the Prometheus name of a counter.
func MetricName(counter string) string {
	return Namespace + "_" + invalidMetricChars.ReplaceAllString(strings.ToLower(counter), "_")
}

// HTTP holds the request histogram of one listener.
type HTTP struct {
	duration *prometheus.HistogramVec
}

// NewHTTP registers the HTTP request histogram on reg for the listener
// named server ("public", "admin").
func NewHTTP(reg prometheus.Registerer, server string) *HTTP {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   Namespace,
		Name:        "http_request_duration_seconds",
		Help:        "HTTP request duration by route pattern, method and status code.",
		ConstLabels: prometheus.Labels{"server": server},
		Buckets:     prometheus.DefBuckets,
	}, []string{"route", "method", "code"})
	reg.MustRegister(h)
	return &HTTP{duration: h}
}

// Middleware observes every request. The route label is the ServeMux
// pattern that matched (bounded cardinality), or "unmatched"; outside
// httpx.Baseline, wrap it in httpx.TrackRoute.
func (m *HTTP) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		m.duration.WithLabelValues(httpx.Route(r), r.Method, strconv.Itoa(sw.code)).Observe(time.Since(start).Seconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

// WriteHeader records the status code.
func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// NATS holds the message-handling histogram of a consumer.
type NATS struct {
	duration *prometheus.HistogramVec
}

// NewNATS registers the NATS message histogram on reg.
func NewNATS(reg prometheus.Registerer) *NATS {
	h := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "nats_message_duration_seconds",
		Help:      "Time to handle one NATS message by subject pattern and outcome.",
		Buckets:   []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
	}, []string{"subject", "outcome"})
	reg.MustRegister(h)
	return &NATS{duration: h}
}

// Wrap returns handle timed under subject, which must be the
// subscription's pattern (never a concrete subject, which would make
// the label unbounded). The outcome label is "ok" or "error".
func (m *NATS) Wrap(subject string, handle func([]byte) error) func([]byte) error {
	return func(data []byte) error {
		start := time.Now()
		err := handle(data)
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		m.duration.WithLabelValues(subject, outcome).Observe(time.Since(start).Seconds())
		return err
	}
}
