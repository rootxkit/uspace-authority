// Package metrics is the Prometheus registry of a process: Go and
// process collectors, a collector exposing core.Counters as gauges with
// stable snake_case names, and request histograms for HTTP (labelled by
// route pattern) and NATS (labelled by subscription pattern).
package metrics
