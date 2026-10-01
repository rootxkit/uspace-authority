package tracing

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config is what Setup needs; it comes from config.Common.
type Config struct {
	// Endpoint is the OTLP/HTTP endpoint URL; empty means no exporter.
	Endpoint    string
	ServiceName string
	Version     string
}

// Shutdown flushes and stops the provider.
type Shutdown func(context.Context) error

// Setup installs the global tracer provider and propagator. With no
// endpoint the provider is a no-op and Enabled reports false, so the
// process can say on its first line that tracing is off rather than
// leave it to be guessed. The returned Shutdown restores the previous
// global provider (tests rely on it, E-11).
func Setup(ctx context.Context, cfg Config) (trace.TracerProvider, bool, Shutdown, error) {
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	restore := func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	}
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	if cfg.Endpoint == "" {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return tp, false, func(context.Context) error { restore(); return nil }, nil
	}
	// The exporter logs and ignores a malformed URL; refuse it here.
	if u, err := url.Parse(cfg.Endpoint); err != nil || u.Scheme == "" || u.Host == "" {
		restore()
		return nil, false, nil, errors.New("otlp exporter: endpoint must be an absolute URL")
	}
	exp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(cfg.Endpoint))
	if err != nil {
		restore()
		return nil, false, nil, fmt.Errorf("otlp exporter: %w", err)
	}
	res := resource.NewSchemaless(
		attribute.String("service.name", cfg.ServiceName),
		attribute.String("service.version", cfg.Version),
	)
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return tp, true, func(ctx context.Context) error {
		defer restore()
		return tp.Shutdown(ctx)
	}, nil
}
