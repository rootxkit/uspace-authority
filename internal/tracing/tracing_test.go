package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
)

func TestSetupWithoutEndpointIsANoOpAndSaysSo(t *testing.T) {
	before := otel.GetTracerProvider()
	_, on, shutdown, err := Setup(context.Background(), Config{ServiceName: "t"})
	if err != nil || on {
		t.Fatalf("on=%v err=%v, want off without error", on, err)
	}
	_, span := otel.Tracer("t").Start(context.Background(), "s")
	if span.SpanContext().IsValid() {
		t.Error("a no-op provider produced a valid span")
	}
	span.End()
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if otel.GetTracerProvider() != before {
		t.Error("shutdown did not restore the global provider (E-11)")
	}
}

func TestSetupWithEndpointExportsAndRestores(t *testing.T) {
	before := otel.GetTracerProvider()
	// Nothing listens there: spans are buffered and the exporter's
	// failure surfaces only at shutdown, never at setup.
	_, on, shutdown, err := Setup(context.Background(), Config{Endpoint: "http://127.0.0.1:1/v1/traces", ServiceName: "t", Version: "test"})
	if err != nil || !on {
		t.Fatalf("on=%v err=%v, want on", on, err)
	}
	_, span := otel.Tracer("t").Start(context.Background(), "s")
	if !span.SpanContext().IsValid() {
		t.Error("the SDK provider produced an invalid span")
	}
	span.End()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // do not wait on the unreachable collector
	_ = shutdown(ctx)
	if otel.GetTracerProvider() != before {
		t.Error("shutdown did not restore the global provider (E-11)")
	}
}

func TestSetupRefusesAMalformedEndpoint(t *testing.T) {
	before := otel.GetTracerProvider()
	if _, _, _, err := Setup(context.Background(), Config{Endpoint: "://bad"}); err == nil {
		t.Fatal("a malformed endpoint was accepted")
	}
	if otel.GetTracerProvider() != before {
		t.Error("a failed setup left the global provider changed")
	}
}
