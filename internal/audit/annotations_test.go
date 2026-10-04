package audit

import (
	"context"
	"testing"
)

// WP-19, E-01: a map payload recorded under annotations gains the
// members it does not set, keeps the ones it does, and a payload of
// another type, or one recorded without annotations, is left alone.
func TestAnnotationsAreAddedWhereThePayloadIsSilent(t *testing.T) {
	plain := context.Background()
	if got := annotate(plain, map[string]any{"a": 1}); len(got.(map[string]any)) != 1 {
		t.Fatalf("annotated without annotations: %v", got)
	}
	ctx := WithAnnotations(plain, map[string]any{"case_ref": "CASE-1", "agency": "A"})
	ctx = WithAnnotations(ctx, map[string]any{"police_query_id": "q-1"})
	in := map[string]any{"case_ref": "own", "x": 2}
	got := annotate(ctx, in).(map[string]any)
	if got["case_ref"] != "own" || got["agency"] != "A" || got["police_query_id"] != "q-1" || got["x"] != 2 {
		t.Fatalf("annotated %v", got)
	}
	if _, touched := in["agency"]; touched {
		t.Fatal("the caller's payload map was changed")
	}
	if got := annotate(ctx, nil).(map[string]any); got["agency"] != "A" {
		t.Fatalf("nil payload: %v", got)
	}
	type other struct{ A int }
	if got, ok := annotate(ctx, other{A: 1}).(other); !ok || got.A != 1 {
		t.Fatalf("a struct payload was replaced: %v", got)
	}
	if a := Annotations(ctx); len(a) != 3 || Annotations(plain) != nil {
		t.Fatalf("Annotations %v", a)
	}
}
