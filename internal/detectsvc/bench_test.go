package detectsvc

import (
	"context"
	"testing"

	"github.com/rootxkit/uspace-core/alerting"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/violation"
)

// BenchmarkTrackMapping is a trk.v1 message to the monitor's input (plan
// §8: reported, not gated; the judgement is benchmarked in core).
func BenchmarkTrackMapping(b *testing.B) {
	m := message(&testing.T{}, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(500)}, t0)
	c := &core.Counters{}
	env := zones.Env{Ground: zones.GroundKnown, GroundM: 400}
	b.ReportAllocs()
	for b.Loop() {
		tm, err := TimesOf(m)
		if err != nil {
			b.Fatal(err)
		}
		_ = ToTrack(m, tm, env, c)
	}
}

// BenchmarkEventMapping is one raise and its clear to violation/v1
// messages, with the excerpt copied.
func BenchmarkEventMapping(b *testing.B) {
	in := &fakeInputs{}
	in.setPolicy(1, nil)
	clk := &clock{now: t0}
	set := DefaultSettings()
	set.Now = clk.Now
	pub := discard{}
	w := NewWorker("c3:131:224", in, set, pub, nil, nil)
	m := message(&testing.T{}, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(500)}, t0)
	w.Observe(m)
	a := alerting.Alert{Key: "height:A", Kind: alerting.KindHeight, Severity: core.SeverityWarning, Aircraft: []string{"A"},
		Detail: map[string]any{"height_agl_m": 130.0, "max_height_agl_m": 120.0}, RaisedAtS: seconds(t0), LastTrueS: seconds(t0)}
	b.ReportAllocs()
	for b.Loop() {
		w.handle(alerting.Events{Raised: []alerting.Alert{a}})
		w.handle(alerting.Events{Cleared: []alerting.Cleared{{Alert: a, Reason: alerting.ClearResolved}}})
	}
}

// discard publishes nowhere.
type discard struct{}

func (discard) PublishViolation(context.Context, *violation.Message) error { return nil }
