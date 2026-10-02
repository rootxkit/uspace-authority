package switches

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/sources"
)

func strp(s string) *string { return &s }

func TestValidateNamesEachFault(t *testing.T) {
	if err := Validate(sources.TypeDirectRID, strp("rx-tbs-01"), "maintenance"); err != nil {
		t.Fatal(err)
	}
	if err := Validate(sources.TypeNetworkRID, nil, "x"); err != nil {
		t.Fatal(err)
	}
	err := Validate("remote_id", strp("rx.1"), "")
	for _, f := range []string{"source_type", "instance_id", "reason"} {
		if err == nil || !strings.Contains(err.Error(), f) {
			t.Errorf("%s not named: %v", f, err)
		}
	}
	if err := Validate(sources.TypeANSPFeed, strp("feed"), strings.Repeat("x", 501)); err == nil {
		t.Fatal("a long reason passed")
	}
}

// E-10: a state past the bucket's value bound is refused naming the
// bound, the bucket and the variable, and counted; at the bound it
// passes.
func TestEncodeRefusesAStatePastTheBucketBound(t *testing.T) {
	s := &Service{Counters: &core.Counters{}, Bucket: "source_control", Now: func() time.Time { return time.Unix(0, 0) }}
	d := sources.Document{Epoch: "e", Version: 1}
	for i := range 20 {
		id := "rx-" + strings.Repeat("a", i+1)
		d.Controls = append(d.Controls, sources.Control{SourceType: sources.TypeDirectRID, InstanceID: &id, Reason: "r", Actor: "a", Version: 1})
	}
	raw, err := s.encode(d)
	if err != nil {
		t.Fatal(err)
	}
	s.MaxBytes = len(raw)
	if _, err := s.encode(d); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	s.MaxBytes = len(raw) - 1
	_, err = s.encode(d)
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "controls" || !strings.Contains(err.Error(), "SOURCE_CONTROL_MAX_VALUE_BYTES") ||
		!strings.Contains(err.Error(), "source_control") || s.Counters.Get(CounterTooLarge) != 1 {
		t.Fatalf("past the bound: %v", err)
	}
}

type failPub struct{ n int }

func (f *failPub) Publish(string, []byte) error { f.n++; return errors.New("disconnected") }

// A push that fails is counted (the followers' watch and re-read repair
// it); with no push configured nothing is sent.
func TestPushFailureIsCounted(t *testing.T) {
	p := &failPub{}
	s := &Service{Counters: &core.Counters{}, Push: p, Subject: "ctl.sources"}
	s.push([]byte("x"))
	if p.n != 1 || s.Counters.Get(CounterPushFailed) != 1 {
		t.Fatal(s.Counters.Snapshot())
	}
	s.Subject = ""
	s.push([]byte("x"))
	if p.n != 1 {
		t.Fatal("pushed without a subject")
	}
}
