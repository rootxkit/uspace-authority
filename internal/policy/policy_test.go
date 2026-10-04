package policy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

func fieldsOf(err error) []string {
	var out []string
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		for _, e := range j.Unwrap() {
			out = append(out, fieldsOf(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		out = append(out, fe.Field)
	}
	return out
}

// E-15 presence: the documented defaults validate.
func TestDefaultsValidate(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatal(err)
	}
}

// E-15: zero, negative, NaN and both infinities are refused for every
// numeric threshold, and the refusal names that field and only it.
func TestValidateRefusesEveryNonPositiveOrNonFiniteThreshold(t *testing.T) {
	bad := map[string]float64{"zero": 0, "negative": -1, "nan": math.NaN(), "+inf": math.Inf(1), "-inf": math.Inf(-1)}
	numbers := Defaults().numbers()
	if len(numbers) != 15 {
		t.Fatalf("%d numeric thresholds; this test and the migration's CHECK list them all", len(numbers))
	}
	v := reflect.ValueOf(Defaults())
	ty := v.Type()
	checked := 0
	for i := range ty.NumField() {
		if ty.Field(i).Type.Kind() != reflect.Float64 {
			continue
		}
		field := strings.TrimSuffix(ty.Field(i).Tag.Get("json"), ",omitempty")
		for name, x := range bad {
			th := Defaults()
			reflect.ValueOf(&th).Elem().Field(i).SetFloat(x)
			got := fieldsOf(th.Validate())
			if len(got) != 1 || got[0] != field {
				t.Errorf("%s = %s: refused fields %v", field, name, got)
			}
		}
		checked++
	}
	if checked != len(numbers) {
		t.Fatalf("checked %d numeric fields, Validate knows %d", checked, len(numbers))
	}
}

func TestValidateRefusesUnknownSeveritiesAndModes(t *testing.T) {
	th := Defaults()
	th.ZoneConditionalSeverity, th.MismatchSeverity, th.IdentificationSeverity = "", "loud", "CRITICAL"
	th.NoAuthorisationSeverity = "urgent"
	th.HeightLimitInUspace = "skip"
	got := strings.Join(fieldsOf(th.Validate()), ",")
	if got != "zone_conditional_severity,mismatch_severity,identification_severity,no_authorisation_severity,height_limit_in_uspace" {
		t.Fatalf("got %s", got)
	}
	th = Defaults()
	th.HeightLimitInUspace = HeightSkipWhenAuthorised
	th.MismatchSeverity = core.SeverityInfo
	th.NoAuthorisationSeverity = core.SeverityCritical
	if err := th.Validate(); err != nil {
		t.Fatalf("the other valid values: %v", err)
	}
}

func version(v int64) Policy { return Policy{Version: v, Thresholds: Defaults()} }

// E-01 pair: a follower applies a higher version and ignores an older
// one (counted) or the same one (a re-read, not counted).
func TestFollowerAppliesOnlyAHigherVersion(t *testing.T) {
	f := NewFollower(nil)
	if f.Version() != 0 {
		t.Fatal("a new follower holds a policy")
	}
	if !f.Apply(version(2)) || f.Version() != 2 {
		t.Fatalf("first policy not applied: %d", f.Version())
	}
	if !f.Apply(version(3)) || f.Version() != 3 {
		t.Fatalf("higher version not applied: %d", f.Version())
	}
	if f.Apply(version(2)) || f.Version() != 3 {
		t.Fatalf("older version applied: %d", f.Version())
	}
	if f.Apply(version(3)) || f.Counters().Get(CounterOlderIgnored) != 1 || f.Counters().Get(CounterApplied) != 2 {
		t.Fatalf("counters %v", f.Counters().Snapshot())
	}
}

// E-15 at the follower: a policy that does not validate never replaces
// the held one, whatever its version; a valid one does.
func TestFollowerRefusesAnInvalidPolicy(t *testing.T) {
	f := NewFollower(nil)
	f.Apply(version(1))
	bad := version(5)
	bad.ClearAfterS = 0
	if f.Apply(bad) || f.Version() != 1 || f.Counters().Get(CounterInvalidRefused) != 1 {
		t.Fatalf("invalid policy: version %d counters %v", f.Version(), f.Counters().Snapshot())
	}
	if f.Apply(Policy{Thresholds: Defaults()}) || f.Counters().Get(CounterInvalidRefused) != 2 {
		t.Fatal("version 0 applied")
	}
	if !f.Apply(version(5)) || f.Version() != 5 {
		t.Fatal("the valid version 5 was not applied")
	}
	p, ok := f.Current()
	if !ok || p.ClearAfterS != 3 {
		t.Fatalf("current %+v %v", p, ok)
	}
}

func attrs(as []slog.Attr) map[string]string {
	m := map[string]string{}
	for _, a := range as {
		m[a.Key] = a.Value.String()
	}
	return m
}

// E-02: without a policy the status line says "none", never a version
// that looks like defaults in force.
func TestFollowerStatusSaysNoneThenTheVersion(t *testing.T) {
	f := NewFollower(nil)
	if m := attrs(f.StatusAttrs()); m["policy"] != "none" || m["policy_version"] != "0" {
		t.Fatalf("before: %v", m)
	}
	f.Apply(version(4))
	if m := attrs(f.StatusAttrs()); m["policy_version"] != "4" || m["policy"] != "" || m["policy_age_s"] == "" {
		t.Fatalf("after: %v", m)
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// G-08: Run applies what the re-read finds; a failing re-read keeps the
// last policy, is counted and logged; Run ends with its context.
func TestFollowerRunKeepsTheLastPolicyWhenTheReReadFails(t *testing.T) {
	f := NewFollower(nil)
	var mu sync.Mutex
	calls := 0
	load := func(context.Context) (Policy, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return version(7), nil
		}
		return Policy{}, errors.New("database unreachable")
	}
	var logs safeBuffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.Run(ctx, load, 5*time.Millisecond, slog.New(slog.NewJSONHandler(&logs, nil)))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.Counters().Get(CounterRefreshFailed) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if f.Version() != 7 || f.Counters().Get(CounterRefreshFailed) < 2 {
		t.Fatalf("version %d counters %v", f.Version(), f.Counters().Snapshot())
	}
	if !strings.Contains(logs.String(), "policy applied") || !strings.Contains(logs.String(), "keeping the last policy") {
		t.Fatalf("logs: %s", logs.String())
	}
}

type recorder struct{ got []int64 }

func (r *recorder) PublishPolicy(_ context.Context, p Policy) error {
	r.got = append(r.got, p.Version)
	return nil
}

func TestFollowerIsAPublisher(t *testing.T) {
	var _ Publisher = NewFollower(nil)
	var _ Publisher = NopPublisher{}
	var _ Publisher = &recorder{}
	f := NewFollower(nil)
	if err := f.PublishPolicy(context.Background(), version(2)); err != nil || f.Version() != 2 {
		t.Fatal(err)
	}
}

// WP-3: the registration-number pattern is a policy column (G-07,
// INV-03): an empty, over-long or unparsable pattern is refused naming
// the field; the default and another valid pattern are accepted.
func TestValidateRegistrationNumberPattern(t *testing.T) {
	for _, bad := range []string{"", "[A-Z", strings.Repeat("A", MaxPatternLen+1)} {
		th := Defaults()
		th.RegistrationNumberPattern = bad
		if got := fieldsOf(th.Validate()); len(got) != 1 || got[0] != "registration_number_pattern" {
			t.Errorf("%.20q: %v", bad, got)
		}
	}
	for _, good := range []string{Defaults().RegistrationNumberPattern, `^GEO[0-9]{6}$`} {
		th := Defaults()
		th.RegistrationNumberPattern = good
		if err := th.Validate(); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
}
