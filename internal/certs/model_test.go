package certs

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/tokens"
)

var (
	notStarted = Facts{Operations: OpsNotStarted}
	operating  = Facts{Operations: OpsOperating}
	ceased     = Facts{Operations: OpsCeased}
)

func with(f Facts, edit func(*Facts)) Facts {
	edit(&f)
	return f
}

// The status precedence: ended, suspended, ceased, limited, operating,
// issued (the generated column of 00018_certificates; the integration
// test reads the column for the same facts).
func TestStatusOfFacts(t *testing.T) {
	cases := []struct {
		f    Facts
		want string
	}{
		{notStarted, StatusIssued},
		{operating, StatusOperating},
		{ceased, StatusCeased},
		{with(operating, func(f *Facts) { f.Limited = true }), StatusLimited},
		{with(notStarted, func(f *Facts) { f.Limited = true }), StatusLimited},
		{with(ceased, func(f *Facts) { f.Limited = true }), StatusCeased},
		{with(operating, func(f *Facts) { f.Limited, f.Suspended = true, true }), StatusSuspended},
		{with(operating, func(f *Facts) { f.Suspended, f.Ended = true, StatusRevoked }), StatusRevoked},
		{with(ceased, func(f *Facts) { f.Ended = StatusLapsed }), StatusLapsed},
	}
	for _, c := range cases {
		if got := c.f.Status(); got != c.want {
			t.Errorf("%+v: %s, want %s", c.f, got, c.want)
		}
	}
}

// E-01: every refused transition beside an accepted one of the same
// action.
func TestTransitionGraph(t *testing.T) {
	type step struct {
		from   Facts
		action string
		ok     bool
		want   string // status after, when ok; a word of the reason otherwise
	}
	suspended := with(operating, func(f *Facts) { f.Suspended = true })
	limited := with(operating, func(f *Facts) { f.Limited = true })
	limitedSuspended := with(limited, func(f *Facts) { f.Suspended = true })
	revoked := with(operating, func(f *Facts) { f.Ended = StatusRevoked })
	lapsed := with(notStarted, func(f *Facts) { f.Ended = StatusLapsed })
	steps := []step{
		{operating, ActionSuspend, true, StatusSuspended},
		{notStarted, ActionSuspend, true, StatusSuspended},
		{suspended, ActionSuspend, false, "suspended already"},
		{revoked, ActionSuspend, false, "revoked"},

		{operating, ActionLimit, true, StatusLimited},
		{suspended, ActionLimit, true, StatusSuspended},
		{limited, ActionLimit, false, "limited already"},
		{lapsed, ActionLimit, false, "lapsed"},

		{operating, ActionRevoke, true, StatusRevoked},
		{suspended, ActionRevoke, true, StatusRevoked},
		{revoked, ActionRevoke, false, "revoked"},
		{lapsed, ActionRevoke, false, "lapsed"},

		{suspended, ActionReinstate, true, StatusOperating},
		{limitedSuspended, ActionReinstate, true, StatusLimited}, // the limitation stays
		{limited, ActionReinstate, true, StatusOperating},
		{operating, ActionReinstate, false, "neither"},
		{revoked, ActionReinstate, false, "revoked"},

		{notStarted, ActionLapse, true, StatusLapsed},
		{ceased, ActionLapse, true, StatusLapsed},
		{operating, ActionLapse, false, "operating"},
		{lapsed, ActionLapse, false, "lapsed"},

		{operating, "teleport", false, "unknown"},
	}
	for _, s := range steps {
		after, err := Apply(s.from, s.action)
		switch {
		case s.ok && err != nil:
			t.Errorf("%s from %s refused: %v", s.action, s.from.Status(), err)
		case s.ok && after.Status() != s.want:
			t.Errorf("%s from %s: %s, want %s", s.action, s.from.Status(), after.Status(), s.want)
		case !s.ok && (err == nil || !errors.Is(err, ErrTransition) || !strings.Contains(err.Error(), s.want)):
			t.Errorf("%s from %s: %v, want refused with %q", s.action, s.from.Status(), err, s.want)
		case !s.ok && after != s.from:
			t.Errorf("%s from %s changed the facts on a refusal: %+v", s.action, s.from.Status(), after)
		}
	}
	// Lifting the suspension keeps the limitation; lifting the
	// limitation keeps the operations.
	if after, _ := Apply(limitedSuspended, ActionReinstate); !after.Limited || after.Suspended || after.Operations != OpsOperating {
		t.Fatalf("%+v", after)
	}
}

func TestNoticeGraph(t *testing.T) {
	suspended := with(operating, func(f *Facts) { f.Suspended = true })
	steps := []struct {
		from  Facts
		state string
		ok    bool
		want  string
	}{
		{notStarted, NoticeStarted, true, StatusOperating},
		{operating, NoticeStarted, false, "started already"},
		{with(notStarted, func(f *Facts) { f.Suspended = true }), NoticeStarted, false, "suspended"},

		{operating, NoticeCeased, true, StatusCeased},
		{suspended, NoticeCeased, true, StatusSuspended},
		{notStarted, NoticeCeased, false, "not running"},
		{ceased, NoticeCeased, false, "not running"},

		{ceased, NoticeRestarted, true, StatusOperating},
		{with(ceased, func(f *Facts) { f.Limited = true }), NoticeRestarted, true, StatusLimited},
		{operating, NoticeRestarted, false, "not ceased"},
		{with(ceased, func(f *Facts) { f.Suspended = true }), NoticeRestarted, false, "suspended"},

		{with(operating, func(f *Facts) { f.Ended = StatusRevoked }), NoticeCeased, false, "revoked"},
		{operating, "paused", false, "unknown"},
	}
	for _, s := range steps {
		after, err := Notice(s.from, s.state)
		switch {
		case s.ok && (err != nil || after.Status() != s.want):
			t.Errorf("%s from %+v: %v %s, want %s", s.state, s.from, err, after.Status(), s.want)
		case !s.ok && (err == nil || !strings.Contains(err.Error(), s.want)):
			t.Errorf("%s from %+v: %v, want refused with %q", s.state, s.from, err, s.want)
		}
	}
}

// Only an operating or limited certificate whose holder operates is
// listed; a limited one not started is not.
func TestListedFacts(t *testing.T) {
	for _, c := range []struct {
		f    Facts
		want bool
	}{
		{operating, true},
		{with(operating, func(f *Facts) { f.Limited = true }), true},
		{notStarted, false},
		{with(notStarted, func(f *Facts) { f.Limited = true }), false},
		{ceased, false},
		{with(operating, func(f *Facts) { f.Suspended = true }), false},
		{with(operating, func(f *Facts) { f.Ended = StatusRevoked }), false},
	} {
		if got := c.f.Listed(); got != c.want {
			t.Errorf("%+v: %v, want %v", c.f, got, c.want)
		}
	}
}

// E-01: a code longer than 8, lower-case, with a symbol, empty or
// non-ASCII is refused beside the accepted ones.
func TestCheckCode(t *testing.T) {
	for _, ok := range []string{"A", "USSPDEV", "AB12CD34", "00000001"} {
		if err := CheckCode(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for code, why := range map[string]string{
		"": "required", "ABCDEFGHI": "at most 8", "ussp": "upper-case", "USSP-DEV": "upper-case", "ÄBC": "upper-case", "A B": "upper-case",
	} {
		if err := CheckCode(code); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: %v, want %q", code, err, why)
		}
	}
	if ClientIDFor(HolderUSSP, "AB12") != "ussp-AB12-01" || ClientIDFor(HolderCISP, "CIS1") != "cisp-01" {
		t.Fatal("client ids")
	}
	// The client id is one the token service registers (M24).
	if _, err := tokens.SystemOf(ClientIDFor(HolderUSSP, "AB12CD34")); err != nil {
		t.Fatal(err)
	}
}

// Scope derivation per service set: the base set every USSP holds, each
// service adding only what it needs, and every scope grantable to the
// client (least privilege, WP-2 table B).
func TestScopesFor(t *testing.T) {
	base := []string{"registry.validate", "occurrences.write", "certificates.status", "rid.service_provider", "cis.read"}
	cases := []struct {
		services []string
		extra    []string
	}{
		{[]string{ServiceWeather}, nil},
		{[]string{ServiceNetworkIdentification}, []string{"rid.display_provider"}},
		{[]string{ServiceGeoAwareness}, []string{"utm.constraint_processing"}},
		{[]string{ServiceFlightAuthorisation}, []string{"utm.strategic_coordination"}},
		{[]string{ServiceConformance}, []string{"utm.conformance_monitoring_sa"}},
		{[]string{ServiceTrafficInformation, ServiceNetworkIdentification}, []string{"rid.display_provider"}},
		{USSPServices, []string{"rid.display_provider", "utm.constraint_processing", "utm.strategic_coordination", "utm.conformance_monitoring_sa"}},
	}
	for _, c := range cases {
		got := ScopesFor(HolderUSSP, c.services)
		want := append(slices.Clone(base), c.extra...)
		if !slices.Equal(got, want) {
			t.Errorf("%v: %v, want %v", c.services, got, want)
		}
		for _, s := range got {
			if err := tokens.CheckGrantable(s, "ussp-AB12-01"); err != nil {
				t.Errorf("%s: %v", s, err)
			}
		}
		if slices.Contains(got, "utm.constraint_management") || slices.Contains(got, "utm.availability_arbitration") ||
			slices.Contains(got, "police.query") || slices.Contains(got, "ussp.records") {
			t.Errorf("%v: %v grants a scope no USSP service needs", c.services, got)
		}
	}
	if got := ScopesFor(HolderCISP, []string{ServiceCommonInformation}); !slices.Equal(got, []string{"certificates.status"}) {
		t.Fatalf("cisp %v", got)
	}
}

func TestCheckServices(t *testing.T) {
	got, err := CheckServices(HolderUSSP, []string{ServiceWeather, ServiceNetworkIdentification})
	if err != nil || !slices.Equal(got, []string{ServiceNetworkIdentification, ServiceWeather}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := CheckServices(HolderCISP, []string{ServiceCommonInformation}); err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	for _, c := range []struct {
		holder   string
		services []string
	}{
		{HolderUSSP, nil},
		{HolderUSSP, []string{ServiceCommonInformation}},
		{HolderUSSP, []string{ServiceWeather, ServiceWeather}},
		{HolderUSSP, []string{"telepathy"}},
		{HolderCISP, []string{ServiceNetworkIdentification}},
		{HolderCISP, []string{ServiceCommonInformation, ServiceWeather}},
	} {
		if _, err := CheckServices(c.holder, c.services); err == nil {
			t.Errorf("%s %v accepted", c.holder, c.services)
		}
	}
}

func TestCheckHTTPSURL(t *testing.T) {
	for _, ok := range []string{"https://ussp.example.test", "https://ussp.example.test/api", "http://127.0.0.1:8080", "http://localhost"} {
		if err := CheckHTTPSURL("base_url", ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://ussp.example.test", "ftp://x", "https://u:p@x", "https://x?a=1", "https://x#f", "relative",
		"https://" + strings.Repeat("a", MaxURL)} {
		if err := CheckHTTPSURL("base_url", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckNoticeTime(t *testing.T) {
	issued := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := issued.Add(48 * time.Hour)
	if err := CheckNoticeTime(issued.Add(time.Hour), issued, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckNoticeTime(now.Add(MaxNoticeAhead-time.Second), issued, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckNoticeTime(issued.Add(-time.Second), issued, now); err == nil {
		t.Fatal("before the issue accepted")
	}
	if err := CheckNoticeTime(now.Add(MaxNoticeAhead+time.Second), issued, now); err == nil {
		t.Fatal("from the future accepted")
	}
}

func TestCheckLimitations(t *testing.T) {
	if err := CheckLimitations("limitations", []string{"VLOS only"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{" "}, {strings.Repeat("x", MaxLimitation+1)}, make([]string, MaxLimitations+1)} {
		if err := CheckLimitations("limitations", bad); err == nil {
			t.Errorf("%d limitations accepted", len(bad))
		}
	}
}
