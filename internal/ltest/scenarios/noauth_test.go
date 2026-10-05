package scenarios

import (
	"strconv"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// activated is an Activated operational intent of a lab USSP whose
// volume is a 100 m circle around (lat, lon), 0-1000 m WGS84, for the
// hour around now.
func activated(id string, lat, lon float64) (f3548.OperationalIntentReference, f3548.Volume4D) {
	now := time.Now().UTC()
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	ref := f3548.OperationalIntentReference{Id: id, Manager: "ussp-lab-01", UssBaseUrl: "https://ussp.lab.test", State: f3548.Activated,
		Version: 1, UssAvailability: f3548.Normal, SubscriptionId: "sub-25",
		TimeStart: f3548.Time{Format: f3548.RFC3339, Value: start}, TimeEnd: f3548.Time{Format: f3548.RFC3339, Value: end}}
	ext := f3548.Volume4D{
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: start}, TimeEnd: &f3548.Time{Format: f3548.RFC3339, Value: end},
		Volume: f3548.Volume3D{OutlineCircle: &f3548.Circle{Center: &f3548.LatLngPoint{Lat: lat, Lng: lon},
			Radius: &f3548.Radius{Units: f3548.RadiusUnitsM, Value: 100}},
			AltitudeLower: &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 0},
			AltitudeUpper: &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 1000}},
	}
	return ref, ext
}

// The no_authorisation detector and the 120 m rule in U-space (WP-26;
// spec 04 §3.3, Art. 6(4); plan Q-A5, Q-A22), with detect reading the
// fake InterUSS DSS over HTTP with a token from its own client. The
// policy is the documented defaults with height_limit_in_uspace
// skip_when_authorised (a policy choice pending GCAA, spec Q2; the grace
// stays the default 10 s). Two aircraft hover inside a U-space
// airspace with no operational intent at their positions: both raise
// no_authorisation after the grace, and the one 199 m over the DEM
// raises height_120m (an unauthorised flight is judged against 120 m).
// An Activated intent at each clears its no_authorisation resolved, and
// the high one's height_120m clears authorised.
func TestScenarioNoAuthorisationAndTheHeightLimitInUSpace(t *testing.T) {
	th := policy.Defaults()
	th.HeightLimitInUspace = policy.HeightSkipWhenAuthorised
	s := ltest.New(t, ltest.Options{Name: "no_authorisation", Policy: &th})
	sd := s.Seed(seed("noauth.json"))
	u := s.ZoneByID(sd, "USP25")

	dss := fakedss.NewDSS()
	t.Cleanup(dss.Close)
	tok := ltest.NewTokenServer(t, "authority-01")
	ri := s.StartRIDIngest(nil)
	s.StartTSDBWriter(nil)
	// The DSS poll: how often detect reads every U-space airspace in
	// force, set here so the gated raises' bound below follows from it.
	const requeryS = 5
	det := s.StartDetect(map[string]string{"DSS_BASE_URL": ltest.HostURL(dss.URL()), "DETECT_TOKEN_URL": tok.URL(),
		"DETECT_CLIENT_SECRET_FILE": tok.SecretFile, "DETECT_CLIENT_ID": tok.ClientID, "DETECT_INTENT_REQUERY_S": strconv.Itoa(requeryS)})
	det.WaitLine("no_authorisation detector reads the DSS (utm.conformance_monitoring_sa, Q-A5)", nil, 10*time.Second)
	s.StartViolationStore()

	const groundLowM, groundHighM = 427.6, 427.9 // the DEM at the two points
	low := ltest.At(u.LatDeg, u.LonDeg, groundLowM+92)
	high := ltest.At(u.LatDeg+0.002, u.LonDeg, groundHighM+199)
	rx := s.NewReceiver(s.ReceiverID("rx-na"), u.LatDeg, u.LonDeg-0.005, ri)
	a := &ltest.Aircraft{Transmitter: mac(0xE01), Serial: "TESTNA0000001", OperatorID: "GEOTEST00002601", System: true,
		Path: ltest.Hold(low.LatDeg, low.LonDeg, low.AltAMSLM)}
	b := &ltest.Aircraft{Transmitter: mac(0xE02), Serial: "TESTNA0000002", OperatorID: "GEOTEST00002601", System: true,
		Path: ltest.Hold(high.LatDeg, high.LonDeg, high.AltAMSLM)}
	f := rx.Fly(a, b)

	inside := time.Now()
	na := s.AwaitRaised(violation.KindNoAuthorisation, a.TrackID(), 40*time.Second)
	nb := s.AwaitRaised(violation.KindNoAuthorisation, b.TrackID(), 10*time.Second)
	hb := s.AwaitRaised(violation.KindHeight120m, b.TrackID(), 10*time.Second)
	if d := na.RaisedAt.Sub(inside); d < 10*time.Second {
		t.Errorf("no_authorisation raised %v after the aircraft entered, before the policy's 10 s grace", d)
	}
	s.Note("entered_to_no_authorisation_ms", na.RaisedAt.Sub(inside).Milliseconds())

	refA, extA := activated("6f1c1b8e-1d1a-4f6e-9a55-000000002501", low.LatDeg, low.LonDeg)
	dss.PutIntent(refA, extA)
	if r := s.AwaitCleared(na.ID, 30*time.Second); r != "resolved" {
		t.Errorf("A's no_authorisation cleared %s, want resolved", r)
	}
	if s.Open(violation.KindNoAuthorisation, b.TrackID()) == nil {
		t.Error("B's no_authorisation cleared by A's intent")
	}
	refB, extB := activated("6f1c1b8e-1d1a-4f6e-9a55-000000002502", high.LatDeg, high.LonDeg)
	dss.PutIntent(refB, extB)
	if r := s.AwaitCleared(nb.ID, 30*time.Second); r != "resolved" {
		t.Errorf("B's no_authorisation cleared %s, want resolved", r)
	}
	if r := s.AwaitCleared(hb.ID, 30*time.Second); r != "authorised" {
		t.Errorf("B's height_120m cleared %s, want authorised", r)
	}
	f.WaitSteps(3)
	f.Stop()
	if dss.IntentQueries() == 0 || tok.Issued() == 0 {
		t.Errorf("the DSS was asked %d times with %d tokens issued", dss.IntentQueries(), tok.Issued())
	}
	for _, c := range dss.Claims() {
		if c.Scope != "utm.conformance_monitoring_sa" || c.Aud != "localhost" {
			t.Errorf("a DSS call carried scope %q and aud %q", c.Scope, c.Aud)
		}
	}
	// Both kinds wait, by design, for the DSS's outcome (the grace; a
	// height raise in U-space waits for the first authorisation outcome),
	// so their captured_at-to-raise is not the per-sample budget. It is
	// held instead to the wait it is designed for: the grace plus one DSS
	// poll.
	gate := time.Duration(th.NoAuthorisationGraceS*float64(time.Second)) + requeryS*time.Second
	s.Verify(
		ltest.Raise(violation.KindNoAuthorisation, a.TrackID(), "resolved").InZone(u.ZoneID()).WithSeverity(core.SeverityWarning).GatedByAnOutcome(gate),
		ltest.Raise(violation.KindNoAuthorisation, b.TrackID(), "resolved").InZone(u.ZoneID()).WithSeverity(core.SeverityWarning).GatedByAnOutcome(gate),
		ltest.Raise(violation.KindHeight120m, b.TrackID(), "authorised").GatedByAnOutcome(gate),
	)
	s.CheckIdentity(ri, true)
}
