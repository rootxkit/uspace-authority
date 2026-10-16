package cisp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"
)

// The expiry rule of the 02 F3 erratum (2026-10-16): a restrictions
// version the CISP made itself is installed, not held, when it is a
// verified expiry of the set in use. Every refusal has its acceptance
// beside it (E-01). The restrictions are invented, around Tbilisi.

// darFeature is a served restriction: the ANSP's feature, its one
// limitedApplicability period [end-3h, end], and the CISP's block.
// lowerM is the layer's lower limit, so that a test can change the
// feature's content.
func darFeature(id string, end time.Time, lowerM int) json.RawMessage {
	return darFeatureBlock(id, end, lowerM, 1)
}

// darFeatureBlock is darFeature with the CISP block's ansp_version.
func darFeatureBlock(id string, end time.Time, lowerM, anspVersion int) json.RawMessage {
	start, stop := end.Add(-3*time.Hour).UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)
	return json.RawMessage(fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.80,41.70],[44.82,41.70],[44.82,41.72],[44.80,41.72],[44.80,41.70]]],"layer":{"lower":%d,"lowerReference":"AGL","upper":120,"upperReference":"AGL","uom":"m"}},"properties":{"identifier":%q,"country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR","EMERGENCY"],"limitedApplicability":[{"startDateTime":%q,"endDateTime":%q}],"zoneAuthority":[{"name":[{"text":"Test ANSP","lang":"en-GB"}],"purpose":"NOTIFICATION"}],"extendedProperties":{"cis_restriction":{"id":"r-%s","ansp_ref":"TEST-DAR-%s","ansp_version":%d,"state":"active","starts_at":%q,"ends_at":%q,"ended_by":null,"uspace_airspace_id":"TSU001"}}}}`,
		lowerM, id, start, stop, id, id, anspVersion, start, stop))
}

// cispRecord is the CISP's expiry record; an empty featureID leaves
// feature_id and ends_at out, as a CISP older than the erratum does.
func cispRecord(op, featureID string, endsAt, at time.Time) []byte {
	m := map[string]any{"op": op, "restriction_id": "r-" + featureID, "at": at.UTC().Format(time.RFC3339)}
	if featureID != "" {
		m["feature_id"], m["ends_at"] = featureID, endsAt.UTC().Format(time.RFC3339)
	} else {
		m["restriction_id"] = "r-A"
	}
	b, _ := json.Marshal(m)
	return b
}

// expiryWorld is a world on a settable clock with the set in use
// {A ending endA, B ending in two hours} (version 2, ANSP-signed).
type expiryWorld struct {
	*world
	t    *testing.T
	now  time.Time
	endA time.Time
	endB time.Time
}

func newExpiryWorld(t *testing.T, endAFromNow time.Duration) *expiryWorld {
	t.Helper()
	w := &expiryWorld{world: newWorld(t), t: t, now: time.Now().UTC().Truncate(time.Second)}
	w.sub.cfg.Now = func() time.Time { return w.now }
	w.endA, w.endB = w.now.Add(endAFromNow), w.now.Add(2*time.Hour)
	a := darFeature("DARA", w.endA, 0)
	w.signed(a, a)
	b := darFeature("DARB", w.endB, 0)
	w.signed(b, a, b)
	if v := w.sub.Current(DatasetRestrictions); v == nil || v.Number != 2 || len(v.Features) != 2 {
		t.Fatalf("the set in use is not {A, B}: %+v", v)
	}
	return w
}

// signed publishes an ANSP-signed version (request = the signed bytes,
// served = the dataset) and pulls it; it must be installed.
func (w *expiryWorld) signed(request json.RawMessage, served ...json.RawMessage) {
	w.t.Helper()
	_, ansp := rings(w.t)
	if _, err := w.fake.Publish("restrictions", served, request, ansp, "restriction_created"); err != nil {
		w.t.Fatal(err)
	}
	if err := w.sub.Pull(context.Background(), DatasetRestrictions, nil); err != nil {
		w.t.Fatalf("an ANSP-signed version was not installed: %v", err)
	}
}

// expire publishes a version the CISP made: served, and record signed
// by ring as X-CIS-Signature (nil: none). It returns the pull's error.
func (w *expiryWorld) expire(record []byte, ring *auth.KeyRing, served ...json.RawMessage) error {
	w.t.Helper()
	return w.expireSigned(record, record, ring, served...)
}

// expireSigned is expire with the signature made over signedBytes
// (another set of bytes than the record served: tampering).
func (w *expiryWorld) expireSigned(record, signedBytes []byte, ring *auth.KeyRing, served ...json.RawMessage) error {
	w.t.Helper()
	sig := ""
	if ring != nil {
		var err error
		if sig, err = ring.SignDetached(signedBytes, time.Now()); err != nil {
			w.t.Fatal(err)
		}
	}
	if _, err := w.fake.PublishCISP("restrictions", served, record, sig, "restriction_expired"); err != nil {
		w.t.Fatal(err)
	}
	return w.sub.Pull(context.Background(), DatasetRestrictions, nil)
}

// installed checks that version n is in use, verified as an expiry.
func (w *expiryWorld) installed(err error, n int64, ids ...string) {
	w.t.Helper()
	if err != nil {
		w.t.Fatalf("the verified expiry was held: %v", err)
	}
	v := w.sub.Current(DatasetRestrictions)
	got := make([]string, 0, len(v.Features))
	for _, f := range v.Features {
		got = append(got, f.Identifier)
	}
	if v.Number != n || !slices.Equal(got, ids) {
		w.t.Fatalf("in use v%d %v, want v%d %v", v.Number, got, n, ids)
	}
	if st := stateOf(w.sub, DatasetRestrictions); st.Provenance != ProvenanceCISPExpiry || st.HeldVersion != nil {
		w.t.Fatalf("%+v", st)
	}
}

// held checks that err holds the version as not a verified expiry,
// naming why, and that version kept is still in use.
func (w *expiryWorld) held(err error, why string, kept int64) {
	w.t.Helper()
	var ue *UntrustedError
	if !asUntrusted(err, &ue) || !ue.Expiry || !strings.Contains(ue.Reason, why) {
		w.t.Fatalf("want held for %q, got %v", why, err)
	}
	if v := w.sub.Current(DatasetRestrictions); v.Number != kept {
		w.t.Fatalf("v%d in use, want v%d kept", v.Number, kept)
	}
	if st := stateOf(w.sub, DatasetRestrictions); st.HeldVersion == nil || *st.HeldVersion != ue.Version || st.HeldReason != ue.Reason {
		w.t.Fatalf("the hold is not shown: %+v", st)
	}
}

func cispRing(w *expiryWorld) *auth.KeyRing { return w.fake.Ring }

// Plan test 1. The set in use {A, B}; A reaches its end and the CISP
// serves {B} with its expiry record, signed by the CISP, without a
// publisher signature: installed as version 3, A gone, nothing held, the
// age reset and fresh, the projection written and announced, counted.
// The pair: the ANSP's next signed version (B ended) installs against
// the expiry's set (the chaining is unchanged).
func TestExpiryIsInstalledAndTheNextSignedVersionChainsOnIt(t *testing.T) {
	w := newExpiryWorld(t, -time.Minute)
	ctx := context.Background()
	w.now = w.now.Add(4 * time.Minute) // the age of v2 is 240 s
	if st := stateOf(w.sub, DatasetRestrictions); st.AgeS == nil || *st.AgeS != 240 {
		t.Fatalf("%+v", st)
	}
	b := darFeature("DARB", w.endB, 0)
	err := w.expire(cispRecord("expire", "DARA", w.endA, w.endA.Add(time.Second)), cispRing(w), b)
	w.installed(err, 3, "DARB")
	st := stateOf(w.sub, DatasetRestrictions)
	if st.AgeS == nil || *st.AgeS != 0 || st.Stale {
		t.Fatalf("the age was not reset by the install: %+v", st)
	}
	if w.count(CounterExpiryInstalled) != 1 || w.count(CounterExpiryHeld) != 0 || w.count(CounterUntrusted) != 0 {
		t.Fatalf("installed %d held %d untrusted %d", w.count(CounterExpiryInstalled), w.count(CounterExpiryHeld), w.count(CounterUntrusted))
	}
	if v, rows, _ := w.projector.get(); v != 3 || len(rows) != 1 || rows[0].Identifier != "DARB" || !w.projector.confirmedAt().Equal(w.now) {
		t.Fatalf("projection v%d %+v confirmed %v", v, rows, w.projector.confirmedAt())
	}
	if !slices.Contains(w.announcer.seen, "restrictions:3") {
		t.Fatalf("announced %v", w.announcer.seen)
	}
	if c, ok := w.cache.get(DatasetRestrictions); !ok || c.Version != 3 || c.PublisherKID != "" {
		t.Fatalf("cached %+v: an expiry has no publisher kid", c)
	}
	attrs := map[string]string{}
	parts := &Parts{Subscriber: w.sub, Publishers: NewPublishers(nil, 0, nil), Notify: NewLazyCompactVerifier(auth.CompactConfig{})}
	for _, a := range parts.StatusAttrs() {
		attrs[a.Key] = a.Value.String()
	}
	if attrs["cis_restrictions_provenance"] != ProvenanceCISPExpiry || attrs["cis_restrictions_version"] != "3" {
		t.Fatalf("status line %v", attrs)
	}

	// The pair: the ANSP ends B, signed; it installs on top of v3.
	_, ansp := rings(t)
	ended := json.RawMessage(strings.Replace(string(b), `"state":"active"`, `"state":"ended"`, 1))
	if _, err := w.fake.Publish("restrictions", []json.RawMessage{ended}, []byte(`{"op":"end","restriction_id":"r-DARB"}`), ansp, "restriction_ended"); err != nil {
		t.Fatal(err)
	}
	if err := w.sub.Pull(ctx, DatasetRestrictions, nil); err != nil {
		t.Fatal(err)
	}
	if v := w.sub.Current(DatasetRestrictions); v.Number != 4 || v.Features[0].Restriction.State != "ended" {
		t.Fatalf("the signed version after the expiry: %+v", v)
	}
	if st := stateOf(w.sub, DatasetRestrictions); st.Provenance != ProvenancePublisher || st.HeldVersion != nil {
		t.Fatalf("%+v", st)
	}
}

// The constraint of the rollout: a CISP older than the erratum serves
// its record without feature_id (and ends_at). The version is held
// exactly as before this change: the set in use stays, the hold is shown
// and counted. The pair: the same expiry with the full record installs.
func TestExpiryFromACISPWithoutFeatureIDIsHeldAsBefore(t *testing.T) {
	w := newExpiryWorld(t, -time.Minute)
	b := darFeature("DARB", w.endB, 0)
	err := w.expire(cispRecord("expire", "", w.endA, w.endA.Add(time.Second)), cispRing(w), b)
	w.held(err, "names no feature_id", 2)
	if w.count(CounterExpiryHeld) != 1 || w.count(CounterUntrusted) != 1 || w.count(CounterExpiryInstalled) != 0 {
		t.Fatalf("held %d untrusted %d installed %d", w.count(CounterExpiryHeld), w.count(CounterUntrusted), w.count(CounterExpiryInstalled))
	}
	if v, _, _ := w.projector.get(); v != 2 {
		t.Fatalf("the projection moved to v%d", v)
	}
	err = w.expire(cispRecord("expire", "DARA", w.endA, w.endA.Add(time.Second)), cispRing(w), b)
	w.installed(err, 4, "DARB")
}

// Plan test 2. Without X-CIS-Signature, signed by the ANSP's key or by a
// key nobody configured, or over other bytes than those served, and
// with no CISP keys configured at all: held, the set in use kept. The
// pair: the same record signed by the CISP installs.
func TestExpiryNeedsTheCISPSignatureOverTheServedBytes(t *testing.T) {
	w := newExpiryWorld(t, -time.Minute)
	b := darFeature("DARB", w.endB, 0)
	record := cispRecord("expire", "DARA", w.endA, w.endA.Add(time.Second))
	_, ansp := rings(t)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := auth.NewKeyRing(auth.SigningKey{KID: "fake-cisp-1", Key: k})
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(strings.Replace(string(record), `"DARA"`, `"DARB"`, 1))
	w.held(w.expire(record, nil, b), "no X-CIS-Signature", 2)
	w.held(w.expire(record, ansp, b), "X-CIS-Signature does not verify", 2)
	w.held(w.expire(record, stranger, b), "X-CIS-Signature does not verify", 2)
	w.held(w.expireSigned(record, tampered, cispRing(w), b), "X-CIS-Signature does not verify", 2)
	// No CISP keys configured (CIS_CISP_JWKS_URL and CISP_JWKS_URL unset).
	full := w.sub.cfg.Publishers
	authority, _ := rings(t)
	without := NewPublishers(map[string]auth.IssuerConfig{PublisherAuthority: {Keys: authority.JWKS()}, PublisherANSP: {Keys: ansp.JWKS()}}, 0, nil)
	if err := without.Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.sub.cfg.Publishers = without
	w.held(w.expire(record, cispRing(w), b), "no keys are configured for the publisher cisp", 2)
	if w.count(CounterExpiryHeld) != 5 || w.count(CounterExpiryInstalled) != 0 {
		t.Fatalf("held %d installed %d", w.count(CounterExpiryHeld), w.count(CounterExpiryInstalled))
	}
	w.sub.cfg.Publishers = full
	w.installed(w.expire(record, cispRing(w), b), 8, "DARB")
}

// Plan test 3. A removal before the removed restriction's signed end is
// held, also after an extend (the extended end is the one in use); an
// expiry whose at is more than cis_expiry_skew_s past this clock is
// held; at exactly one second inside the skew it installs.
func TestExpiryBeforeTheSignedEndOrPastTheSkewIsHeld(t *testing.T) {
	t.Run("before-the-end", func(t *testing.T) {
		w := newExpiryWorld(t, -time.Minute)
		b := darFeature("DARB", w.endB, 0)
		w.held(w.expire(cispRecord("expire", "DARA", w.endA, w.endA.Add(-time.Second)), cispRing(w), b), "before its signed end", 2)
		w.installed(w.expire(cispRecord("expire", "DARA", w.endA, w.endA), cispRing(w), b), 4, "DARB")
	})
	t.Run("after-an-extend", func(t *testing.T) {
		w := newExpiryWorld(t, -10*time.Minute)
		_, ansp := rings(t)
		extended := darFeatureBlock("DARA", w.now.Add(-time.Minute), 0, 2)
		request := []byte(fmt.Sprintf(`{"op":"extend","restriction_id":"r-DARA","feature":%s}`, extended))
		b := darFeature("DARB", w.endB, 0)
		if _, err := w.fake.Publish("restrictions", []json.RawMessage{extended, b}, request, ansp, "restriction_extended"); err != nil {
			t.Fatal(err)
		}
		if err := w.sub.Pull(context.Background(), DatasetRestrictions, nil); err != nil {
			t.Fatal(err)
		}
		// at between the original end and the extended one.
		at := w.endA.Add(5 * time.Minute)
		w.held(w.expire(cispRecord("expire", "DARA", w.endA, at), cispRing(w), b), "before its signed end", 3)
		w.installed(w.expire(cispRecord("expire", "DARA", w.now.Add(-time.Minute), w.now.Add(-time.Minute)), cispRing(w), b), 5, "DARB")
	})
	t.Run("past-the-skew", func(t *testing.T) {
		w := newExpiryWorld(t, DefaultExpirySkew-time.Second)
		b := darFeature("DARB", w.endB, 0)
		late := w.now.Add(DefaultExpirySkew + time.Second)
		w.held(w.expire(cispRecord("expire", "DARA", w.endA, late), cispRing(w), b), "later than this clock plus cis_expiry_skew_s", 2)
		inside := w.now.Add(DefaultExpirySkew - time.Second)
		w.installed(w.expire(cispRecord("expire", "DARA", w.endA, inside), cispRing(w), b), 4, "DARB")
	})
}

// Plan test 4. The CISP's version adds a feature, changes one (any
// member but the CISP's cis_*), removes none, or names in feature_id a
// feature it does not remove: held. The pair: removing A with B unchanged
// but for its cis_restriction block installs.
func TestExpiryAddsOrChangesNothing(t *testing.T) {
	w := newExpiryWorld(t, -time.Minute)
	b := darFeature("DARB", w.endB, 0)
	a := darFeature("DARA", w.endA, 0)
	rec := cispRecord("expire", "DARA", w.endA, w.endA.Add(time.Second))
	c := darFeature("DARC", w.endB, 0)
	w.held(w.expire(rec, cispRing(w), b, c), `feature "DARC" is added`, 2)
	w.held(w.expire(rec, cispRing(w), darFeature("DARB", w.endB, 10)), `feature "DARB" is changed`, 2)
	w.held(w.expire(rec, cispRing(w), a, b), "it removes no feature", 2)
	w.held(w.expire(cispRecord("expire", "DARB", w.endA, w.endA.Add(time.Second)), cispRing(w), b), `feature_id "DARB" is not among the removed`, 2)
	if w.count(CounterExpiryHeld) != 4 {
		t.Fatalf("held %d", w.count(CounterExpiryHeld))
	}
	w.installed(w.expire(rec, cispRing(w), darFeatureBlock("DARB", w.endB, 0, 7)), 7, "DARB")
}

// Plan test 5. After the expiry is installed: the CISP serving it again
// is a confirmation, never a second install; a notification of it or of
// an older version is a counted replay; an older version the CISP made,
// served after a newer signed one, is never installed.
func TestExpiryIsNeverReinstalledOrDowngraded(t *testing.T) {
	w := newExpiryWorld(t, -time.Minute)
	ctx := context.Background()
	b := darFeature("DARB", w.endB, 0)
	w.installed(w.expire(cispRecord("expire", "DARA", w.endA, w.endA.Add(time.Second)), cispRing(w), b), 3, "DARB")
	expiry := w.fake.Current("restrictions")
	_, _, writes := w.projector.get()
	announced := len(w.announcer.seen)
	notModified := w.count(CounterNotModified)
	if err := w.sub.Pull(ctx, DatasetRestrictions, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, n := w.projector.get(); n != writes || len(w.announcer.seen) != announced || w.count(CounterNotModified) != notModified+1 ||
		w.count(CounterExpiryInstalled) != 1 {
		t.Fatalf("served again: writes %d->%d, announced %d->%d, installed %d", writes, n, announced, len(w.announcer.seen), w.count(CounterExpiryInstalled))
	}
	for _, n := range []int64{3, 2} {
		replays := w.count(CounterVersionReplays)
		if err := w.sub.Pull(ctx, DatasetRestrictions, &Hint{Version: n}); err != nil {
			t.Fatal(err)
		}
		if w.count(CounterVersionReplays) != replays+1 || w.sub.Current(DatasetRestrictions).Number != 3 {
			t.Fatalf("a notification of v%d: replays %d", n, w.count(CounterVersionReplays))
		}
	}
	// A newer signed version, then the CISP's v3 offered again.
	cf := darFeature("DARC", w.endB, 0)
	w.signed(cf, b, cf)
	old, rf := ParseVersion(w.sub.cfg.Schemas, DatasetRestrictions, expiry.Served, "", expiry.Number)
	if rf != nil {
		t.Fatal(rf)
	}
	replays := w.count(CounterVersionReplays)
	cur := w.sub.Current(DatasetRestrictions)
	if err := w.sub.accept(ctx, old, cur, false); err != nil {
		t.Fatal(err)
	}
	if v := w.sub.Current(DatasetRestrictions); v.Number != 4 || w.count(CounterVersionReplays) != replays+1 || w.count(CounterExpiryInstalled) != 1 {
		t.Fatalf("the older CISP version: in use v%d, replays %d, installed %d", v.Number, w.count(CounterVersionReplays), w.count(CounterExpiryInstalled))
	}
	if st := stateOf(w.sub, DatasetRestrictions); st.Provenance != ProvenancePublisher {
		t.Fatalf("%+v", st)
	}
}

// Plan test 6. A CISP-signed record whose op is not expire is held; a
// zones version without a publisher signature is held as before, even
// with a CISP-signed expiry record (the exception is restrictions
// only), and counts no expiry. The pair: op expire on restrictions
// installs.
func TestExpiryIsTheExpireOpOnRestrictionsOnly(t *testing.T) {
	w := newExpiryWorld(t, -time.Minute)
	b := darFeature("DARB", w.endB, 0)
	w.held(w.expire(cispRecord("end", "DARA", w.endA, w.endA.Add(time.Second)), cispRing(w), b), `op "end", not expire`, 2)
	w.held(w.expire([]byte(`["expire"]`), cispRing(w), b), "not the CISP's expiry record", 2)

	w.publishZones(t, true, "TST001")
	if err := w.sub.Pull(context.Background(), DatasetZones, nil); err != nil {
		t.Fatal(err)
	}
	record := cispRecord("expire", "TST001", w.endA, w.endA.Add(time.Second))
	sig, err := w.fake.Ring.SignDetached(record, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := zoneFeatures()
	if _, err := w.fake.PublishCISP("zones", fs, record, sig, "publication"); err != nil {
		t.Fatal(err)
	}
	err = w.sub.Pull(context.Background(), DatasetZones, nil)
	var ue *UntrustedError
	if !asUntrusted(err, &ue) || ue.Expiry || !strings.Contains(ue.Reason, "a version the CISP made itself is not used") {
		t.Fatalf("an unsigned zones version: %v", err)
	}
	if v := w.sub.Current(DatasetZones); v.Number != 1 {
		t.Fatalf("zones v%d in use", v.Number)
	}
	if w.count(CounterExpiryHeld) != 2 {
		t.Fatalf("held %d: the zones hold is not an expiry", w.count(CounterExpiryHeld))
	}
	w.installed(w.expire(cispRecord("expire", "DARA", w.endA, w.endA.Add(time.Second)), cispRing(w), b), 5, "DARB")
}

// Plan test 7, the original failure. After every natural expiry the
// CISP serves the version it made on every reconciliation: held (here
// the pre-fix rule, an op this build does not take), nothing confirms
// the version in use, its age climbs past cis_stale_bound_s and the
// dataset turns cis_stale (the transition logged and counted, the
// projection's confirmed_at frozen). With the expiry verified the same
// reconciliations keep it fresh.
func TestExpiryKeepsTheRestrictionsOutOfCISStale(t *testing.T) {
	run := func(t *testing.T, op string) (*expiryWorld, CacheState) {
		w := newExpiryWorld(t, -time.Minute)
		ctx := context.Background()
		w.sub.cfg.StaleBoundS = func() float64 { return 300 }
		w.sub.checkStale(ctx) // the three datasets never pulled turn stale
		if n := w.count(CounterStaleTransitions); n != 3 {
			t.Fatalf("stale transitions at start %d", n)
		}
		_ = w.expire(cispRecord(op, "DARA", w.endA, w.endA.Add(time.Second)), cispRing(w), darFeature("DARB", w.endB, 0))
		for range 6 {
			w.now = w.now.Add(time.Minute)
			_ = w.sub.Pull(ctx, DatasetRestrictions, nil)
			w.sub.checkStale(ctx)
		}
		return w, stateOf(w.sub, DatasetRestrictions)
	}
	t.Run("held", func(t *testing.T) {
		w, st := run(t, "expire_unknown")
		if !st.Stale || st.AgeS == nil || *st.AgeS != 360 || *st.Version != 2 || st.HeldVersion == nil || *st.HeldVersion != 3 {
			t.Fatalf("the held expiry did not age the set in use into cis_stale: %+v", st)
		}
		if w.count(CounterStaleTransitions) != 4 || w.count(CounterExpiryHeld) != 7 {
			t.Fatalf("stale transitions %d, held %d", w.count(CounterStaleTransitions), w.count(CounterExpiryHeld))
		}
		if got := w.projector.confirmedAt(); !got.Equal(w.now.Add(-6 * time.Minute)) {
			t.Fatalf("confirmed_at %v moved while the version was held", got)
		}
	})
	t.Run("verified", func(t *testing.T) {
		w, st := run(t, "expire")
		if st.Stale || st.AgeS == nil || *st.AgeS != 0 || *st.Version != 3 || st.HeldVersion != nil {
			t.Fatalf("%+v", st)
		}
		if w.count(CounterStaleTransitions) != 3 || w.count(CounterExpiryInstalled) != 1 {
			t.Fatalf("stale transitions %d, installed %d", w.count(CounterStaleTransitions), w.count(CounterExpiryInstalled))
		}
		if got := w.projector.confirmedAt(); !got.Equal(w.now) {
			t.Fatalf("confirmed_at %v, want %v", got, w.now)
		}
	})
}
