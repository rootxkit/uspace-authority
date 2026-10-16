package cisp

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DefaultExpirySkew is cis_expiry_skew_s when nothing configures it
// (CIS_EXPIRY_SKEW_S): how far past this system's clock the at of a
// CISP expiry record may be. A CISP whose key is misused can then end a
// restriction at most this early in the version bookkeeping; the
// detectors judge each restriction's own window regardless.
const DefaultExpirySkew = 30 * time.Second

// expiryOp is the op of the CISP's expiry record, one no publisher can
// send (a publisher's PATCH ops are activate, extend, end and cancel).
const expiryOp = "expire"

// expiryCheck is what a restrictions version the CISP made itself is
// judged against (spec 02 F3 erratum, 2026-10-16).
type expiryCheck struct {
	// Prev is the restrictions version in use, each feature as it was
	// bound to its publisher's signature when installed; nil when none.
	Prev *Version
	// Now is this system's clock and Skew cis_expiry_skew_s.
	Now  time.Time
	Skew time.Duration
}

// expiryRecord is the CISP's expiry record: the bytes
// /v1/restrictions/versions/{v} serves for a version the CISP made
// when a restriction reached its end, signed by X-CIS-Signature. A CISP
// older than the erratum sends op, restriction_id and at only.
type expiryRecord struct {
	Op            string     `json:"op"`
	RestrictionID string     `json:"restriction_id"`
	FeatureID     string     `json:"feature_id"`
	EndsAt        *time.Time `json:"ends_at"`
	At            *time.Time `json:"at"`
}

// checkExpiry decides whether v, a restrictions version served without
// X-Publisher-Signature, is a verified expiry of the set in use: its
// bytes are the CISP's expiry record and X-CIS-Signature over them
// verifies with the CISP's keys (kid and iat under the publisher
// signature rules, CIS_PUBLISHER_SIG_MAX_AGE_S); the record's at is not
// later than ex.Now plus ex.Skew; and, compared feature by feature with
// ex.Prev without the CISP's cis_* members, v removes one or more
// features and adds or changes none, every removed feature has one
// limitedApplicability period whose endDateTime is at or before at, and
// feature_id is one of them. Anything else is an *UntrustedError with
// Expiry set, naming why: the version is held as before. The removed
// restrictions are ended by installing v; whether a restriction applies
// is still judged from its own window (the detectors), never from this.
func checkExpiry(ctx context.Context, pv PublisherVerifier, v *Version, f *Fetched, ex expiryCheck) (Provenance, error) {
	held := func(format string, a ...any) (Provenance, error) {
		return Provenance{}, &UntrustedError{Dataset: v.Dataset, Version: v.Number, Expiry: true,
			Reason: fmt.Sprintf("no %s and not a verified expiry: %s", HeaderPublisherSignature, fmt.Sprintf(format, a...))}
	}
	if strings.TrimSpace(f.CISSignature) == "" {
		return held("no %s", HeaderCISSignature)
	}
	sig, err := pv.Verify(ctx, PublisherCISP, f.CISSignature, f.Body)
	if err != nil {
		return held("%s does not verify with the CISP's keys: %s", HeaderCISSignature, short(err.Error()))
	}
	var rec expiryRecord
	if err := json.Unmarshal(f.Body, &rec); err != nil {
		return held("the version's bytes are not the CISP's expiry record: %s", short(err.Error()))
	}
	switch {
	case rec.Op != expiryOp:
		return held("the CISP's record is op %q, not %s", short(rec.Op), expiryOp)
	case rec.FeatureID == "":
		return held("the expiry record names no feature_id (a CISP older than the 02 F3 erratum)")
	case rec.RestrictionID == "":
		return held("the expiry record names no restriction_id")
	case rec.EndsAt == nil:
		return held("the expiry record has no ends_at")
	case rec.At == nil:
		return held("the expiry record has no at")
	}
	at := *rec.At
	if latest := ex.Now.Add(ex.Skew); at.After(latest) {
		return held("the expiry is at %s, later than this clock plus cis_expiry_skew_s (%s)",
			at.UTC().Format(time.RFC3339), latest.UTC().Format(time.RFC3339))
	}
	if ex.Prev == nil {
		return held("no restrictions version is in use to compare it with")
	}
	prev := make(map[string]*Feature, len(ex.Prev.Features))
	for i := range ex.Prev.Features {
		prev[ex.Prev.Features[i].Identifier] = &ex.Prev.Features[i]
	}
	kept := make(map[string]bool, len(v.Features))
	for i := range v.Features {
		ft := &v.Features[i]
		p, ok := prev[ft.Identifier]
		if !ok {
			return held("feature %q is added", short(ft.Identifier))
		}
		was, okWas := canonicalRaw(p.Raw)
		now, okNow := canonicalRaw(ft.Raw)
		if !okWas || !okNow || was != now {
			return held("feature %q is changed", short(ft.Identifier))
		}
		kept[ft.Identifier] = true
	}
	var removed []string
	for i := range ex.Prev.Features {
		p := &ex.Prev.Features[i]
		if kept[p.Identifier] {
			continue
		}
		end, ok := signedEnd(p)
		if !ok {
			return held("removed feature %q has not one limitedApplicability period with an endDateTime", short(p.Identifier))
		}
		if end.After(at) {
			return held("feature %q is removed at %s, before its signed end %s", short(p.Identifier),
				at.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
		}
		removed = append(removed, p.Identifier)
	}
	if len(removed) == 0 {
		return held("it removes no feature")
	}
	if !slices.Contains(removed, rec.FeatureID) {
		return held("feature_id %q is not among the removed features", short(rec.FeatureID))
	}
	return Provenance{Kind: ProvenanceCISPExpiry, KID: sig.KID, Removed: removed}, nil
}

// signedEnd is the endDateTime of f's single limitedApplicability
// period: the end its publisher signed (the CISP accepts a restriction
// only when that period equals its window, and each feature in use was
// bound to the publisher's request when installed).
func signedEnd(f *Feature) (time.Time, bool) {
	if len(f.Applicability) != 1 || f.Applicability[0].EndDateTime == nil {
		return time.Time{}, false
	}
	return f.Applicability[0].EndDateTime.Time, true
}

// canonicalRaw is the canonical form of a served feature without the
// CISP's cis_* members; false when it is not a JSON object.
func canonicalRaw(raw json.RawMessage) (string, bool) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", false
	}
	return canonicalFeature(m), true
}
