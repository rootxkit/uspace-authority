package cisp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// DefaultPublisherSigMaxAge is how old a publisher's signature on a
// pulled version may be. The publisher's iat is the publication time and
// the CISP forwards that signature unchanged for the life of the
// version, so a signature is as old as its version: 366 days lets a
// dataset left unpublished for a year still verify; an older one is held,
// visibly (CIS_PUBLISHER_SIG_MAX_AGE_S raises it). The replay guard is
// the version number, which only moves forward.
const DefaultPublisherSigMaxAge = 366 * 24 * time.Hour

// DefaultKeysRetry is the wait between two attempts to fetch a
// publisher's JWKS that could not be fetched.
const DefaultKeysRetry = 30 * time.Second

// PublisherVerifier verifies a publisher's detached JWS over a version's
// bytes (core's auth.DetachedVerifier; Publishers).
type PublisherVerifier interface {
	Verify(ctx context.Context, publisher, header string, payload []byte) (coreauth.Signature, error)
}

// UntrustedError is a version whose provenance could not be shown: its
// publisher's signature is missing, does not verify, or there are no
// keys to verify it with. The version is not used; the one held before
// stays and the console says so.
type UntrustedError struct {
	Dataset Dataset
	Version int64
	Reason  string
	// Mismatch is true when the signature verified but what was
	// served (or merged from a delta) is not what it signs (audit A-B2).
	Mismatch bool
}

func (e *UntrustedError) Error() string {
	return fmt.Sprintf("%s version %d held, not used: %s", e.Dataset, e.Version, e.Reason)
}

// Publishers holds one detached verifier per publisher (the authority
// for its own datasets, the ANSP for the restrictions), each built when
// its keys can be read: a publisher whose JWKS cannot be fetched holds
// its own datasets' new versions only, never the other's.
type Publishers struct {
	mu    sync.Mutex
	cfg   map[string]coreauth.DetachedConfig
	built map[string]*atomic.Pointer[coreauth.DetachedVerifier]
	errs  map[string]string
	retry time.Duration
}

// NewPublishers configures one verifier per publisher with its keys (a
// JWKS URL or a static set) and maxAge.
func NewPublishers(keys map[string]coreauth.IssuerConfig, maxAge time.Duration, httpClient *http.Client) *Publishers {
	if maxAge <= 0 {
		maxAge = DefaultPublisherSigMaxAge
	}
	p := &Publishers{cfg: map[string]coreauth.DetachedConfig{}, built: map[string]*atomic.Pointer[coreauth.DetachedVerifier]{},
		errs: map[string]string{}, retry: DefaultKeysRetry}
	for name, k := range keys {
		p.cfg[name] = coreauth.DetachedConfig{
			Publishers: map[string]coreauth.IssuerConfig{name: k}, MaxAge: maxAge, MaxPayloadBytes: MaxBodyBytes, HTTPClient: httpClient,
		}
		p.built[name] = &atomic.Pointer[coreauth.DetachedVerifier]{}
	}
	return p
}

// Build tries once to build every verifier not built yet; it returns
// the first failure.
func (p *Publishers) Build(ctx context.Context) error {
	var errs []error
	for _, name := range p.names() {
		if p.built[name].Load() != nil {
			continue
		}
		v, err := coreauth.NewDetachedVerifier(ctx, p.cfg[name])
		p.mu.Lock()
		if err != nil {
			p.errs[name] = short(err.Error())
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		} else {
			delete(p.errs, name)
			p.built[name].Store(v)
		}
		p.mu.Unlock()
	}
	return errors.Join(errs...)
}

func (p *Publishers) names() []string {
	out := make([]string, 0, len(p.cfg))
	for n := range p.cfg {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Run builds the verifiers, trying again every retry period until all
// are built or ctx ends.
func (p *Publishers) Run(ctx context.Context) {
	t := time.NewTicker(p.retry)
	defer t.Stop()
	for p.Build(ctx) != nil {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Verify verifies with the publisher's verifier, or refuses naming why.
func (p *Publishers) Verify(ctx context.Context, publisher, header string, payload []byte) (coreauth.Signature, error) {
	b, ok := p.built[publisher]
	if !ok {
		return coreauth.Signature{}, fmt.Errorf("no keys are configured for the publisher %s", publisher)
	}
	if v := b.Load(); v != nil {
		return v.Verify(ctx, publisher, header, payload)
	}
	p.mu.Lock()
	why := p.errs[publisher]
	p.mu.Unlock()
	if why == "" {
		why = "not fetched yet"
	}
	return coreauth.Signature{}, fmt.Errorf("the %s's keys are not available: %s", publisher, why)
}

// Counters merges the built verifiers' counters, prefixed by publisher.
func (p *Publishers) Counters() *core.Counters {
	out := &core.Counters{}
	for _, name := range p.names() {
		if v := p.built[name].Load(); v != nil {
			for k, n := range v.Counters().Snapshot() {
				out.Add(name+"_"+k, n)
			}
		}
	}
	return out
}

// Missing lists the publishers whose keys are not available, with why.
func (p *Publishers) Missing() []string {
	var out []string
	for _, name := range p.names() {
		if p.built[name].Load() != nil {
			continue
		}
		p.mu.Lock()
		why := p.errs[name]
		p.mu.Unlock()
		if why == "" {
			why = "not fetched yet"
		}
		out = append(out, name+": "+why)
	}
	return out
}

// VersionReader reads a version as published.
type VersionReader interface {
	GetVersion(ctx context.Context, ds Dataset, v int64) (Fetched, error)
}

// checkProvenance reads version v as published (GET
// /v1/{dataset}/versions/{v}) and verifies X-Publisher-Signature over its
// bytes with the keys of the dataset's publisher. It returns an
// *UntrustedError when the signature is missing or does not verify (or
// there are no keys), with the kid that verified otherwise, and another
// error when the version could not be read (a pull failure: nothing is
// held, the next pull tries again). A version the CISP made itself (a
// restriction expiring) carries no publisher signature and is held
// until the publisher's next signed version (spec gap, in the runbook).
func checkProvenance(ctx context.Context, r VersionReader, pv PublisherVerifier, v *Version) (string, error) {
	untrusted := func(format string, a ...any) (string, error) {
		return "", &UntrustedError{Dataset: v.Dataset, Version: v.Number, Reason: fmt.Sprintf(format, a...)}
	}
	if pv == nil {
		return untrusted("no publisher keys are configured")
	}
	f, err := r.GetVersion(ctx, v.Dataset, v.Number)
	if err != nil {
		return "", fmt.Errorf("reading %s version %d as published: %w", v.Dataset, v.Number, err)
	}
	if f.Status != http.StatusOK {
		return "", fmt.Errorf("reading %s version %d as published: the CISP answered %d", v.Dataset, v.Number, f.Status)
	}
	if f.Version != 0 && f.Version != v.Number {
		return untrusted("the CISP served version %d for version %d", f.Version, v.Number)
	}
	if strings.TrimSpace(f.PublisherSignature) == "" {
		return untrusted("no %s (a version the CISP made itself is not used until its publisher signs the next)", HeaderPublisherSignature)
	}
	pub := PublisherOf(v.Dataset)
	sig, err := pv.Verify(ctx, pub, f.PublisherSignature, f.Body)
	if err != nil {
		return untrusted("%s does not verify with the %s's keys: %s", HeaderPublisherSignature, pub, short(err.Error()))
	}
	if f.PublisherKID != "" && f.PublisherKID != sig.KID {
		return untrusted("%s names %q, the signature's kid is %q", HeaderPublisherKID, short(f.PublisherKID), sig.KID)
	}
	if why := signedContentDiffers(v, f.Body); why != "" {
		return "", &UntrustedError{Dataset: v.Dataset, Version: v.Number, Reason: why, Mismatch: true}
	}
	return sig.KID, nil
}

// signedContentDiffers ties what is about to be installed to the bytes
// the publisher signed (audit A-B2): a signature verified over one body
// says nothing about another. It returns why v is not the signed
// content, or "" when it is.
//
//   - ussp_list: the served list, without the CISP's top-level cis_
//     members, must be the signed list.
//   - zones and uspace_airspace (the signed bytes are the whole
//     collection): the served features must be exactly the signed
//     features, by identifier and content.
//   - restrictions (the signed bytes are the ANSP's request for one
//     restriction): the request's feature must be served as it was
//     signed; a create's feature must be present. The other features of
//     the version are covered only by the requests that made them (the
//     CISP composes the dataset; spec gap in the runbook).
//
// Features are compared as canonical JSON (member order and number
// spelling do not matter) without the extendedProperties members
// starting with cis_, which the CISP adds.
func signedContentDiffers(v *Version, signed []byte) string {
	var top map[string]any
	if err := json.Unmarshal(signed, &top); err != nil {
		return "the signed bytes are not a JSON object"
	}
	if !v.Dataset.ED318() {
		var served map[string]any
		if err := json.Unmarshal(v.Body, &served); err != nil {
			return "the served list is not a JSON object"
		}
		if canonical(withoutTopCIS(top)) != canonical(withoutTopCIS(served)) {
			return "the served list is not the list its publisher signed"
		}
		return ""
	}
	held := make(map[string]string, len(v.Features))
	for _, f := range v.Features {
		var m map[string]any
		if err := json.Unmarshal(f.Raw, &m); err != nil {
			return fmt.Sprintf("served feature %q is not a JSON object", short(f.Identifier))
		}
		held[f.Identifier] = canonicalFeature(m)
	}
	if top["type"] == "FeatureCollection" {
		feats, _ := top["features"].([]any)
		seen := make(map[string]bool, len(feats))
		for _, raw := range feats {
			m, _ := raw.(map[string]any)
			id := featureIdentifier(m)
			if id == "" {
				return "a signed feature has no properties.identifier"
			}
			seen[id] = true
			got, ok := held[id]
			switch {
			case !ok:
				return fmt.Sprintf("signed feature %q is not served", short(id))
			case got != canonicalFeature(m):
				return fmt.Sprintf("served feature %q is not the feature its publisher signed", short(id))
			}
		}
		for _, f := range v.Features {
			if !seen[f.Identifier] {
				return fmt.Sprintf("served feature %q is not in the signed version", short(f.Identifier))
			}
		}
		return ""
	}
	if v.Dataset != DatasetRestrictions {
		return "the signed bytes are not a feature collection"
	}
	feat, _ := top["feature"].(map[string]any)
	if top["type"] == "Feature" {
		feat = top
	}
	if feat == nil {
		// An op without a feature (end, cancel, extend): nothing in the
		// request to compare.
		return ""
	}
	id := featureIdentifier(feat)
	if id == "" {
		return "the signed feature has no properties.identifier"
	}
	got, ok := held[id]
	_, patch := top["op"]
	switch {
	case !ok && patch:
		return ""
	case !ok:
		return fmt.Sprintf("signed feature %q is not served", short(id))
	case got != canonicalFeature(feat):
		return fmt.Sprintf("served feature %q is not the feature its publisher signed", short(id))
	}
	return ""
}

func featureIdentifier(m map[string]any) string {
	props, _ := m["properties"].(map[string]any)
	id, _ := props["identifier"].(string)
	return id
}

// canonicalFeature is m as canonical JSON without the extendedProperties
// members the CISP adds (cis_*); m is changed.
func canonicalFeature(m map[string]any) string {
	if props, ok := m["properties"].(map[string]any); ok {
		if ext, ok := props["extendedProperties"].(map[string]any); ok {
			for k := range ext {
				if strings.HasPrefix(k, "cis_") {
					delete(ext, k)
				}
			}
			if len(ext) == 0 {
				delete(props, "extendedProperties")
			}
		}
	}
	return canonical(m)
}

func withoutTopCIS(m map[string]any) map[string]any {
	for k := range m {
		if strings.HasPrefix(k, "cis_") {
			delete(m, k)
		}
	}
	return m
}

// canonical is v marshalled again: object members sorted, numbers as
// float64.
func canonical(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
