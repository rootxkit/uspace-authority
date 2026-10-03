package incidents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"
	"unicode/utf8"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Counters of the evidence packs (E-09).
const (
	CounterPackBuilt          = "evidence_packs_built"
	CounterPackRefused        = "evidence_packs_refused"   // a build refused (window, size, role, storage, busy)
	CounterPackBusy           = "evidence_packs_busy"      // a build refused past the concurrency bound (E-10)
	CounterPackReadBusy       = "evidence_pack_reads_busy" // a download or verification refused past its bound (E-10)
	CounterPackUnsigned       = "evidence_packs_unsigned"  // built without a publication key
	CounterPackOrphaned       = "evidence_packs_orphaned"  // stored but not recorded (the transaction failed)
	CounterPackDownloaded     = "evidence_packs_downloaded"
	CounterPackVerified       = "evidence_packs_verified"
	CounterPackTampered       = "evidence_packs_tampered"       // a stored archive that does not match its hash
	CounterPackUnreadable     = "evidence_packs_unreadable"     // a stored archive that cannot be read (storage, key): not evidence of tampering
	CounterSectionUnavailable = "evidence_sections_unavailable" // a section of a built pack unavailable
)

// PublisherAuthority names this system's publication key to the
// detached verifier.
const PublisherAuthority = "authority"

// SealSchema names the seal statement's shape.
const SealSchema = "evidence-pack-seal/v1"

// SealStatement is what a pack's signature covers. Its bytes are
// json.Marshal of this struct (fixed member order), rebuilt from the
// evidence_packs columns to verify: a changed hash, window or id breaks
// the signature as surely as a changed archive breaks the hash.
type SealStatement struct {
	Schema      string `json:"schema"`
	PackID      string `json:"pack_id"`
	IncidentID  string `json:"incident_id"`
	Kind        string `json:"kind"`
	WindowFrom  string `json:"window_from"`
	WindowTo    string `json:"window_to"`
	ContentHash string `json:"content_hash"`
	SizeBytes   int64  `json:"size_bytes"`
	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by"`
}

// Bytes are the signed bytes.
func (s SealStatement) Bytes() []byte {
	b, _ := json.Marshal(s) //nolint:errchkjson // a struct of strings and an integer always marshals
	return b
}

func sealOf(r *gen.EvidencePack) SealStatement {
	return SealStatement{Schema: SealSchema, PackID: r.PackID, IncidentID: r.IncidentID, Kind: r.Kind, WindowFrom: stamp(r.WindowFrom),
		WindowTo: stamp(r.WindowTo), ContentHash: r.ContentHash, SizeBytes: r.SizeBytes, CreatedAt: stamp(r.CreatedAt),
		CreatedBy: r.CreatedBy}
}

// Signer signs seal statements (the publication key ring of
// uspace-core/auth).
type Signer interface {
	SignDetached(payload []byte, now time.Time) (string, error)
	KIDs() []string
}

// Verifier verifies a detached signature (uspace-core/auth's
// DetachedVerifier).
type Verifier interface {
	Verify(ctx context.Context, publisher, header string, payload []byte) (coreauth.Signature, error)
}

// Packs builds, stores, serves and verifies evidence packs.
type Packs struct {
	Service *Service
	Builder *Builder
	// Storage nil: every pack operation is refused with 503.
	Storage Storage
	// Sealer seals a legal pack's archive at rest (the PII key).
	Sealer *pii.Sealer
	// Signer nil: packs are unsigned, said in the manifest and counted.
	Signer   Signer
	Verifier Verifier
	// MaxWindow bounds a pack's window; MaxBytes its archive.
	MaxWindow time.Duration
	MaxBytes  int64
	// BuildTimeout bounds one build.
	BuildTimeout time.Duration
	// ReadConcurrency bounds the downloads and verifications at once
	// (each holds a whole archive in memory; audit B-S5).
	ReadConcurrency int
	// sem bounds the builds at once, readSem the reads (E-10).
	sem      chan struct{}
	readSem  chan struct{}
	Counters *core.Counters
	Logger   *slog.Logger
}

// DefaultReadConcurrency is ReadConcurrency when it is not set.
const DefaultReadConcurrency = 4

// NewPacks returns p with its build bound set to concurrency and its
// read bound to ReadConcurrency.
func NewPacks(p *Packs, concurrency int) *Packs {
	if concurrency < 1 {
		concurrency = 1
	}
	p.sem = make(chan struct{}, concurrency)
	reads := p.ReadConcurrency
	if reads < 1 {
		reads = DefaultReadConcurrency
	}
	p.readSem = make(chan struct{}, reads)
	return p
}

// acquireRead takes a read slot or refuses (503 pack_busy, counted):
// every download and verification holds a whole archive in memory, so
// they are bounded like the builds (audit B-S5). release is to be
// deferred.
func (p *Packs) acquireRead() (release func(), err error) {
	if p.readSem == nil {
		return func() {}, nil
	}
	select {
	case p.readSem <- struct{}{}:
		return func() { <-p.readSem }, nil
	default:
		p.inc(CounterPackReadBusy)
		return nil, httpx.Refuse(http.StatusServiceUnavailable, SlugPackBusy,
			"as many packs as configured are being read; try again shortly")
	}
}

func (p *Packs) inc(name string) {
	if p.Counters != nil {
		p.Counters.Inc(name)
	}
}

func (p *Packs) refuse(err error) error {
	p.inc(CounterPackRefused)
	return err
}

// PackRequest is one pack to build.
type PackRequest struct {
	Kind     string
	From, To time.Time
	Purpose  string
	CaseRef  string
}

func checkPurpose(field, v string) error {
	if v == "" {
		return core.Fieldf(field, "required: say why the evidence is assembled or read")
	}
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > 200 {
		return core.Fieldf(field, "at most 200 characters of UTF-8")
	}
	return nil
}

func forbiddenLegal() error {
	return httpx.Refuse(http.StatusForbidden, httpx.SlugForbidden,
		"a legal pack carries personal data: only a personal-data role (inspector) builds or downloads one")
}

func (p *Packs) storageOK() error {
	if p.Storage == nil {
		return httpx.Refuse(http.StatusServiceUnavailable, SlugStorageUnavailable, ErrNoStorage.Error())
	}
	return nil
}

func packNotFound(id string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such evidence pack",
		core.Fieldf("pack_id", "%q is not a pack of this incident", id))
}

// Create builds the pack of r for the incident, seals it (hash, and the
// signature of the seal statement), stores it, and records it with its
// evidence_pack_built events row (purpose, hash) in one transaction.
// piiRole says the session holds a personal-data role.
func (p *Packs) Create(ctx context.Context, actor audit.Actor, piiRole bool, incidentID string, r PackRequest) (gen.EvidencePack, error) {
	if err := p.checkRequest(piiRole, &r); err != nil {
		return gen.EvidencePack{}, p.refuse(err)
	}
	if err := p.storageOK(); err != nil {
		return gen.EvidencePack{}, p.refuse(err)
	}
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	default:
		p.inc(CounterPackBusy)
		return gen.EvidencePack{}, p.refuse(httpx.Refuse(http.StatusServiceUnavailable, SlugPackBusy,
			"as many packs as configured are being built; try again shortly"))
	}
	if p.BuildTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.BuildTimeout)
		defer cancel()
	}
	view, err := p.Service.Get(ctx, incidentID)
	if err != nil {
		return gen.EvidencePack{}, err
	}
	// The database's clock places the pack (never the replica's).
	createdAt, err := p.Service.DB.Queries().DBNow(ctx)
	if err != nil {
		return gen.EvidencePack{}, err
	}
	createdAt = createdAt.UTC()
	packID := p.Service.newID()
	manifest, entries, err := p.Builder.Build(ctx, BuildInput{Incident: view, PackID: packID, Kind: r.Kind, From: r.From, To: r.To,
		Purpose: r.Purpose, CaseRef: r.CaseRef, Actor: actor, CreatedAt: createdAt})
	if err != nil {
		return gen.EvidencePack{}, p.refuse(err)
	}
	archive, manifestJSON, err := Seal(manifest, entries)
	if err != nil {
		return gen.EvidencePack{}, err
	}
	if int64(len(archive)) > p.MaxBytes {
		return gen.EvidencePack{}, p.refuse(httpx.Refuse(http.StatusRequestEntityTooLarge, SlugPackTooLarge,
			"the archive is larger than a pack carries; it is refused rather than thinned: narrow the window",
			core.Fieldf("to", "the archive is %d bytes, at most %d", len(archive), p.MaxBytes)))
	}
	row := gen.EvidencePack{PackID: packID, IncidentID: incidentID, Kind: r.Kind, WindowFrom: r.From.UTC(), WindowTo: r.To.UTC(),
		ContentHash: ContentHash(archive), SizeBytes: int64(len(archive)), Manifest: manifestJSON, CreatedBy: actor.ID,
		Purpose: r.Purpose, CreatedAt: createdAt}
	if r.CaseRef != "" {
		row.CaseRef = &r.CaseRef
	}
	seal := sealOf(&row)
	if row.SealStatement, err = json.Marshal(seal); err != nil {
		return gen.EvidencePack{}, err
	}
	if p.Signer != nil {
		sig, err := p.Signer.SignDetached(seal.Bytes(), createdAt)
		if err != nil {
			return gen.EvidencePack{}, err
		}
		h, err := coreauth.ParseDetachedHeader(sig)
		if err != nil {
			return gen.EvidencePack{}, err
		}
		row.Signature, row.SignatureKid = &sig, &h.KID
	} else {
		p.inc(CounterPackUnsigned)
	}
	stored := archive
	if r.Kind == KindLegal {
		if p.Sealer == nil {
			return gen.EvidencePack{}, p.refuse(httpx.Refuse(http.StatusServiceUnavailable, SlugStorageUnavailable,
				"a legal pack is sealed at rest with the PII key, which is not configured"))
		}
		if stored, err = p.Sealer.Seal(archive, packAAD(packID)); err != nil {
			return gen.EvidencePack{}, err
		}
		kid := p.Sealer.KeyID()
		row.SealedKeyID = &kid
	}
	if row.StorageRef, err = p.Storage.Put(incidentID, packID, stored); err != nil {
		return gen.EvidencePack{}, err
	}
	unavailable := []string{}
	for name, s := range manifest.Sections {
		if s.State == StateUnavailable {
			unavailable = append(unavailable, name)
		}
	}
	slices.Sort(unavailable)
	err = p.Service.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := q.InsertEvidencePack(ctx, gen.InsertEvidencePackParams(row)); err != nil {
			return err
		}
		_, err := p.Service.Audit.Record(ctx, q, audit.Event{Actor: actor, Purpose: r.Purpose, EntityType: EntityType,
			EntityID: incidentID, EventType: audit.EventEvidencePackBuilt, Payload: map[string]any{
				"pack_id": packID, "kind": r.Kind, "window_from": seal.WindowFrom, "window_to": seal.WindowTo,
				"content_hash": row.ContentHash, "size_bytes": row.SizeBytes, "signature_kid": row.SignatureKid,
				"storage_ref": row.StorageRef, "sealed_at_rest": row.SealedKeyID != nil, "case_ref": row.CaseRef,
				"sections_unavailable": unavailable, "frame_payloads_withheld": manifest.FramesWithheld,
			}})
		return err
	})
	if err != nil {
		p.inc(CounterPackOrphaned)
		logger(p.Logger).Error("evidence pack stored but not recorded; the stored file is an orphan",
			slog.String("pack_id", packID), slog.String("storage_ref", row.StorageRef), slog.String("error", err.Error()))
		return gen.EvidencePack{}, err
	}
	p.inc(CounterPackBuilt)
	if p.Counters != nil && len(unavailable) > 0 {
		p.Counters.Add(CounterSectionUnavailable, uint64(len(unavailable)))
	}
	return row, nil
}

func logger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.DiscardHandler)
}

func packAAD(packID string) []byte { return []byte("evidence_packs:" + packID + ":archive") }

func (p *Packs) checkRequest(piiRole bool, r *PackRequest) error {
	if err := oneOf("kind", r.Kind, []string{KindOversight, KindLegal}); err != nil {
		return err
	}
	if err := checkPurpose("purpose", r.Purpose); err != nil {
		return err
	}
	if r.Kind == KindLegal {
		if r.CaseRef == "" {
			return core.Fieldf("case_ref", "required for a legal pack")
		}
		if !piiRole {
			return forbiddenLegal()
		}
	}
	if r.CaseRef != "" && (!utf8.ValidString(r.CaseRef) || utf8.RuneCountInString(r.CaseRef) > 200) {
		return core.Fieldf("case_ref", "at most 200 characters of UTF-8")
	}
	// The window is stored as timestamptz (microseconds) and the seal is
	// verified over the stored row: it is signed over the same precision,
	// or a genuine pack would read as tampered (audit B-S1).
	r.From, r.To = r.From.Truncate(time.Microsecond), r.To.Truncate(time.Microsecond)
	if r.From.IsZero() || !r.To.After(r.From) {
		return core.Fieldf("to", "must be after from")
	}
	if d := r.To.Sub(r.From); d > p.MaxWindow {
		return httpx.Refuse(http.StatusBadRequest, SlugWindowTooLarge,
			"a window longer than the maximum is refused rather than thinned; build several packs",
			core.Fieldf("to", "the window is %s, at most %s", d, p.MaxWindow))
	}
	return nil
}

// Seal completes the manifest with every file's hash, adds it as
// manifest.json and writes the deterministic archive. It returns the
// archive and the manifest's JSON (the manifest column).
func Seal(m Manifest, entries []Entry) ([]byte, []byte, error) {
	files := make([]FileDigest, 0, len(entries))
	for _, e := range entries {
		files = append(files, FileDigest{Path: e.Path, SHA256: ContentHash(e.Data), Bytes: len(e.Data)})
	}
	slices.SortFunc(files, func(a, b FileDigest) int {
		switch {
		case a.Path < b.Path:
			return -1
		case a.Path > b.Path:
			return 1
		}
		return 0
	})
	m.Files = files
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	all := append(slices.Clone(entries), Entry{Path: "manifest.json", Data: append(mj, '\n')})
	archive, err := Archive(all)
	if err != nil {
		return nil, nil, err
	}
	return archive, mj, nil
}

// Get reads one pack of an incident.
func (p *Packs) Get(ctx context.Context, incidentID, packID string) (gen.EvidencePack, error) {
	row, err := p.Service.DB.Queries().GetEvidencePack(ctx, gen.GetEvidencePackParams{IncidentID: incidentID, PackID: packID})
	if store.IsNoRows(err) {
		return row, packNotFound(packID)
	}
	return row, err
}

// read reads the stored archive and opens it when sealed at rest.
// read returns the stored archive. unreadable says the bytes could not
// be had at all (the storage failed, the object is above the read
// bound, the PII key is not configured or is another one): that is an
// outage, not evidence about the archive. A sealed archive that does
// not open under its own key is a modified one (unreadable false).
func (p *Packs) read(row *gen.EvidencePack) (data []byte, unreadable bool, err error) {
	// A sealed archive is the plaintext plus the nonce and the tag.
	data, err = p.Storage.Get(row.StorageRef, p.MaxBytes+64)
	if err != nil {
		return nil, true, err
	}
	if row.SealedKeyID == nil {
		return data, false, nil
	}
	if p.Sealer == nil {
		return nil, true, errors.New("the archive is sealed at rest and the PII key is not configured")
	}
	if *row.SealedKeyID != p.Sealer.KeyID() {
		return nil, true, fmt.Errorf("the archive is sealed under key %q, the configured PII key is %q", *row.SealedKeyID, p.Sealer.KeyID())
	}
	data, err = p.Sealer.Open(*row.SealedKeyID, data, packAAD(row.PackID))
	return data, false, err
}

// Verification is what a check of a stored pack found.
type Verification struct {
	PackID         string
	ContentHash    string
	RecomputedHash *string
	HashMatches    bool
	Problem        *string
	// Unreadable is true when the stored archive could not be read at
	// all: whether it matches is unknown, and it is not tampering
	// (audit B-S2).
	Unreadable      bool
	Signature       string
	SignatureDetail *string
	VerifiedAt      time.Time
}

// tampered reports whether v is evidence of a modification: a hash that
// differs (over bytes that were read), or a seal that does not verify.
func (v *Verification) tampered() bool {
	return (!v.Unreadable && !v.HashMatches) || v.Signature == SigInvalid
}

// Signature verdicts.
const (
	SigVerified     = "verified"
	SigInvalid      = "invalid"
	SigUnsigned     = "unsigned"
	SigUnverifiable = "unverifiable"
)

func strPtr(s string) *string { return &s }

// check recomputes the hash of the stored archive and verifies the seal
// statement's signature; data is the archive when the hash matches.
func (p *Packs) check(ctx context.Context, row *gen.EvidencePack) (Verification, []byte) {
	v := Verification{PackID: row.PackID, ContentHash: row.ContentHash, Signature: SigUnsigned}
	data, unreadable, err := p.read(row)
	switch {
	case unreadable:
		v.Unreadable = true
		v.Problem = strPtr("the stored archive cannot be read: " + reason(err))
	case err != nil:
		v.Problem = strPtr("the stored sealed archive does not open under its key: it was modified after sealing: " + reason(err))
	default:
		h := ContentHash(data)
		v.RecomputedHash = &h
		v.HashMatches = h == row.ContentHash
		if !v.HashMatches {
			v.Problem = strPtr("the stored archive's hash differs from content_hash: it was modified after sealing")
		}
	}
	switch {
	case row.Signature == nil:
		v.SignatureDetail = strPtr("built without a publication key")
	case p.Signer == nil || p.Verifier == nil:
		v.Signature = SigUnverifiable
		v.SignatureDetail = strPtr("no publication key is configured on this system")
	case !slices.Contains(p.Signer.KIDs(), deref(row.SignatureKid)):
		v.Signature = SigUnverifiable
		v.SignatureDetail = strPtr("signed with kid " + deref(row.SignatureKid) + ", which this system no longer holds; verify against the published JWKS")
	default:
		seal := sealOf(row)
		if _, err := p.Verifier.Verify(ctx, PublisherAuthority, *row.Signature, seal.Bytes()); err != nil {
			v.Signature = SigInvalid
			v.SignatureDetail = strPtr("the seal statement rebuilt from the stored row does not verify: " + reason(err))
		} else {
			v.Signature = SigVerified
		}
	}
	if !v.HashMatches || v.Signature == SigInvalid {
		return v, nil
	}
	return v, data
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (p *Packs) recordVerification(ctx context.Context, actor audit.Actor, row *gen.EvidencePack, v *Verification, via string) error {
	return p.Service.DB.WithTx(ctx, func(q *gen.Queries) error {
		at, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		v.VerifiedAt = at.UTC()
		var matches any = v.HashMatches
		if v.Unreadable {
			matches = nil // unknown: nothing was read to compare
		}
		_, err = p.Service.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityType, EntityID: row.IncidentID,
			EventType: audit.EventEvidencePackVerified, Payload: map[string]any{
				"pack_id": row.PackID, "via": via, "content_hash": row.ContentHash, "recomputed_hash": v.RecomputedHash,
				"hash_matches": matches, "unreadable": v.Unreadable, "signature": v.Signature, "problem": v.Problem,
			}})
		return err
	})
}

// Verify checks a stored pack and records the check (an
// evidence_pack_verified events row, whatever it found).
func (p *Packs) Verify(ctx context.Context, actor audit.Actor, incidentID, packID string) (Verification, error) {
	if err := p.storageOK(); err != nil {
		return Verification{}, err
	}
	release, err := p.acquireRead()
	if err != nil {
		return Verification{}, err
	}
	defer release()
	row, err := p.Get(ctx, incidentID, packID)
	if err != nil {
		return Verification{}, err
	}
	v, _ := p.check(ctx, &row)
	p.inc(CounterPackVerified)
	p.countCheck(&v)
	if err := p.recordVerification(ctx, actor, &row, &v, "verify"); err != nil {
		return Verification{}, err
	}
	if v.Unreadable && !v.tampered() {
		return v, unreadableProblem(&v)
	}
	return v, nil
}

// countCheck counts a check that found tampering or could not read.
func (p *Packs) countCheck(v *Verification) {
	switch {
	case v.tampered():
		p.inc(CounterPackTampered)
	case v.Unreadable:
		p.inc(CounterPackUnreadable)
	}
}

func unreadableProblem(v *Verification) error {
	return httpx.Refuse(http.StatusServiceUnavailable, SlugStorageUnavailable,
		"the stored pack cannot be read; whether it matches its seal is unknown: "+deref(v.Problem))
}

// Download reads a stored pack for purpose: the hash (and a signature
// it holds) is checked before anything is served, a mismatch is
// recorded and refused (409 evidence_tampered), and the download is an
// evidence_pack_downloaded events row committed before the body is
// returned. A legal pack is served to a personal-data role only.
func (p *Packs) Download(ctx context.Context, actor audit.Actor, piiRole bool, incidentID, packID, purpose string) ([]byte, gen.EvidencePack, error) {
	if err := checkPurpose("purpose", purpose); err != nil {
		return nil, gen.EvidencePack{}, err
	}
	if err := p.storageOK(); err != nil {
		return nil, gen.EvidencePack{}, err
	}
	release, err := p.acquireRead()
	if err != nil {
		return nil, gen.EvidencePack{}, err
	}
	defer release()
	row, err := p.Get(ctx, incidentID, packID)
	if err != nil {
		return nil, row, err
	}
	if row.Kind == KindLegal && !piiRole {
		return nil, row, forbiddenLegal()
	}
	v, data := p.check(ctx, &row)
	if data == nil {
		p.countCheck(&v)
		if err := p.recordVerification(ctx, actor, &row, &v, "download"); err != nil {
			return nil, row, err
		}
		if !v.tampered() {
			return nil, row, unreadableProblem(&v)
		}
		return nil, row, httpx.Refuse(http.StatusConflict, SlugTampered,
			"the stored pack does not match its seal and is not served: "+deref(v.Problem)+deref(v.SignatureDetail))
	}
	err = p.Service.DB.WithTx(ctx, func(q *gen.Queries) error {
		_, err := p.Service.Audit.Record(ctx, q, audit.Event{Actor: actor, Purpose: purpose, EntityType: EntityType, EntityID: incidentID,
			EventType: audit.EventEvidencePackDownloaded, Payload: map[string]any{
				"pack_id": packID, "kind": row.Kind, "content_hash": row.ContentHash, "signature": v.Signature, "case_ref": row.CaseRef,
			}})
		return err
	})
	if err != nil {
		return nil, row, err
	}
	p.inc(CounterPackDownloaded)
	return data, row, nil
}
