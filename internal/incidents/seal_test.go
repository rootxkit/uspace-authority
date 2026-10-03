package incidents

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

func TestArchiveIsDeterministicAndOrderFree(t *testing.T) {
	es := []Entry{{Path: "b.json", Data: []byte("{}")}, {Path: "a/x.json", Data: []byte("[1]")}, {Path: "a.json", Data: []byte("x")}}
	a1, err := Archive(es)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := Archive([]Entry{es[2], es[0], es[1]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1, a2) {
		t.Fatal("the same entries in another order gave other bytes")
	}
	read, err := ReadArchive(a1, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(read) != 3 || read[0].Path != "a.json" || read[1].Path != "a/x.json" || string(read[2].Data) != "{}" {
		t.Fatalf("read %+v", read)
	}
	if _, err := ReadArchive(a1, 2); err == nil {
		t.Fatal("contents past the bound read")
	}
	for _, bad := range [][]Entry{{{Path: "/abs"}}, {{Path: "../up"}}, {{Path: "a\\b"}}, {{Path: ""}}, {{Path: "x"}, {Path: "x"}}} {
		if _, err := Archive(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func FuzzReadArchive(f *testing.F) {
	a, _ := Archive([]Entry{{Path: "a", Data: []byte("x")}})
	f.Add(a)
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		es, err := ReadArchive(b, 1<<16)
		if err == nil {
			total := 0
			for _, e := range es {
				total += len(e.Data)
			}
			if total > 1<<16 {
				t.Fatalf("read %d bytes past the bound", total)
			}
		}
	})
}

// T7: a modified byte changes the hash.
func TestHashDetectsAModifiedByte(t *testing.T) {
	a, err := Archive([]Entry{{Path: "manifest.json", Data: []byte(`{"a":1}`)}})
	if err != nil {
		t.Fatal(err)
	}
	h := ContentHash(a)
	if !strings.HasPrefix(h, "sha256:") || len(h) != 7+64 || ContentHash(a) != h {
		t.Fatalf("hash %q", h)
	}
	b := bytes.Clone(a)
	b[len(b)/2] ^= 0x01
	if ContentHash(b) == h {
		t.Fatal("a modified byte kept the hash")
	}
}

func TestDirStoresOnceAndReadsBack(t *testing.T) {
	d := Dir{Root: t.TempDir()}
	ref, err := d.Put(testIncID, testPackID, []byte("archive"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := d.Get(ref, 100)
	if err != nil || string(got) != "archive" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := d.Put(testIncID, testPackID, []byte("other")); err == nil {
		t.Fatal("a stored archive was overwritten")
	}
	if got, _ := d.Get(ref, 100); string(got) != "archive" {
		t.Fatal("the stored archive changed")
	}
	if _, err := d.Get(ref, 3); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("past the bound: %v", err)
	}
	for _, bad := range []string{"file:../x/y.zip", "file:" + testIncID + "/../../etc.zip", "s3:x", "file:" + testIncID} {
		if _, err := d.Get(bad, 100); err == nil {
			t.Errorf("%q read", bad)
		}
	}
	if _, err := d.Put("not-an-id", testPackID, nil); err == nil {
		t.Fatal("a bad id stored")
	}
	entries, err := os.ReadDir(filepath.Join(d.Root, testIncID))
	if err != nil || len(entries) != 1 {
		t.Fatalf("left behind %v %v", entries, err)
	}
}

func sealer(t *testing.T) *pii.Sealer {
	t.Helper()
	s, err := pii.NewSealer("pii-test", bytes.Repeat([]byte{7}, pii.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// packFixture is a stored, signed pack row and its archive.
func packFixture(t *testing.T, legal bool) (*Packs, *gen.EvidencePack, *memStorage, []byte) {
	t.Helper()
	r := ring(t, "pub-test-1", 0)
	v, err := coreauth.NewDetachedVerifier(context.Background(), coreauth.DetachedConfig{
		Publishers: map[string]coreauth.IssuerConfig{PublisherAuthority: {Keys: r.JWKS()}}, MaxAge: signatureMaxAge})
	if err != nil {
		t.Fatal(err)
	}
	st := &memStorage{}
	p := &Packs{Storage: st, Sealer: sealer(t), Signer: r, Verifier: v, MaxBytes: 1 << 20}
	archive, _, err := Seal(Manifest{Schema: ManifestSchema, Sections: map[string]Section{}}, []Entry{{Path: "incident.json", Data: []byte("{}")}})
	if err != nil {
		t.Fatal(err)
	}
	row := &gen.EvidencePack{PackID: testPackID, IncidentID: testIncID, Kind: KindOversight, WindowFrom: at(0), WindowTo: at(60),
		ContentHash: ContentHash(archive), SizeBytes: int64(len(archive)), CreatedBy: "officer-1", CreatedAt: at(120)}
	stored := archive
	if legal {
		row.Kind = KindLegal
		if stored, err = p.Sealer.Seal(archive, packAAD(testPackID)); err != nil {
			t.Fatal(err)
		}
		kid := p.Sealer.KeyID()
		row.SealedKeyID = &kid
	}
	sig, err := r.SignDetached(sealOf(row).Bytes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	kid := "pub-test-1"
	row.Signature, row.SignatureKid = &sig, &kid
	if row.StorageRef, err = st.Put(testIncID, testPackID, stored); err != nil {
		t.Fatal(err)
	}
	return p, row, st, archive
}

func tamper(st *memStorage, ref string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.objs[ref][len(st.objs[ref])/2] ^= 0x01
}

// A stored pack verifies (hash and signature); a modified byte of the
// stored archive is detected, sealed at rest or not; a row whose
// recorded hash was changed fails its signature.
func TestCheckDetectsTampering(t *testing.T) {
	for _, legal := range []bool{false, true} {
		p, row, st, archive := packFixture(t, legal)
		v, data := p.check(context.Background(), row)
		if !v.HashMatches || v.Signature != SigVerified || !bytes.Equal(data, archive) || v.Problem != nil {
			t.Fatalf("legal %v: %+v", legal, v)
		}
		tamper(st, row.StorageRef)
		v, data = p.check(context.Background(), row)
		if v.HashMatches || data != nil || v.Problem == nil {
			t.Fatalf("legal %v: a tampered archive passed: %+v", legal, v)
		}
	}
	p, row, _, _ := packFixture(t, false)
	other := *row
	other.ContentHash = ContentHash([]byte("another archive"))
	v, data := p.check(context.Background(), &other)
	if v.HashMatches || v.Signature != SigInvalid || data != nil {
		t.Fatalf("a changed row passed: %+v", v)
	}
	// The window is under the signature too.
	other = *row
	other.WindowTo = at(61)
	if v, _ := p.check(context.Background(), &other); v.Signature != SigInvalid {
		t.Fatalf("a changed window passed: %+v", v)
	}
}

func TestCheckSignatureStates(t *testing.T) {
	p, row, _, _ := packFixture(t, false)
	unsigned := *row
	unsigned.Signature, unsigned.SignatureKid = nil, nil
	if v, data := p.check(context.Background(), &unsigned); v.Signature != SigUnsigned || !v.HashMatches || data == nil {
		t.Fatalf("unsigned %+v", v)
	}
	// Signed with a key this system does not hold any more.
	p.Signer = ring(t, "pub-test-2", 1)
	if v, data := p.check(context.Background(), row); v.Signature != SigUnverifiable || data == nil {
		t.Fatalf("unverifiable %+v", v)
	}
	p.Signer, p.Verifier = nil, nil
	if v, _ := p.check(context.Background(), row); v.Signature != SigUnverifiable {
		t.Fatalf("no key %+v", v)
	}
	// A legal archive without the PII key cannot be opened.
	lp, lrow, _, _ := packFixture(t, true)
	lp.Sealer = nil
	if v, _ := lp.check(context.Background(), lrow); v.Problem == nil || v.HashMatches {
		t.Fatalf("opened without a key %+v", v)
	}
}

func TestSealStatementBytesAreStable(t *testing.T) {
	_, row, _, _ := packFixture(t, false)
	if !bytes.Equal(sealOf(row).Bytes(), sealOf(row).Bytes()) || !bytes.Contains(sealOf(row).Bytes(), []byte(row.ContentHash)) {
		t.Fatal("the seal statement is not stable")
	}
	if h, err := coreauth.ParseDetachedHeader(*row.Signature); err != nil || h.KID != "pub-test-1" || h.B64 {
		t.Fatalf("%+v %v", h, err)
	}
}

func problemOf(t *testing.T, err error) *httpx.Problem {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	return httpx.ProblemFromError(err)
}

// The refusals before any build: the window, the kind, the purpose, a
// legal pack's case reference and role, the storage, the bound on
// builds at once (E-10).
func TestCreateRefusals(t *testing.T) {
	p := NewPacks(&Packs{MaxWindow: time.Hour, Counters: &core.Counters{}, Storage: &memStorage{}}, 1)
	ok := PackRequest{Kind: KindOversight, From: at(0), To: at(3600), Purpose: "review"}
	cases := []struct {
		name   string
		pii    bool
		mutate func(r *PackRequest)
		status int
		slug   string
	}{
		{"window", false, func(r *PackRequest) { r.To = at(3601) }, http.StatusBadRequest, SlugWindowTooLarge},
		{"reversed", false, func(r *PackRequest) { r.To = r.From }, http.StatusBadRequest, httpx.SlugValidation},
		{"kind", false, func(r *PackRequest) { r.Kind = "secret" }, http.StatusBadRequest, httpx.SlugValidation},
		{"purpose", false, func(r *PackRequest) { r.Purpose = "" }, http.StatusBadRequest, httpx.SlugValidation},
		{"case_ref", true, func(r *PackRequest) { r.Kind = KindLegal }, http.StatusBadRequest, httpx.SlugValidation},
		{"legal without a personal-data role", false, func(r *PackRequest) { r.Kind, r.CaseRef = KindLegal, "C-1" }, http.StatusForbidden, httpx.SlugForbidden},
	}
	for _, c := range cases {
		r := ok
		c.mutate(&r)
		pr := problemOf(t, func() error { _, err := p.Create(context.Background(), officer, c.pii, testIncID, r); return err }())
		if pr.Status != c.status || pr.Slug() != c.slug {
			t.Errorf("%s: %d %s", c.name, pr.Status, pr.Slug())
		}
	}
	// Accepted request, refused only by what follows: no storage.
	noStore := NewPacks(&Packs{MaxWindow: time.Hour}, 1)
	if pr := problemOf(t, func() error { _, err := noStore.Create(context.Background(), officer, true, testIncID, ok); return err }()); pr.Status != http.StatusServiceUnavailable || pr.Slug() != SlugStorageUnavailable {
		t.Fatalf("no storage: %d %s", pr.Status, pr.Slug())
	}
	// The bound on builds at once: one held, the next refused and counted.
	p.sem <- struct{}{}
	pr := problemOf(t, func() error { _, err := p.Create(context.Background(), officer, true, testIncID, ok); return err }())
	<-p.sem
	if pr.Status != http.StatusServiceUnavailable || pr.Slug() != SlugPackBusy || p.Counters.Get(CounterPackBusy) != 1 {
		t.Fatalf("busy: %d %s %d", pr.Status, pr.Slug(), p.Counters.Get(CounterPackBusy))
	}
	if p.Counters.Get(CounterPackRefused) != uint64(len(cases))+1 {
		t.Fatalf("refused counted %d", p.Counters.Get(CounterPackRefused))
	}
}

func TestCursorRoundTrip(t *testing.T) {
	c := EncodeCursor(at(5), testIncID)
	got, id, err := DecodeCursor(c)
	if err != nil || !got.Equal(at(5)) || id != testIncID {
		t.Fatalf("%v %s %v", got, id, err)
	}
	for _, bad := range []string{"", "!!", base64.RawURLEncoding.EncodeToString([]byte("x|y")), base64.RawURLEncoding.EncodeToString([]byte("2026-01-01T00:00:00Z|" + testIncID + "x"))} {
		if _, _, err := DecodeCursor(bad); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
}

func FuzzDecodeCursor(f *testing.F) {
	f.Add(EncodeCursor(at(1), testIncID))
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, s string) {
		when, id, err := DecodeCursor(s)
		if err == nil && !idPattern.MatchString(id) {
			t.Fatalf("decoded %q as %v %q", s, when, id)
		}
	})
}
