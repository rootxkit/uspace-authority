package archive

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/odid"
)

func f64(v float64) *float64 { return &v }

// A System message with the remote pilot position, built by core's
// encoder (LESSONS E-03: no offsets here).
func systemFrame(t *testing.T) []byte {
	t.Helper()
	b, err := odid.Encode(odid.System{OperatorLocationType: 1, ClassificationType: 1, OperatorLatDeg: f64(41.7151), OperatorLonDeg: f64(44.8271),
		AreaCount: 1, AreaRadiusM: 30, AreaCeilingM: f64(120), AreaFloorM: f64(0.5), CategoryEU: 1, ClassEU: 2,
		OperatorAltHAEM: f64(512.5), TimestampS: 123456})
	if err != nil {
		t.Fatal(err)
	}
	return b[:]
}

func packWithSystem(t *testing.T) []byte {
	t.Helper()
	sys, err := odid.DecodeMessage([odid.MessageSize]byte(systemFrame(t)), odid.DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p, err := odid.EncodePack([]odid.Message{
		odid.BasicID{IDType: odid.IDTypeSerial, UAType: 2, UAID: "TEST0000000000000001"},
		odid.Location{Status: odid.StatusAirborne, LatDeg: f64(41.72), LonDeg: f64(44.83), AltHAEM: f64(600), HeightM: f64(80)},
		sys,
		odid.OperatorID{OperatorIDType: 0, OperatorID: "GEO-TEST-0001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func systemOf(t *testing.T, frame []byte) odid.System {
	t.Helper()
	ms, err := odid.Decode(frame, odid.DecodeOptions{KeepSkipped: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if s, ok := m.(odid.System); ok {
			return s
		}
	}
	t.Fatal("no System message in the frame")
	return odid.System{}
}

// 06 §5, E-01: a System message's remote pilot position is removed and
// nothing else changes; beside it, a frame without one is left as it
// was, byte for byte.
func TestRedactOperatorRemovesThePositionAndKeepsTheRest(t *testing.T) {
	for name, frame := range map[string][]byte{"system": systemFrame(t), "pack": packWithSystem(t)} {
		t.Run(name, func(t *testing.T) {
			before := systemOf(t, frame)
			if before.OperatorLatDeg == nil || before.OperatorAltHAEM == nil {
				t.Fatalf("fixture carries no position: %+v", before)
			}
			out, red := RedactOperator(frame)
			if red != Redacted {
				t.Fatalf("outcome %v", red)
			}
			after := systemOf(t, out)
			if after.OperatorLatDeg != nil || after.OperatorLonDeg != nil || after.OperatorAltHAEM != nil {
				t.Fatalf("position kept: %+v", after)
			}
			if after.AreaCeilingM == nil || *after.AreaCeilingM != *before.AreaCeilingM || after.ClassEU != before.ClassEU ||
				after.TimestampS != before.TimestampS {
				t.Fatalf("other System fields changed: %+v -> %+v", before, after)
			}
			if len(out) != len(frame) {
				t.Fatalf("length %d -> %d", len(frame), len(out))
			}
			// Only the System message's 25 bytes may differ.
			diff := 0
			for i := range frame {
				if frame[i] != out[i] {
					diff++
				}
			}
			if diff == 0 || diff > odid.MessageSize {
				t.Fatalf("%d bytes changed", diff)
			}
			if !bytes.Equal(frame, systemFrameOrPack(name, t)) {
				t.Fatal("the input frame was modified in place")
			}
		})
	}
}

func systemFrameOrPack(name string, t *testing.T) []byte {
	if name == "system" {
		return systemFrame(t)
	}
	return packWithSystem(t)
}

func TestRedactOperatorLeavesAFrameWithoutAPosition(t *testing.T) {
	loc, err := odid.Encode(odid.Location{Status: odid.StatusAirborne, LatDeg: f64(41.7), LonDeg: f64(44.8)})
	if err != nil {
		t.Fatal(err)
	}
	noPos, err := odid.Encode(odid.System{OperatorLocationType: 0, TimestampS: 1})
	if err != nil {
		t.Fatal(err)
	}
	for name, frame := range map[string][]byte{"location": loc[:], "system without position": noPos[:]} {
		out, red := RedactOperator(frame)
		if red != Unchanged || !bytes.Equal(out, frame) {
			t.Errorf("%s: %v %x", name, red, out)
		}
	}
}

func TestRedactOperatorRefusesAnUndecodableFrame(t *testing.T) {
	for name, frame := range map[string][]byte{"empty": nil, "short": {0x42, 1, 2}, "bad pack": {0xF2, 25, 9, 0}} {
		if out, red := RedactOperator(frame); red != Undecodable || out != nil {
			t.Errorf("%s: %v %x", name, red, out)
		}
	}
}

// Whatever bytes arrive, RedactOperator never panics, and a frame it
// says it redacted decodes without an operator position.
func FuzzRedactOperator(f *testing.F) {
	f.Add(systemFrameFuzz())
	f.Add([]byte{0xF2, 25, 1})
	f.Add(bytes.Repeat([]byte{0x42}, 25))
	f.Fuzz(func(t *testing.T, frame []byte) {
		out, red := RedactOperator(frame)
		if red != Redacted {
			return
		}
		ms, err := odid.Decode(out, odid.DecodeOptions{KeepSkipped: true})
		if err != nil {
			t.Fatalf("redacted frame does not decode: %v", err)
		}
		for _, m := range ms {
			if s, ok := m.(odid.System); ok && (s.OperatorLatDeg != nil || s.OperatorAltHAEM != nil) {
				t.Fatalf("redacted frame keeps a position: %+v", s)
			}
		}
	})
}

func systemFrameFuzz() []byte {
	b, _ := odid.Encode(odid.System{OperatorLocationType: 1, OperatorLatDeg: f64(41.7), OperatorLonDeg: f64(44.8), TimestampS: 9})
	return b[:]
}

// The local directory store: an object is visible only after Commit, is
// never overwritten, an aborted one leaves nothing, and keys cannot
// leave the root.
func TestDirStoreWritesOnceAndNeverOverwrites(t *testing.T) {
	d := Dir{Root: t.TempDir()}
	key := "telemetry/tracks/2026/01/02/x.ndjson.gz"
	w, err := d.Create(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Open(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("visible before commit: %v", err)
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(); err == nil {
		t.Fatal("a second commit was accepted")
	}
	if b, err := Get(d, key, 10); err != nil || string(b) != "one" {
		t.Fatalf("read back %q %v", b, err)
	}
	if _, err := d.Create(key); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite: %v", err)
	}
	if err := Put(d, key, []byte("two")); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrite by put: %v", err)
	}
	if _, err := Get(d, key, 2); err == nil {
		t.Fatal("a read past the bound was accepted")
	}
	// Abort leaves no object and no temporary file.
	w2, err := d.Create("telemetry/tracks/2026/01/02/y.ndjson.gz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w2.Write([]byte("partial"))
	w2.Abort()
	entries, err := os.ReadDir(filepath.Join(d.Root, "telemetry", "tracks", "2026", "01", "02"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("after abort: %v %v", entries, err)
	}
	if err := d.Delete(key); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := Put(d, key, []byte("again")); err != nil {
		t.Fatalf("a deleted key cannot be written again: %v", err)
	}
}

func TestCheckKeyRefusesEscapes(t *testing.T) {
	for _, k := range []string{"", "a", "../x/y", "a/../b", "a/.hidden", "/abs/x", `a\b`, "A/b", "a//b", strings.Repeat("a/", 600) + "b"} {
		if CheckKey(k) == nil {
			t.Errorf("accepted %q", k)
		}
	}
	for _, k := range []string{"telemetry/tracks/2026/01/02/20260102T000000Z__hyper_1_2_chunk.ndjson.gz", "ussp-records/ABC/2026/01/2026-01-02-0123456789abcdef.json"} {
		if err := CheckKey(k); err != nil {
			t.Errorf("refused %q: %v", k, err)
		}
	}
}

// ARCHIVE_URL: an absolute file: directory is the store; nothing else
// is accepted, so a store that cannot keep writes never reports them.
func TestOpenAcceptsOnlyAnAbsoluteDirectory(t *testing.T) {
	dir := t.TempDir()
	u := "file://" + filepath.ToSlash(dir)
	if runtime.GOOS == "windows" {
		u = "file:///" + filepath.ToSlash(dir)
	}
	s, err := Open(u)
	if err != nil {
		t.Fatalf("open %s: %v", u, err)
	}
	if !strings.HasPrefix(s.Describe(), "file://") {
		t.Errorf("describe %q", s.Describe())
	}
	if _, err := Open(""); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("empty: %v", err)
	}
	for _, bad := range []string{"s3://bucket/prefix", "https://example.test/archive", "file://host/dir", "file:relative/dir", "file:///tmp/x?y=1"} {
		if _, err := DirOf(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestHashReaderCountsAndHashes(t *testing.T) {
	h, n, err := HashReader(io.NopCloser(strings.NewReader("abc")))
	if err != nil || n != 3 || h != Hash([]byte("abc")) || !strings.HasPrefix(h, "sha256:") {
		t.Fatalf("%s %d %v", h, n, err)
	}
}
