package incidents

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// archiveTime is the modification time of every entry: fixed, so two
// builds of the same contents are the same bytes (the DOS epoch, the
// earliest a ZIP header holds).
var archiveTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// Entry is one file of an archive.
type Entry struct {
	Path string
	Data []byte
}

// HashPrefix prefixes a content hash.
const HashPrefix = "sha256:"

// ContentHash is "sha256:" and the hex SHA-256 of b.
func ContentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// Archive writes entries as a deterministic ZIP: entries sorted by path,
// every timestamp archiveTime, no extra fields or comment, deflate at
// the default level. The same entries give the same bytes. A path that
// is empty, absolute, holds ".." or a backslash, or repeats another is
// refused.
func Archive(entries []Entry) ([]byte, error) {
	es := slices.Clone(entries)
	slices.SortFunc(es, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	for i, e := range es {
		if e.Path == "" || strings.HasPrefix(e.Path, "/") || strings.Contains(e.Path, "\\") || slices.Contains(strings.Split(e.Path, "/"), "..") {
			return nil, fmt.Errorf("archive: path %q is not a relative path", e.Path)
		}
		if i > 0 && es[i-1].Path == e.Path {
			return nil, fmt.Errorf("archive: path %q twice", e.Path)
		}
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range es {
		h := &zip.FileHeader{Name: e.Path, Method: zip.Deflate, Modified: archiveTime}
		h.SetMode(0o444)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(e.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadArchive lists the entries of an archive Archive wrote, reading at
// most maxBytes of contents in all (E-10). It is used by tests and by an
// officer's tooling; the pack's own check is the hash.
func ReadArchive(b []byte, maxBytes int64) ([]Entry, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	var out []Entry
	left := maxBytes
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("archive: %s: %w", f.Name, err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, left+1))
		_ = rc.Close()
		if err != nil {
			return nil, fmt.Errorf("archive: %s: %w", f.Name, err)
		}
		left -= int64(len(data))
		if left < 0 {
			return nil, fmt.Errorf("archive: contents exceed %d bytes", maxBytes)
		}
		out = append(out, Entry{Path: f.Name, Data: data})
	}
	return out, nil
}
