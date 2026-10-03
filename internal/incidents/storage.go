package incidents

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Storage keeps sealed archives. A stored object is never overwritten:
// Put of an existing reference fails.
type Storage interface {
	// Put stores data under the incident and pack ids and returns the
	// reference recorded in evidence_packs.storage_ref.
	Put(incidentID, packID string, data []byte) (string, error)
	// Get reads the object of ref, at most maxBytes (a larger one is an
	// error, never a truncated read).
	Get(ref string, maxBytes int64) ([]byte, error)
	// Discard removes the object of ref that Put stored for a pack whose
	// row then did not commit (never a recorded pack's).
	Discard(ref string) error
}

// ErrNoStorage is the state without EVIDENCE_DIR: packs are refused.
var ErrNoStorage = errors.New("no evidence storage configured (EVIDENCE_DIR)")

// ErrTooLarge is a stored object above the read bound.
var ErrTooLarge = errors.New("stored evidence larger than the read bound")

// refPrefix marks a reference into a Dir.
const refPrefix = "file:"

var idPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// Dir stores archives as files under Root: <incident>/<pack>.zip, mode
// 0400, written to a temporary name, synced and renamed into place, so
// a reader never sees a partial file and nothing is overwritten.
type Dir struct {
	Root string
}

// Put implements Storage.
func (d Dir) Put(incidentID, packID string, data []byte) (string, error) {
	if !idPattern.MatchString(incidentID) || !idPattern.MatchString(packID) {
		return "", fmt.Errorf("evidence storage: ids %q, %q are not ULIDs", incidentID, packID)
	}
	dir := filepath.Join(d.Root, incidentID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("evidence storage: %w", err)
	}
	rel := incidentID + "/" + packID + ".zip"
	final := filepath.Join(dir, packID+".zip")
	if _, err := os.Lstat(final); err == nil {
		return "", fmt.Errorf("evidence storage: %s exists; never overwritten", rel)
	}
	tmp, err := os.CreateTemp(dir, "."+packID+"-*.tmp")
	if err != nil {
		return "", fmt.Errorf("evidence storage: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return "", fmt.Errorf("evidence storage: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return "", fmt.Errorf("evidence storage: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("evidence storage: %w", err)
	}
	if err := os.Chmod(name, 0o400); err != nil {
		return "", fmt.Errorf("evidence storage: %w", err)
	}
	// os.Link fails when final exists, so a concurrent Put of the same
	// pack cannot replace a stored archive.
	if err := os.Link(name, final); err != nil {
		return "", fmt.Errorf("evidence storage: %w", err)
	}
	ok = true
	_ = os.Remove(name)
	return refPrefix + rel, nil
}

// path is the file of ref, refused unless ref is a reference of this
// store.
func (d Dir) path(ref string) (string, error) {
	rel, found := strings.CutPrefix(ref, refPrefix)
	parts := strings.Split(rel, "/")
	if !found || len(parts) != 2 || !idPattern.MatchString(parts[0]) || !strings.HasSuffix(parts[1], ".zip") ||
		!idPattern.MatchString(strings.TrimSuffix(parts[1], ".zip")) {
		return "", fmt.Errorf("evidence storage: %q is not a reference of this store", ref)
	}
	return filepath.Join(d.Root, parts[0], parts[1]), nil
}

// Discard implements Storage.
func (d Dir) Discard(ref string) error {
	p, err := d.path(ref)
	if err != nil {
		return err
	}
	// The file is 0400; a read-only file cannot be removed on every
	// platform.
	if err := os.Chmod(p, 0o600); err != nil {
		return fmt.Errorf("evidence storage: %w", err)
	}
	if err := os.Remove(p); err != nil {
		return fmt.Errorf("evidence storage: %w", err)
	}
	return nil
}

// Get implements Storage.
func (d Dir) Get(ref string, maxBytes int64) ([]byte, error) {
	p, err := d.path(ref)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("evidence storage: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("evidence storage: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}
