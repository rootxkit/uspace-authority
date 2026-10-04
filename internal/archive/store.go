package archive

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Store keeps archived objects. An object is written once: Create of an
// existing key fails, and a key is only reused after Delete.
type Store interface {
	// Create starts the object at key. Nothing is visible at key until
	// the writer's Commit returns nil; Abort (or a failed Commit) leaves
	// nothing behind.
	Create(key string) (Writer, error)
	// Open reads the object at key.
	Open(key string) (io.ReadCloser, error)
	// Delete removes the object at key; ErrNotFound when there is none.
	Delete(key string) error
	// Describe names the store for the log and the status line, without
	// secrets.
	Describe() string
}

// Writer is an object being written.
type Writer interface {
	io.Writer
	// Commit makes the object visible at its key, durably.
	Commit() error
	// Abort discards what was written.
	Abort()
}

// ErrNotFound is a key without an object.
var ErrNotFound = errors.New("archive: no object at this key")

// ErrExists is a key that already holds an object.
var ErrExists = errors.New("archive: an object exists at this key; it is never overwritten")

// ErrNotConfigured is the state without ARCHIVE_URL: nothing is archived,
// and so nothing is dropped.
var ErrNotConfigured = errors.New("archive: no archive store configured (ARCHIVE_URL)")

var keyPattern = regexp.MustCompile(`^[a-z0-9_-]+(/[A-Za-z0-9_.-]+)+$`)

// CheckKey accepts a relative slash-separated key of safe segments
// (no "..", no absolute path).
func CheckKey(key string) error {
	if len(key) > 1024 || !keyPattern.MatchString(key) {
		return fmt.Errorf("archive: %q is not an archive key", key)
	}
	for seg := range strings.SplitSeq(key, "/") {
		if seg == "." || seg == ".." || strings.HasPrefix(seg, ".") {
			return fmt.Errorf("archive: %q is not an archive key", key)
		}
	}
	return nil
}

// Open returns the store ARCHIVE_URL names: file:///absolute/dir for a
// local directory (on Windows file:///C:/dir). An empty URL is
// ErrNotConfigured. Any other scheme is refused: an S3-compatible store
// is not implemented in this build (docs/runbooks/retention.md), and a
// store that silently accepted writes it cannot keep would report
// archives that do not exist.
func Open(raw string) (Store, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, ErrNotConfigured
	}
	root, err := DirOf(raw)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("ARCHIVE_URL: %w", err)
	}
	return Dir{Root: root}, nil
}

// DirOf is the directory of a file: URL.
func DirOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("ARCHIVE_URL: not a URL")
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("ARCHIVE_URL: scheme %q is not supported; only file:///<absolute directory> (an S3-compatible store is not implemented)", u.Scheme)
	}
	if u.Host != "" && u.Host != "localhost" {
		return "", errors.New("ARCHIVE_URL: a file: URL names no host (file:///<absolute directory>)")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("ARCHIVE_URL: no user, query or fragment")
	}
	p := u.Path
	if runtime.GOOS == "windows" && len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	p = filepath.FromSlash(p)
	if !filepath.IsAbs(p) {
		return "", errors.New("ARCHIVE_URL: the directory must be absolute (file:///<absolute directory>)")
	}
	return filepath.Clean(p), nil
}

// Dir stores objects as files under Root: written to a temporary name,
// synced, linked into place (a link fails when the key exists, so
// nothing is overwritten) and made read-only.
type Dir struct {
	Root string
}

// Describe implements Store.
func (d Dir) Describe() string { return "file://" + filepath.ToSlash(d.Root) }

func (d Dir) path(key string) (string, error) {
	if err := CheckKey(key); err != nil {
		return "", err
	}
	return filepath.Join(d.Root, filepath.FromSlash(key)), nil
}

// Create implements Store.
func (d Dir) Create(key string) (Writer, error) {
	final, err := d.path(key)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(final); err == nil {
		return nil, fmt.Errorf("%s: %w", key, ErrExists)
	}
	dir := filepath.Dir(final)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	return &dirWriter{f: f, final: final, key: key}, nil
}

type dirWriter struct {
	f     *os.File
	final string
	key   string
	done  bool
}

func (w *dirWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

// Commit implements Writer.
func (w *dirWriter) Commit() error {
	if w.done {
		return errors.New("archive: object already committed or aborted")
	}
	w.done = true
	name := w.f.Name()
	fail := func(err error) error {
		_ = w.f.Close()
		_ = os.Remove(name)
		return fmt.Errorf("archive: %s: %w", w.key, err)
	}
	if err := w.f.Sync(); err != nil {
		return fail(err)
	}
	if err := w.f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("archive: %s: %w", w.key, err)
	}
	if err := os.Chmod(name, 0o400); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("archive: %s: %w", w.key, err)
	}
	if err := os.Link(name, w.final); err != nil {
		_ = os.Chmod(name, 0o600)
		_ = os.Remove(name)
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", w.key, ErrExists)
		}
		return fmt.Errorf("archive: %s: %w", w.key, err)
	}
	_ = os.Chmod(name, 0o600)
	_ = os.Remove(name)
	syncDir(filepath.Dir(w.final))
	return nil
}

// syncDir makes a link durable where the platform allows it.
func syncDir(dir string) {
	f, err := os.Open(filepath.Clean(dir))
	if err != nil {
		return
	}
	_ = f.Sync()
	_ = f.Close()
}

// Abort implements Writer.
func (w *dirWriter) Abort() {
	if w.done {
		return
	}
	w.done = true
	name := w.f.Name()
	_ = w.f.Close()
	_ = os.Remove(name)
}

// Open implements Store.
func (d Dir) Open(key string) (io.ReadCloser, error) {
	p, err := d.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Clean(p))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	return f, nil
}

// Delete implements Store.
func (d Dir) Delete(key string) error {
	p, err := d.path(key)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %w", key, ErrNotFound)
	}
	// A read-only file cannot be removed on every platform.
	_ = os.Chmod(p, 0o600)
	if err := os.Remove(p); err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	return nil
}

// Hash is "sha256:<hex>" of b, the form the ledgers record.
func Hash(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// HashReader hashes r to its end and counts its bytes.
func HashReader(r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", n, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// Put writes data at key in one call: Create, Write, Commit.
func Put(s Store, key string, data []byte) error {
	w, err := s.Create(key)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		w.Abort()
		return fmt.Errorf("archive: %s: %w", key, err)
	}
	return w.Commit()
}

// Get reads the object at key, at most maxBytes (a larger one is an
// error, never a truncated read).
func Get(s Store, key string, maxBytes int64) ([]byte, error) {
	r, err := s.Open(key)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("archive: %s: %w", key, err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("archive: %s is larger than %d bytes", key, maxBytes)
	}
	return b, nil
}
