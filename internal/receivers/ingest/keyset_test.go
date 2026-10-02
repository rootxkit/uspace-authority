package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

type fakeSource struct {
	mu      sync.Mutex
	raw     map[string][]byte
	err     error
	changed func()
	loads   int
}

func (s *fakeSource) Load(context.Context) (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	if s.err != nil {
		return nil, s.err
	}
	return maps.Clone(s.raw), nil
}

func (s *fakeSource) Watch(ctx context.Context, changed func(), _ *slog.Logger) {
	s.mu.Lock()
	s.changed = changed
	s.mu.Unlock()
	<-ctx.Done()
}

func (s *fakeSource) set(id string, raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw == nil {
		delete(s.raw, id)
	} else {
		s.raw[id] = raw
	}
}

func (s *fakeSource) poke() bool {
	s.mu.Lock()
	c := s.changed
	s.mu.Unlock()
	if c != nil {
		c()
	}
	return c != nil
}

// B-14, E-01: a valid set loads; a set with an entry stored under another
// id or one that does not parse is a startup error; an unreadable store
// is not (the ingest starts degraded, on loopback).
func TestLoadKeyring(t *testing.T) {
	h := cheapHasher(t)
	r := newRx(t, h, "rx-1", nil)
	raw, _ := json.Marshal(r.entry)
	f := newFixture(t)
	src := &fakeSource{raw: map[string][]byte{"rx-1": raw}}
	if n, err := LoadKeyring(context.Background(), src, f.kr); err != nil || n != 1 {
		t.Fatalf("valid: %d %v", n, err)
	}
	src.set("rx-2", raw)
	if _, err := LoadKeyring(context.Background(), src, f.kr); !errors.Is(err, ErrKeySetInvalid) {
		t.Fatalf("entry under another id: %v", err)
	}
	src.set("rx-2", []byte("{"))
	if _, err := LoadKeyring(context.Background(), src, f.kr); !errors.Is(err, ErrKeySetInvalid) {
		t.Fatalf("garbage: %v", err)
	}
	src.err = errors.New("bus down")
	if _, err := LoadKeyring(context.Background(), src, f.kr); err == nil || errors.Is(err, ErrKeySetInvalid) {
		t.Fatalf("unreadable: %v", err)
	}
	if f.kr.Len() != 1 {
		t.Fatal("a refused set replaced the held one")
	}
}

// A change pushed by the watch is followed at once; a broken reload keeps
// the last set; a deleted receiver goes.
func TestFollowKeySetReloadsOnPush(t *testing.T) {
	h := cheapHasher(t)
	r1, r2 := newRx(t, h, "rx-1", nil), newRx(t, h, "rx-2", nil)
	raw1, _ := json.Marshal(r1.entry)
	raw2, _ := json.Marshal(r2.entry)
	f := newFixture(t)
	src := &fakeSource{raw: map[string][]byte{"rx-1": raw1}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		FollowKeySet(ctx, src, f.kr, time.Hour, logging.Discard(), quietLimiter())
		close(done)
	}()
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return src.poke() && f.kr.Len() == 1 })
	src.set("rx-2", raw2)
	waitFor(t, func() bool { src.poke(); return f.kr.Len() == 2 })
	src.set("rx-2", []byte("{"))
	before := func() int { src.mu.Lock(); defer src.mu.Unlock(); return src.loads }()
	src.poke()
	waitFor(t, func() bool { src.mu.Lock(); defer src.mu.Unlock(); return src.loads > before })
	if f.kr.Len() != 2 {
		t.Fatal("a broken reload dropped the held set")
	}
	src.set("rx-2", nil)
	waitFor(t, func() bool { src.poke(); return f.kr.Len() == 1 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in 5 s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
