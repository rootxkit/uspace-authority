package ltest

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakeansp"
	"github.com/rootxkit/uspace-authority/internal/manned"
	"github.com/rootxkit/uspace-authority/internal/proc"
)

// StaticTokens hands every call the same bearer and counts the calls.
// The fake ANSP records the bearer and verifies nothing (its TLS
// certificate names 127.0.0.1, which no audience may name, M18), so
// the token's own issuance is not part of a manned scenario; it is
// tested in internal/tokens and internal/manned.
type StaticTokens struct{ calls atomic.Int64 }

// Token implements manned.Tokens.
func (s *StaticTokens) Token(context.Context, string, ...string) (string, error) {
	s.calls.Add(1)
	return "ltest-token", nil
}

// Calls is how many tokens were handed out.
func (s *StaticTokens) Calls() int64 { return s.calls.Load() }

// MannedFeedSubject is the src.v1 subject of the ANSP feed's status.
func MannedFeedSubject(instance string) string { return "src.v1.ansp_feed." + instance }

// StartMannedIngest runs manned-ingest (WP-15) against the fake ANSP a
// over TLS trusting its certificate, mTLS off (the lab's setting; said
// at error level by the process), for bbox (west,south,east,north), and
// returns once its stream is open at the fake.
func (s *Stack) StartMannedIngest(a *fakeansp.ANSP, bbox string, extra map[string]string) *Proc {
	s.T.Helper()
	env := s.merge(map[string]string{
		"ANSP_BASE_URL": a.URL(), "MANNED_BBOX": bbox, "AUTHORITY_MTLS_MODE": "off", "MANNED_STATUS_INTERVAL_MS": "500",
		"MANNED_BACKOFF_MIN_MS": "100", "MANNED_BACKOFF_MAX_MS": "1000", "MANNED_SWITCHES_REAPPLY_S": "1",
	}, extra)
	cfg := &config.MannedIngest{}
	tok := &StaticTokens{}
	p := s.track(StartProc(s.T, proc.Spec{Name: "manned-ingest", Config: cfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return manned.Run(ctx, rt, cfg, manned.Options{Tokens: tok, RootCAs: a.RootCAs()})
	}}, env))
	s.Await("the manned stream open at the ANSP", 20*time.Second, func() bool { return a.Open() >= 1 })
	return p
}

// ReplayLoop replays samples on a over and over until the returned stop
// is called or the test ends.
func (s *Stack) ReplayLoop(a *fakeansp.ANSP, samples []fakeansp.Sample) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			a.Replay(ctx, samples, 1)
		}
	}()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	s.T.Cleanup(stop)
	return stop
}
