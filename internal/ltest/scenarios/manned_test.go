package scenarios

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakeansp"
)

// The manned feed's degraded state (02 F4; B-03, B-04, C-12: an
// unavailable feed is not lost; E-02): manned-ingest streams the fake
// ANSP's recorded ADS-B traffic (synthetic, TST callsigns) as man.v1
// with the feed live. The ANSP goes down: the feed's status says down
// (unavailable since T, never silently empty) and no manned track is
// published; the ANSP back, the feed is live again and the tracks
// resume. The authority raises no violation from manned traffic (D5).
func TestScenarioMannedFeedDownAndBack(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "manned"})
	a := fakeansp.New(fakeansp.Options{StatusEvery: 500 * time.Millisecond})
	t.Cleanup(a.Close)
	recording, err := fakeansp.LoadRecording(filepath.Join("..", "fakeansp", "testdata", "adsb-recording.jsonl"))
	if err != nil || len(recording) == 0 {
		t.Fatalf("recording: %d samples, %v", len(recording), err)
	}
	s.StartTSDBWriter(nil)
	s.StartDetect(nil)
	s.StartViolationStore()
	feed := ltest.MannedFeedSubject("ansp")
	p := s.StartMannedIngest(a, "44.6,41.5,45.1,41.9", nil)
	if l := p.WaitLine("AUTHORITY_MTLS_MODE=off: no client certificate is presented to the ANSP (lab and staging only)", nil, 10*time.Second); l["level"] != "ERROR" {
		t.Errorf("mTLS off said at %v, want ERROR", l["level"])
	}
	s.ReplayLoop(a, recording)

	s.AwaitSourceState(feed, "live", time.Time{}, 20*time.Second)
	s.Await("manned tracks", 20*time.Second, func() bool { return len(s.Rec.Manned()) >= 5 })

	a.Down()
	down := time.Now()
	s.AwaitSourceState(feed, "down", down, 20*time.Second)
	quiet := time.Now().Add(500 * time.Millisecond)
	s.AwaitSourceState(feed, "down", quiet.Add(time.Second), 10*time.Second)
	for _, m := range s.Rec.Manned() {
		if m.At.After(quiet) {
			t.Errorf("a manned track on %s while the ANSP was down", m.Subject)
			break
		}
	}

	a.Up()
	up := time.Now()
	s.AwaitSourceState(feed, "live", up, 30*time.Second)
	s.Await("manned tracks again", 20*time.Second, func() bool {
		n := 0
		for _, m := range s.Rec.Manned() {
			if m.At.After(up) {
				n++
			}
		}
		return n >= 3
	})
	states := s.Rec.SourceStates(feed)
	s.Note("feed_states", states)
	t.Logf("the feed went through %v", states)
	s.Verify() // manned traffic raises nothing
}
