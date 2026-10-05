package scenarios

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/ltest"
)

// SC-18 (storage down while observations arrive, B-06, B-07) through
// the stack: tsdb-writer is not running while a receiver posts; every
// batch is still acknowledged (202 after the work-queue write), the
// tracks are on the picture, and the rows wait in JetStream's TSW
// stream. The writer started, every observation and every track is
// written and none is lost: rid_observations equals what was accepted
// and the tracks table equals what trk.v1 carried. (The in-memory hold
// before the hand-over and its cap are rid-ingest's, tested in
// cmd/rid-ingest.)
func TestScenarioSC18StorageDownWhileObservationsArrive(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-18"})
	ri := s.StartRIDIngest(nil)
	const lat, lon = 41.30, 44.62
	rx := s.NewReceiver(s.ReceiverID("rx-sc18"), lat, lon, ri)
	ac := &ltest.Aircraft{Transmitter: mac(0x181), Serial: "TESTSC1800001", Path: ltest.Hold(lat, lon+0.001, 520)}
	f := rx.Fly(ac)
	f.WaitSteps(10)
	f.Stop()
	s.Await("the tracks on the picture", 10*time.Second, func() bool { return len(s.Rec.Tracks(ac.TrackID())) >= 10 })
	var rows int64
	if err := s.TSAdmin.QueryRow(`SELECT count(*) FROM rid_observations`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("%d rows written with no writer (%v)", rows, err)
	}
	waiting := s.StreamMessages(bus.StreamTSW)
	if waiting == 0 {
		t.Fatal("nothing waits in TSW with the writer down")
	}
	s.Note("tsw_messages_waiting", waiting)
	s.StartTSDBWriter(nil)
	s.Verify()
	s.CheckIdentity(ri, true)
}
