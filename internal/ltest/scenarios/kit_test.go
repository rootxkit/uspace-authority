package scenarios

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/ltest"
)

// The scenarios of uspace-lab knowledge/scenarios.md that the authority
// owns, and every alert path of the authority, through internal/ltest:
// a simulated receiver posting signed ODID frames to rid-ingest, the
// processes run in this test binary with the binary's wiring, real
// NATS, PostgreSQL and TimescaleDB (INTEGRATION=1, the service
// containers of make up or CI). Each scenario declares what it expects;
// the runner fails it on a missed or a false alert, checks every raise
// and clear against api's stored rows and their events, measures the
// latency and the no-silent-loss identity, and writes the results file
// (docs/runbooks/scenarios.md).

// Every scenario flies in cell N41E044, where internal/ground's
// synthetic DEM is known (elevation 400 + 10*row + col over 0.25 deg
// rows from 42 N and columns from 44 E: 422 m at 41.50 N 44.50 E) and
// the test geoid is 15.9 m.

// seed is a scenario file of testdata.
func seed(name string) string { return filepath.Join("testdata", name) }

// near is a point dNorthDeg, dEastDeg from z's centre at altAMSLM.
func near(z ltest.Zone, dNorthDeg, dEastDeg, altAMSLM float64) ltest.Point {
	return ltest.At(z.LatDeg+dNorthDeg, z.LonDeg+dEastDeg, altAMSLM)
}

// centre is z's centre at altAMSLM.
func centre(z ltest.Zone, altAMSLM float64) ltest.Point { return near(z, 0, 0, altAMSLM) }

// outside is a point 0.003 deg (about 330 m) north of z's centre.
func outside(z ltest.Zone, altAMSLM float64) ltest.Point { return near(z, 0.003, 0, altAMSLM) }

// mac is a test transmitter address.
func mac(n int) string { return fmt.Sprintf("AA:BB:CC:25:%02X:%02X", n>>8, n&0xff) }

// standard starts the processes most scenarios need: rid-ingest,
// tsdb-writer, detect and api's violation store.
func standard(t *testing.T, s *ltest.Stack) *ltest.RIDIngest {
	t.Helper()
	ri := s.StartRIDIngest(nil)
	s.StartTSDBWriter(nil)
	s.StartDetect(nil)
	s.StartViolationStore()
	return ri
}
