// Package ltest is the scenario harness (WP-25, plan §9; INV-02): it
// runs the authority's processes in one test binary against real NATS
// JetStream, PostgreSQL + PostGIS and TimescaleDB (the service
// containers of make up and of CI's scenarios job) and drives them with
// simulated inputs, so an alert path counts as done when a scenario has
// raised it and cleared it end to end.
//
// It is test-only: imported by _test.go files alone (depguard
// ltest-only-in-tests; internal/layout fails a binary that links it,
// spec 06 T11). Its simulated receiver is a real ODID broadcast as far
// as ingest knows, never "trust: simulated" on the wire, but every
// batch carries X-Lab-Scenario, which rid-ingest refuses unless
// LAB_HEADERS_ALLOWED is true (false by default), so a stray simulator
// cannot reach staging.
//
// # The stack (New)
//
// One scratch database of each migration tree, migrated from scratch
// (internal/store/storetest); every stream of the topology deleted and
// provisioned again (bus.Ensure) so nothing of an earlier scenario is
// read; this run's own receiver key-set and source-control buckets; the
// active policy published as api publishes it (the migration's seeded
// version, policy.Defaults(), unless a scenario creates and activates
// another through api's policy service). Scenarios of one package run
// one after another: the streams are shared. Without INTEGRATION=1 New
// skips, saying why.
//
// Seed applies a scenario file (registry operators and aircraft, zones):
// the registry and zones projections are written as api's projector
// writes them (registry.TSProjection, zonesvc.TSProjection) and
// announced on registry.v1.changed and zones.v1.changed after the
// commit. Switch sets a source on or off through api's switch service
// (the row, its events row, the KV state, then the push).
//
// # The processes
//
// StartRIDIngest, StartTSDBWriter, StartDetect, StartDPPoller and
// StartMannedIngest run each process through proc.Main with the Run its
// cmd/*/main.go hands to proc.Main (detect's whole body is
// detectsvc.RunProcess for this), configured from an environment map,
// with its stdout kept as JSON lines (Proc: WaitLine, Counters from the
// status line). Each returns once the process says it is ready, and
// detect once its TRK durable exists. StartViolationStore runs api's
// consumer of ALRT (internal/violations) against the scratch relational
// database: api's other duties need keys and sessions no scenario
// judges. The processes run on the wall clock; none of them takes a
// controllable clock across a process boundary, and the harness never
// sleeps to synchronise: it waits on bus messages, log lines and the
// receiver's steps, with a deadline.
//
// # Inputs
//
// Receiver is a simulated Remote ID receiver: aircraft paths (Legs,
// Hold: position, AMSL, speed, track, status, per-step serial, operator
// and address changes) at 1 Hz, encoded through uspace-core odid
// (Basic ID, Location, System, Operator ID; one pack, or one message per
// datagram for Bluetooth 4), the geodetic altitude broadcast as AMSL + N
// of the test geoid the ingest also reads and no timestamp until the
// transmitter knows UTC (R-16), signed with a key generated at run time
// (auth.SignReport) and posted to rid-ingest, with a drop rate, exact
// drops, a delivery latency and the backlog flag (SC-10, SC-11). Its
// Tally accounts for every observation it built.
//
// The doubles are the sibling packages: fakedss (an F3411 DSS and
// Service Provider and the F3548 operational intent query, on the
// pinned contracts), fakecisp (F1/F3), fakeansp (F4, with a recorded
// ADS-B file). TokenServer stands in for this system's own token
// endpoint for the processes that ask it for a token towards a peer.
//
// # The runner
//
// Recorder keeps everything on trk.v1, alrt.v1, src.v1 and man.v1 with
// its arrival time. Verify judges the violations seen on alrt.v1
// against the scenario's expectations (Raise: a kind on a track, raised
// once per expected clear reason): the missed-alert and false-alert
// counts must both be zero, each raise and clear must be stored by api
// with its events row, and the raise latency (captured_at of the
// raising sample to the raise) is measured against the plan's 2 s.
// CheckIdentity proves the no-silent-loss identity for every receiver:
// sent = accepted + duplicates + refused + dropped, nothing failed, the
// ingest's own counters agree, and rid_observations and the tracks
// table hold exactly what was accepted and published.
//
// Every scenario writes <SCENARIO_RESULTS_DIR>/<scenario>.json when it
// ends (the commits of this repository and of uspace-core it measured,
// E-05; the report; each process's last status counters; the
// receivers' accounts; notes), and a failed one each process's last log
// lines beside it. docs/runbooks/scenarios.md says how to write a
// scenario and how to read the file.
package ltest
