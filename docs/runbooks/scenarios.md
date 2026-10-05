# Runbook: scenarios

An alert path of the authority is done when a scenario raises it and
clears it through the real processes (CLAUDE.md rule 4, LESSONS
INV-02). The scenario harness is `internal/ltest` (WP-25); the
scenarios are `internal/ltest/scenarios/*_test.go` with their scenario
files in `internal/ltest/scenarios/testdata/`. This page says how to
run them, how to write one and how to read the results file.

## Running them

```
make up            # PostGIS, TimescaleDB and NATS (deploy/compose.dev.yaml)
make scenarios     # every scenario, one after another; results in scenario-results/
make down
```

`make scenarios` is `INTEGRATION=1 go test -p 1 -run Scenario ./internal/ltest/...`
with the development stack's URLs (`PG_URL`, `TS_URL`, `NATS_URL`) and
`SCENARIO_RESULTS_DIR`. One scenario: `-run TestScenarioSC07`. Without
`INTEGRATION=1` every scenario skips and says why; with it, a skip is a
failure in CI. The scenarios of one package run one after another: each
deletes and provisions again every stream of the bus topology. Run
nothing else against the same NATS meanwhile (`make integration`
recreates the same streams); a second stack on other ports
(`AUTHORITY_DEV_*_PORT`, `docker compose -p <name>`) runs beside the
first.

CI runs the job `scenarios` on every Go change with the same three
service containers as `integration`, and uploads `scenario-results/`
(each result, and the logs of a failed scenario) and `scenarios.log` as
the artifact `scenario-results`.

## What runs

Every process runs in the test binary through `proc.Main` with the
`Run` its `cmd/*/main.go` hands to it, so a scenario runs the binary's
wiring, configured from an environment map:

| Starter | Process | Notes |
|---|---|---|
| `StartRIDIngest` | rid-ingest | free port, this run's key-set bucket, the test geoid, `LAB_HEADERS_ALLOWED=true` |
| `StartTSDBWriter` | tsdb-writer | the scratch telemetry database |
| `StartDetect` | detect | `CELLS=all`, the synthetic DEM and the test geoid; returns once its TRK durable exists |
| `StartDPPoller` | dp-poller | the fake DSS, a token endpoint double, this run's oversight, views and certificates buckets |
| `StartMannedIngest` | manned-ingest | the fake ANSP over TLS, mTLS off (the lab's setting) |
| `StartViolationStore` | api's ALRT consumer | `internal/violations` against the scratch relational database |

api itself is not started: its binary needs signing keys, sessions and
TLS no scenario judges. What api does for a scenario is done by api's
own code: the violation store above, the projector writes of the
registry and zones (`Seed`, `SeedRegistry`, `PublishZones`), the policy
service (`Options.Policy`, `SetPolicy`) and the switch service
(`Switch`).

The ground is `internal/ground/testdata`: a synthetic DEM over cell
N41E044 (elevation `400 + 10 * row + col` metres, rows of 0.25 deg from
42 N, columns from 44 E: 422 m at 41.50 N 44.50 E, dataset
`COP-DEM GLO-30`) and a constant geoid of 15.9 m. Fly there: the ground
elsewhere is unknown and the height limit is not judged.

## Writing a scenario

```go
func TestScenarioSCxxWhatItShows(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-xx"})       // the stack; skips without INTEGRATION=1
	sd := s.Seed(seed("scxx.json"))                         // registry and zones, as api projects them
	z := s.ZoneByID(sd, "ZONE1")
	ri := standard(t, s)                                    // rid-ingest, tsdb-writer, detect, the violation store
	rx := s.NewReceiver(s.ReceiverID("rx-scxx"), z.LatDeg, z.LonDeg-0.01, ri)
	ac := &ltest.Aircraft{Transmitter: mac(0x123), Serial: "TESTSCXX00001", OperatorID: "GEOTEST00009901",
		System: true, Path: ltest.Legs(pass(z, 520)...)}
	f := rx.Fly(ac)                                         // 1 Hz, in the background
	f.WaitSteps(ltest.Steps(pass(z, 520)...))
	f.Stop()
	s.Await("the clear", 20*time.Second, func() bool { return s.Cleared(violation.KindZoneIncursion, ac.TrackID()) != nil })
	s.Verify(ltest.Raise(violation.KindZoneIncursion, ac.TrackID(), "resolved").InZone(z.ZoneID()))
	s.CheckIdentity(ri, true)
}
```

Rules:

- **Declare every raise you expect, and only those.** `Verify` fails on
  a missed alert (an expected raise that never came) and on a false
  alert (a raise nothing expected): both counts must be zero.
  `Raise(kind, track, clears...)` expects one raise per clear reason, in
  order; `""` expects the violation still open. Add `InZone` and
  `WithSeverity` when they matter.
- **Raise and clear.** A scenario that only raises proves half a path.
  Clear with the reason the path produces: `resolved` (out, past the
  hysteresis), `stale` (silence past `stale_after_s`), `landed`
  (ODID status ground), `source_disabled` (`Switch`), `reconfigured`
  (`PublishZones` without the zone, or a policy change), `authorised`
  (`height_120m` in U-space with an intent and `skip_when_authorised`).
  `flight_ended` is never produced by the authority: nothing here ends a
  flight (uspace-core `alerting.Monitor.Drop` is not called).
- **Pair every absence with its presence** (E-01). A "nothing is
  raised" check needs tracks in the place where something could have
  been raised (count them), and a sibling check where it is.
- **Never sleep.** Wait on what the system says: `Await` (re-checked at
  every bus message), `AwaitRaised`, `AwaitCleared`,
  `AwaitSourceState`, `Proc.WaitLine`, `Flight.WaitSteps`. Each has a
  deadline and fails naming what did not come.
- **Thresholds are the policy's.** A scenario uses the documented
  defaults (`policy.Defaults()`, several pending GCAA) or creates a
  policy version on purpose (`Options.Policy`); it never loosens a
  threshold to pass (INV-03). A policy choice under test (for example
  `height_limit_in_uspace: skip_when_authorised`) says so in the test's
  comment.
- **Fixtures** use `GEO...TEST...` operator numbers and `TEST*` serials
  (CLAUDE.md rule 11; `SeedRegistry` refuses others). A network Remote
  ID flight needs an ANSI/CTA-2063-A serial (`TEST9SC1600001`: `TEST`,
  length code `9`, nine characters) or the Display Provider does not
  take it as a serial. Zone types are ED-318's spelling
  (`REQ_AUTHORIZATION`).
- **Account for every observation**: end with `CheckIdentity(ri,
  writer)` when rid-ingest runs (`writer` true when tsdb-writer runs).
- **Name the scenario** (`Options.Name`, `SC-xx` from
  `uspace-lab/knowledge/scenarios.md` when it is one) and say in the
  comment what the scenario of record says and where this run differs.

Paths are `ltest.Legs(Stay, Move, Landed, Quiet...)` or any
`func(step int) ltest.State`; a step can change the serial, the operator
number or the address (`State.Serial`, `OperatorID`, `Transmitter`). A
receiver can drop (`DropRate` with `Seed`, or `Drop` for an exact
datagram), delay (`Latency`: posted that long after it was heard,
signed when sent) and mark batches as backlog (`Backlog`).

## Reading the results file

Each scenario writes `<SCENARIO_RESULTS_DIR>/<scenario>.json` when it
ends, pass or fail, and reads it back:

| Member | What it is |
|---|---|
| `scenario`, `test`, `passed` | the scenario, its Go test, and whether the test passed |
| `started_at`, `finished_at` | UTC |
| `commits` | `uspace-authority`: `git rev-parse HEAD`, with `+dirty` for a modified tree (`GITHUB_SHA` only when git cannot run; CI checks it equals `GITHUB_SHA`); `uspace-core`: the module version and sum the test binary was built with (E-05). "unknown: ..." says why one could not be read |
| `report.expected` | the expectations |
| `report.observed[]` | every violation seen on `alrt.v1`: id, kind, track, zone, severity, `raised_at`, `captured_at` (of the sample that raised it), `cleared_at`, `clear_reason`, `latency_ms` (captured_at to the raise on the bus), `stored_latency_ms` (to api's row), `events` (api's events rows), `expected` |
| `report.missed_alerts`, `report.false_alerts` | both 0 on a pass |
| `report.failures[]` | every difference, in words |
| `report.latency`, `report.stored_latency` | n, min, p50, p95, p99, max in ms; a raise p99 at or over 2000 ms fails (plan §8), except raises expected `GatedByAnOutcome` (waiting by design for a DSS outcome, WP-26), which are recorded only |
| `status` | each process's last status-line counters, by component |
| `notes.sources[]` | per receiver: `sent = accepted + duplicates + refused + dropped + failed`, `refused_by` (status and slug), the ingest's own `observations_accepted` and `batches_refused`, and `stored_rows` in `rid_observations` |
| `notes.tracks_published`, `notes.tracks_stored` | per track id, on `trk.v1` and in the tracks table |
| `notes.*` | what the scenario recorded (timings such as `instance_off_to_clear_ms`, source states, the policy versions used) |
| `log_lines_dropped`, `recorder_dropped` | the harness's own bounds exceeded (0 normally) |

A failed scenario also leaves `<scenario>.<process>.log` beside it: the
process's last 400 log lines.

## The scenarios

| Test | Scenario | What it raises and clears |
|---|---|---|
| `TestScenarioSmokeOneAircraftThroughAZoneWithNoDetector` | smoke (WP-25 done-when) | nothing: no detect durable on TRK, ALRT empty; tracks recorded end to end |
| `TestScenarioSC07UnidentifiedAircraftThroughAProhibitedZone` | SC-07 | `zone_incursion` (registered and unidentified) and `unregistered`, twice, cleared `resolved` |
| `TestScenarioSC04HeightLimitOverTheGround` | SC-04 | `height_120m`, cleared `resolved`; peak and DEM dataset stored |
| `TestScenarioSC06IdentificationStatusesAndMismatch` | SC-06 | the four identification statuses; `identification_mismatch` cleared `resolved` when the broadcast operator is corrected |
| `TestScenarioSC08SourcesSwitchedOffAndOn` | SC-08 | `zone_incursion` cleared `source_disabled` by instance and by type, raised again, cleared `resolved`; the switches' events rows |
| `TestScenarioStaleLandedAndASilentReceiver` | ageing | `zone_incursion` cleared `stale` and `landed`; a receiver live, stale, live |
| `TestScenarioSC12WindowsAndAZoneWithdrawnInFlight` | SC-12 | nothing out of a window; PROHIBITED (critical) and CONDITIONAL (warning) cleared `reconfigured` |
| `TestScenarioSC13AGLZonesWithNoDEM` | SC-13 | AGL zones with no DEM: warnings with `not_judged [AGL]`, cleared `resolved`; error-level status |
| `TestScenarioNoAuthorisationAndTheHeightLimitInUSpace` | WP-26 | `no_authorisation` cleared `resolved` by an intent; `height_120m` cleared `authorised` |
| `TestScenarioSC16NetworkProviderOffOnAndDown` | SC-16 | a network flight's `zone_incursion` cleared `source_disabled`, `stale` (provider down) and `resolved`; the provider disabled, down, live |
| `TestScenarioMannedFeedDownAndBack` | manned feed | the feed live, down, live |
| `TestScenarioSC10SerialChangeOnAReusedAddressWithDrops` | SC-10 | no Location under the old serial after the restart |
| `TestScenarioSC11ReceiverLatency` | SC-11 | placed at the broadcast time 1.9 to 2.1 s before receipt |
| `TestScenarioSC17ASuspensionReachesTheResolver` | SC-17 step 2 | a suspension on the tracks within the 5 s refresh |
| `TestScenarioSC18StorageDownWhileObservationsArrive` | SC-18 | rows wait in TSW with the writer down, none lost |
| `TestScenarioSC22MissingSourcesAreSaidNotSilent` | SC-22 | no geoid, projection, terrain or switch state: said on every status line |
| `TestScenarioTheRunnerDetectsAMissAndAFalseAlert` | E-01 | the runner reports a miss, a false alert and a wrong clear |
| `TestScenarioLabHeaderRefusedByAProductionIngest` | T11 | `400 lab_header` with the production default, accepted without the header |

Where a run differs from `uspace-lab/knowledge/scenarios.md` the test
says so: SC-04 changes the altitude over a gently falling synthetic DEM
instead of flying over Kazbegi; SC-12 moves the band to 450-650 m AMSL
so the aircraft stays under 120 m over the DEM; SC-17 runs step 2 only
(steps 3 to 6 are api's and the reader's, tested in
`internal/registry`). Not run by this harness: SC-05 (a conflict, which
the authority does not judge, D5), SC-09 and SC-14 (an authenticated
operator feed the authority does not have), SC-15 (an adapter process
paused with SIGSTOP, which an in-process run cannot do), SC-20 and SC-21
(SITL, the lab's), and SC-19 (replay holes: the records work, WP-27,
and the lab).
