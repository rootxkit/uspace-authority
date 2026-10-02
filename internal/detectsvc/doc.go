// Package detectsvc is the authority's violation detector (WP-12, plan
// D5; spec 01 A7, 04 §3.3; 2019/947 Art. 18(k)): the body of cmd/detect.
// Every judgement is uspace-core's alerting.Monitor (with zones for zone
// incursions and the 120 m rule, and the identification it carries); this
// package maps the authority's tracks onto the monitor's input, maps its
// raises and clears onto violation/v1, and moves them. It never decides
// whether an aircraft is where it may be.
//
// # Workers
//
// One Worker per claimed cell3 (one for CELLS=all), owned by one
// goroutine (RunWorker): a JetStream durable pull consumer on
// trk.v1.<cell3>.> (explicit ack, bounded pending, new messages only at
// its creation: history is never alerted, T-04), one monitor, and a tick
// every second (the end of a condition can be silence, T-10). An aircraft
// that crosses into another cell3 is held by that cell's monitor; the old
// one ages it out as stale.
//
// # Inputs (Shared)
//
//   - Zones: the published zones (internal/zonesvc ProjectionReader on
//     proj_zones) and the dynamic restrictions in force (RestrictionReader
//     on proj_restrictions: active and unknown, fail-safe; planned, ended
//     and cancelled are not in force), re-read periodically and at once on
//     zones.v1.changed and cis.v1.restrictions (Z-12).
//   - The policy: KV policy, written by api (internal/policy KV), with its
//     hysteresis, ageing, live age, severities, pressure margin and height
//     limit (ConfigFor, INV-03). Before one arrives the documented defaults
//     (version 1's) are judged with as policy_version 0, and every status
//     line says so.
//   - Source control (internal/sources Follower): a state taken is handed to
//     every monitor at once (SwitchSource), clearing the violations of the
//     aircraft of a source switched off as source_disabled (B-11, SC-08).
//   - The ground (internal/ground): zones.Env at each track's position,
//     never 0 m for an unknown ground (D-04).
//
// A new zone set or policy rebuilds the monitor (core's Monitor takes both
// at construction) and observes each aircraft's last live sample again:
// a violation the new monitor raises again is carried on under its
// violation_id; one it does not is cleared reconfigured (neither resolved
// nor left open).
//
// # Mapping (ToTrack, plan D5)
//
// Track id, position, altitude with its source (a pressure altitude is
// judged as indicated, widened by the pressure margin, R-09), flying from
// the operational status through core's f3411 (no status is Undeclared,
// airborne), CapturedAtS, RxAtS and SourceTS (T-01, T-03), Backlog (T-04),
// the source type and the authenticated instance (B-11), and the
// identification. Conflicts are not judged (Config.SkipConflicts, Q-A9); a
// conflict event, should one come, is counted conflict_events_ignored.
//
// Raises map onto violation/v1 kinds: height -> height_120m (peak
// height_agl_m, the DEM dataset in terrain_source), zone -> zone_incursion
// (except a USPACE zone: presence, recorded as in_uspace on the aircraft's
// violations), identification -> unregistered, identification_mismatch ->
// identification_mismatch. A severity change is published as updated under
// the same violation_id (C-07). Each raise copies the last
// DETECT_EXCERPT_WINDOW_S of the aircraft's samples into evidence_excerpt
// (bounded, E-10); every open violation is republished every second with
// its current numbers and the samples since (C-08); a clear carries its
// reason and the numbers at clearing (C-14).
//
// # Never silent
//
// A raise or clear the bus does not take waits in a bounded outbox,
// retried every tick (alrt_publish_failed; past the bound
// alrt_outbox_dropped at error level). A track the schema refuses is
// terminated and counted. An aircraft the monitor refuses for capacity is
// counted and logged at error level (C-18). The status line carries every
// counter of the worker and the monitor, and is at error level while
// anything in force is not judged: a projection never read, a zone or
// restriction that cannot be built, a PROHIBITED or REQ_AUTHORISATION zone
// whose AGL or WGS84 limit needs terrain or a geoid this process lacks
// (Z-09, SC-13, SC-22).
package detectsvc
