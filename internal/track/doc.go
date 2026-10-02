// Package track is the track/telemetry/v1 message of the authority's
// picture (spec 04 §3.1, §3.2) with the 04 §2 envelope, typed from
// uspace-lab schemas/common/track/telemetry/v1, which this repository
// consumes and does not define (decision record M14): the USSP produces
// the same shape. A verbatim copy of the lab's schema and envelope is
// kept under testdata/ with the lab commit in testdata/SOURCE, and a test
// holds the struct's JSON names to it. Built by WP-8; dp-poller (WP-14)
// produces the same message for network Remote ID.
//
// What is here:
//
//   - Message, Body and Position: JSON names equal to the schema's. A
//     value the source did not give is null, never zero (LESSONS R-01,
//     R-10): every optional number is a pointer. alt_amsl_m is the
//     geodetic altitude through the geoid only; a pressure altitude is
//     carried in alt_pressure_m with alt_source "pressure" and never in
//     alt_amsl_m (R-08, CLAUDE.md rule 9).
//   - Validate: the schema's rules a producer can break (closed
//     enumerations, ranges, height_ref beside a height, mismatch on a
//     serial_conflict, the cell pattern), and the T11 refusal of
//     trust "simulated" and source "sitl", which production ingest never
//     accepts (spec 06 T11).
//   - Subject and Publish: trk.v1.<cell3>.<cell5>.<track_id> over core
//     NATS; the cell tokens come from internal/cell. A message that does
//     not validate is never published.
//   - IdentChange: the identification block emitted on
//     ident.v1.<track_id> when a track's status, reason or mismatch
//     changes (04 §3.2 "emitted on its own when it changes"). Its schema,
//     ident/change/v1, is this repository's (schemas/ident/change/v1.json):
//     no shared schema exists for it, a spec gap recorded in the WP-8
//     pull request.
//   - Row: one row of the tracks hypertable (timeseries 00006), the
//     message flattened for tsdb-writer (tsw.v1.tracks).
//
// A broadcast is never authenticated: every direct Remote ID track has
// trust "broadcast" and its identification basis "as_broadcast" (R-05).
package track
