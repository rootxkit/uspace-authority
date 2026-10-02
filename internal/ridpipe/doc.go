// Package ridpipe is the Remote ID pipeline of rid-ingest: decode,
// identity, time, altitude, identification, track (docs/PLAN.md §3,
// WP-8). Safety-relevant: every identification and every position the
// picture shows for a broadcast passes here.
//
// WP-7 defined the seam: the Batch rid-ingest has authenticated and
// queued, its raw Rows, and the Sink it hands each batch to once, after
// the batch has left the durable work queue and before its rows are
// stored. Pipeline is that Sink. Every judgement is a call into
// uspace-core (CLAUDE.md rule 3); this package maps the wire onto core's
// inputs and core's outputs onto the track message, and decides nothing
// itself. Per row:
//
//  1. Receipt. The row's reception is placed on this system's clock by
//     T-02 (timeplace.PlaceBatch): rx = IngestTS - (newest ReceiverTS in
//     the batch - ReceiverTS), so the receiver's clock error cancels and
//     the rows keep their spacing; a spacing past 120 s is clamped and
//     counted. A row without ReceiverTS is received at its arrival,
//     IngestTS, and counted (rx_ts_missing, T-12).
//  2. Decode (odid.Decode; R-01..R-04). A refusal is counted by phrase
//     (decode_refused_<phrase>, numbers folded, at most 64 kinds then
//     decode_refused_other), written to the row's decode_error and logged
//     the first time per kind, then once a minute (E-09). Self-ID,
//     Authentication and undefined types decode to nothing; a frame of
//     only those is counted (frames_without_messages). Unknown values are
//     null, never numbers. The decoded columns are written into the row
//     (serial, operator_reg, id_type, lat_deg, lon_deg, alt_wgs84_m,
//     alt_pressure_m, height_m, height_ref, speed_ms, track_deg,
//     vspeed_ms, status, ts_broadcast, captured_at, time_source).
//  3. Time placement (timeplace.PlaceBroadcast with rx and the declared
//     accuracy; T-07, T-08). A Location is placed at its broadcast time
//     when that is believed, otherwise at rx with the fallback counted
//     (time_fallback_<reason>). A row received at arrival (T-12) whose
//     broadcast time is not believed is placed at arrival with
//     time_source system (timeplace.PlaceArrival). Every other row is
//     placed at rx (source_clock, or system for T-12). backlog is the
//     batch's verdict, copied (T-04).
//  4. Identity per transmitter (rid.Tracker; I-01..I-04, R-13), settings
//     from the policy values: identity TTL 15 s, max gap 3 s, identify
//     within 4 s, bounded to MaxTransmitters addresses (E-10). One
//     tracker is keyed by transmitter across every receiver (I-03
//     borrowing) for live rows, and a second one for backlog rows, so a
//     replayed history never borrows a live identity and never moves the
//     live tracker's clock (T-04). Each tracker's clock is the placed
//     rx of its rows in Unix seconds, the rows of a batch taken in the
//     order they were heard; a row behind the clock (an older batch) is
//     taken at the clock and counted (tracker_clock_held). Wall time
//     never moves a tracker's clock: Tick only forgets the live
//     tracker's transmitters silent at now - MaxBatchSpacing, once a
//     second, and never touches the backlog tracker. The tracker publishes each
//     Location once (Take returns nil for a frame that publishes
//     nothing); the track id is rid.AircraftID(id_type, ua_id) when
//     identified and rid.UnidentifiedID(transmitter) otherwise (I-06;
//     D6: the id the DP path gives the same serial). A Location the
//     tracker held for its identity keeps the placement of the row that
//     carried it. The tracks row names the receiver whose Basic ID
//     identified the track (identity_receiver: the lender when a
//     receiver borrowed another's identity, S-35).
//  5. Altitude (rid.AltitudeSelector per track and tracker, so a
//     replayed poor fix never holds the live track on pressure; geoid of WP-11;
//     R-07, R-08). alt_amsl_m is HAE minus the undulation and nothing
//     else; a pressure altitude stays in alt_pressure_m with alt_source
//     pressure and the 10 s hold, never in alt_amsl_m. With no geoid
//     configured alt_amsl_m is null and counted, and the startup line
//     and every status line say such aircraft are not judged vertically
//     (SC-05 step 3, SC-22).
//  6. Velocity and status (rid.VelocityNED, rid.Airborne; R-10, R-11): a
//     speed without a direction is no velocity, and speed_ms, track_deg
//     and vspeed_ms are null together; the tracks row records airborne
//     from the status (only Ground is not airborne). accuracy_h_m and
//     accuracy_v_m are null: no metre value for the ODID accuracy codes
//     exists in uspace-core, and none is written from memory (E-03).
//  7. Identification (identify.ResolveRemoteID over the registry
//     projection of WP-3, basis as_broadcast; G-01, G-02, G-05, G-12,
//     I-05). Before the projection has ever loaded the lookup is nil and
//     the answer is registry_unavailable (or no_serial without a
//     serial), counted (SC-22). The operator number is compared on its
//     public part by core (regnum.CompareKey). D6: the authority holds no
//     authenticated telemetry, so identify.JudgeFleet is never called and
//     reason serial_conflict cannot arise from this process.
//  8. Publish: one track/telemetry/v1 per observation, trust broadcast,
//     source direct_rid, source_instance the receiver, on
//     trk.v1.<cell3>.<cell5>.<track_id> (internal/track, internal/cell);
//     the identification on ident.v1.<track_id> when its status, reason
//     or mismatch differs from the last one published for the id by the
//     same tracker (bounded to MaxTracks ids, E-10; an evicted id
//     announces again);
//     the tracks row of each published observation into Batch.Tracks,
//     which rid-ingest's worker hands to tsdb-writer on tsw.v1.tracks
//     after the raw rows, with their retry and acknowledgement (B-05,
//     SC-18).
//
// Undecoded is the stand-in Sink of a build without the pipeline: it
// counts every row as not decoded.
package ridpipe
