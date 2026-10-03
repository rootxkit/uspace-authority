// Package manned is manned-ingest (WP-15; spec 02 F4, 04 §3.1; docs/PLAN.md
// §2.1): the authority's client of the ANSP's manned traffic information
// service (Reg. (EU) 2021/665 ATS.OR.127(a)).
//
// Transport (Client): for every connection a token from this system's
// own issuer (scope ansp.traffic, aud the ANSP's host, M18), with
// AUTHORITY_MTLS_MODE=required this system's client certificate (off in
// the lab and on staging, said at error level on every status line,
// M25), a bootstrap from GET /v1/manned-traffic/snapshot?bbox= and the
// stream WS /v1/manned-traffic/stream?bbox=. It reconnects forever with
// a jittered backoff (B-08) and closes the stream when source control
// switches the feed off (type ansp_feed, or its instance), opening it
// again when switched on. The paths, the frames and every member name
// are the ANSP's api/openapi.yaml and schemas/track/manned/v1.json,
// pinned in api/clients with api/clients/SOURCE (M11, M14).
//
// Frames (Ingest) are the 04 §2 envelope with a body named by schema
// (M12, M29) and are dispatched on it:
//
//   - track/manned/v1: the body is validated against the ANSP's schema
//     (refused and counted otherwise), gated by source control per
//     adapter, placed on this system's clock and published on
//     man.v1.<cell3>.<cell5>.<icao24> (picture-ws) with its row towards
//     tsdb-writer (manned_tracks). Placement (T-01, T-02): the samples of
//     one frame and the ANSP's write time of the frame (captured_at +
//     age_s) are one batch for uspace-core's timeplace.PlaceBatch, which
//     puts the write time at arrival and each sample before it by its age,
//     so the ANSP's clock skew cancels; a spacing over 120 s is clamped
//     and counted; a frame without rx_ts is placed at arrival and counted
//     (T-12); time_source is provider (system at arrival). The body is
//     kept as the ANSP wrote it: alt_pressure_m (pressure altitude, never
//     AMSL) and alt_wgs84_m (geometric, null when the source gave none)
//     stay apart (D-03); trust surveillance, source ansp_feed,
//     source_instance the ANSP's adapter.
//   - console/status/v1: the feed's own status; the ANSP's degraded[] and
//     sources[] are copied onto this system's source status, and an
//     adapter its adapters[] says is stale, down or disabled ages that
//     adapter's aircraft exactly as a local switch would.
//   - console/snapshot/v1: its aircraft are one batch; its adapters as
//     above.
//   - any other schema is counted and skipped (additive rule), never a
//     disconnection.
//
// One state per aircraft (bounded, E-10) deduplicates: an older sample,
// or the same sample again (the snapshot after a reconnection), is
// skipped; the same sample in a later state (live, stale,
// source_disabled) is republished in that state at its own placement.
// An aircraft is aged, never removed (CLAUDE.md rule 8): a switched-off
// adapter or feed ages its aircraft source_disabled, a stale or
// unavailable feed ages them stale.
//
// Feed state (Feed, Status): healthy, stale (no frame for
// MANNED_STALE_AFTER_S, 5 s, console/status/v1 included), unavailable
// since T (the socket is down: what the ANSP holds is not lost, B-04,
// C-12), lagging with lag_s (the freshest live aircraft older than
// MANNED_LAG_AFTER_S when it arrived, B-03) or disabled by whom;
// published every 2 s on src.v1.ansp_feed.<MANNED_FEED_INSTANCE>, with
// each ANSP adapter's own status on src.v1.ansp_feed.<adapter>, which
// picture-ws shows (WP-13). Every refusal, skip, clamp and reconnection
// is a named counter on the status line and /metrics (E-09).
//
// The process never sends anything towards an aircraft and never opens
// a database (B-15): rows go to tsdb-writer over JetStream.
package manned
