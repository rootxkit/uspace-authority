// Package dp is dp-poller, the authority's ASTM F3411-22a Display
// Provider (WP-14; spec 02 F7, 05 §5, docs/PLAN.md §2.1, D6, Q-A7, Q-A8;
// docs/runbooks/display-provider.md). Safety-relevant: it is the
// authority's picture of every USSP flight. It observes only: nothing
// here sends anything towards an aircraft.
//
// Views (views.go, internal/dpviews). The areas shown are the oversight
// areas api publishes (KV dp_oversight) and the console viewports
// picture-ws reports (KV dp_views, expiring, so an idle console stops
// polling), at most DP_MAX_VIEWS. Each is cut into tiles whose diagonal
// is at most dp_view_diagonal_km (policy; never above F3411's
// NetMaxDisplayAreaDiagonalKm, 7 km), at most DP_MAX_TILES in all
// (tiles.go).
//
// Discovery (discovery.go, isa.go). Per tile, GET
// /rid/v2/dss/identification_service_areas?area= and a DSS subscription
// (PUT /rid/v2/dss/subscriptions/{id}, 24 h, renewed at 75 %, deleted
// when the tile is no longer viewed) with this system's uss_base_url,
// both with a token for the DSS's host granting rid.display_provider.
// The Service Provider that owns an ISA posts its changes to POST
// /uss/identification_service_areas/{id} (notify.go), served through the
// server generated from the pinned contract: the token is verified by
// uspace-core's verifier (this issuer or the lab's, aud one of
// AUTHORITY_AUDIENCES), must grant rid.service_provider, and its subject
// must own the ISA. The set of Service Providers comes only from the
// ISAs (00 §7); one whose owner holds no operating certificate is still
// polled and shown provider_unknown. With the DSS down the known ISAs
// stay in use until their time_end and the status says dss_unavailable.
//
// Polling (engine.go, client.go, provider.go). One poller per (Service
// Provider, tile), one request in flight each, at dp_poll_hz, with the
// limits of LESSONS R-14, each counted and logged at most once a minute:
// a 5 s deadline (the flights shown stay and age), 1 MiB bodies, 500
// flights per response, 64 tiles per Service Provider, 20 details
// fetches per poll, 4 at a time, only for tiles within the details
// diagonal (2 km); a 413 splits the tile into four, at most three times;
// past the F3411 p99 (3 s) the provider is slow and polled at 0.5 Hz;
// failing for 10 s it is unavailable since T and never removed; plain
// HTTP is refused except to a loopback host. A disabled Service
// Provider's pollers stop at once (source control, SC-16).
//
// Mapping (mapping.go). RIDFlight to track/telemetry/v1: trust provider,
// source network_rid, source_instance the Service Provider; the special
// values null (core's accessors); AMSL from HAE through the geoid
// (rid.SelectAltitude), the pressure altitude kept apart; the height
// with its reference; captured_at by timeplace.PlaceNetwork against the
// response timestamp, a state older than 60 s not published; the track
// id rid.AircraftID of a CTA serial (the direct broadcast's, D6, SC-06
// row 3), else rid.UnidentifiedID of the flight id; the identification
// identify.ResolveBroadcast on the provider basis (core.BasisProvider);
// the operator position as received, for the console realm only. A state
// identical to the last published is not published again, and a flight
// seen in two tiles is one flight (memory.go, bounded).
//
// Records (rows.go). The tracks rows and the ussp_flights rows (the
// flight and its details as received) go to tsdb-writer through a
// bounded queue; rows that cannot be handed over are counted and
// recorded as a writer gap. ussp_flights is disposed of within 24 h and
// checked hourly (CLAUDE.md rule 7).
//
// Status (status.go). src.v1.network_rid.<uss_id> every 2 s: live, down
// (unavailable since T), disabled by whom, or unknown; ISAs, tiles,
// flights, p95 and p99, slow, provider_unknown, the DSS's state and
// every counter.
//
// Conformance hook (observe.go, Q-A7). The InterUSS Remote ID
// observation interface at the commit api/clients/SOURCE records, under
// /v1/dp/observations, scope dp.observe (lab-01 only).
package dp
