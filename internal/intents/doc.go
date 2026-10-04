// Package intents is the no_authorisation detector's view of the ASTM
// F3548-21 operational intents (WP-26; spec 04 §3.3 no_authorisation,
// 02 F6, Art. 6(4); docs/PLAN.md D5, Q-A5; docs/runbooks/no-authorisation.md).
// It observes only: it reads the DSS and never writes to it, and nothing
// here sends anything towards an aircraft.
//
// # Reads (client.go)
//
// One operation, queryOperationalIntentReferences (POST
// /dss/v1/operational_intent_references/query), through the client
// generated from the pinned contract (internal/dp/utmapi,
// api/clients/dss-utm.yaml) with uspace-core's f3548 types, a token for
// the DSS's host granting utm.conformance_monitoring_sa (Q-A5), a bounded
// body and a bounded number of references (refused whole past the bound,
// never cut). ParseQueryResponse checks the members the matching rests on
// (fuzzed).
//
// Two things the brief asks for are not reachable with that scope (spec
// gaps, WP-26 pull request): the intent details (GET
// /uss/v1/operational_intents/{entityid}, with the volumes and anything
// that might identify the operator) need utm.strategic_coordination, and
// so does a DSS subscription. So the DSS itself places intents: the board
// reads every U-space airspace in force every Requery (5 s) over the next
// Horizon (1 h), and asks for each aircraft inside one the intents at its
// position (a CheckRadiusM circle, its WGS84 height widened by
// VerticalMarginM when the track has one, one second either side of
// captured_at). A match is an intent at the aircraft's place and time,
// not the aircraft's own: F3548 references name neither operator nor UAS
// (IdentityNotExposed), and the DSS answers at its own cell resolution,
// so a flight close to an authorised one may be taken as authorised (a
// miss, never a false raise).
//
// # Judgement (judge.go)
//
// An intent the DSS places at the aircraft matches when it is flying
// (Activated, or Nonconforming or Contingent, whose conformance the USSP
// monitors) and captured_at is inside its window; every other intent of
// the airspace is a candidate with the reason it failed: withdrawn (no
// longer in the DSS), not_activated (Accepted), before_start, after_end,
// not_at_position. The place is the DSS's judgement; this package reads
// only the state and the window. With no cached intent of the airspace
// that could match, the aircraft is judged unmatched from the cache
// without asking the DSS.
//
// # Board (board.go) and cache (cache.go)
//
// The Board is shared by every worker of a detect process: workers ask
// (Want) for their aircraft inside U-space airspace and read the outcome
// (Outcome); Run reads the DSS once a second, at most ChecksPerStep
// positions per step (the rest deferred, counted), each aircraft at most
// every Recheck. An outcome stands OutcomeMaxAge; none stands while the
// DSS is unavailable: the detector is then suspended, raising nothing
// and clearing nothing on a match, and says so on every status line
// (E-02). The cache holds at most MaxCached references (the oldest
// withdrawn, else the one seen longest ago, evicted and counted, E-10)
// and never one no read listed for 24 h (F3548
// ExternalDataMaxRetentionTimeHours), nor one ended more than EndedKeep
// ago. Nothing is kept across a restart: the next reads rebuild it.
//
// Status: dss_state (dss_unconfigured, no_uspace_designated, starting,
// available, dss_unavailable with since and the last error),
// uspace_zones_watched, intents_cached, intents_withdrawn,
// aircraft_in_uspace, aircraft_matched, oldest_intent_age_s, and the
// counters of board.go and cache.go.
package intents
