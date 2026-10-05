// Package cisp is the authority's client of the CISP (spec 02 F1, F3;
// docs/PLAN.md §5, §6, §7; WP-6): the signed publication outbox and its
// sender, the publisher heartbeat, the F3 subscriber with its webhook
// receiver and its 60 s reconciliation, the cache of every CIS dataset
// and the restrictions projection the detectors read. It never commands
// an aircraft and judges nothing: ED-318 is uspace-core's ed318, the
// JWS are uspace-core's auth helpers (SignDetached, DetachedVerifier,
// SignCompact, CompactVerifier, KeyRing; M26, M27), and the CISP's
// shapes are the pinned copies in api/clients (cisp.yaml, from which
// cispclient is generated, and cisp-schemas/, both at the commit
// api/clients/SOURCE records and CI compares).
//
// Built by WP-6:
//
//   - Outbox (publications, migrations 00013 and 00014). A publication
//     of zones or uspace_airspace (WP-5's export, through zonesvc) or of
//     the USSP list (WP-16, Outbox.Enqueue) is held to what the CISP
//     accepts before anything is signed (CheckPublication: ed318.Parse
//     and the CISP's dataset rules, cis/uspace_requirements/v1 on every
//     USPACE feature and cis/ussp_list/v1 for the list, validated with
//     the pinned schemas; refused whole, 400 publication_refused, every
//     problem by path), signed as a detached JWS with the publication
//     key (b64 false, crit ["b64"], RS256, kid, iat), and written
//     pending with its payload_hash; one pending snapshot per dataset,
//     a newer one supersedes it (E-10). Without the key nothing is
//     queued (503 publication_key_missing). Every state change is an
//     events row (publication_queued, _superseded, _sent, _acknowledged,
//     _retry_scheduled, _failed, _conflict).
//   - Sender (session advisory lock, so one api replica sends). In order
//     per dataset: PUT /v1/publications/{dataset} with If-Match the CISP
//     version last acknowledged (or the one a conflict showed; "zones:0"
//     before the first), a bearer of authority-01 with the dataset's
//     publish scope, and the bytes re-signed at every attempt (the CISP
//     holds iat to five minutes, so a signature made when the row was
//     queued would not survive a retry). 2xx is acknowledged with the
//     CISP's version; 412 reads the CISP's current version back and is
//     acknowledged when it holds this row's bytes (an attempt that landed
//     but whose answer was lost), otherwise it is a conflict and the
//     dataset stops for an operator (never overwritten; the operator's
//     next publication is sent against the version the conflict showed);
//     5xx, 408, 429, 401, 403 and no answer are retried after 2 s
//     doubling, capped at 5 min, for 24 h after the row was queued, then
//     failed with the last reason; any other refusal fails at once with
//     the CISP's problems.
//   - Heartbeat (M3): POST /v1/publishers/heartbeat {sent_at} every 15 s
//     with the zones publish scope, under its own lock; active_refs is
//     omitted (the authority publishes no restrictions). The last
//     success, status and failures are on the status line and the
//     console; a failure is a counter, never a crash.
//   - Subscriber. One worker per dataset (zones, uspace_airspace,
//     ussp_list, restrictions) pulls on a notification and reconciles
//     every 60 s whether or not notifications arrive: HEAD with the held
//     ETag, and on a change the delta from the version held
//     (?since_version=, or the notification's pull_url once the receiver
//     accepted it), merged and parsed like a whole read; any trouble
//     with a delta reads the dataset whole. Every received collection
//     goes through ed318.Parse (the restrictions also need the CISP's
//     cis_restriction block on every feature; the USSP list the pinned
//     schema) and is refused whole when it fails, counted as
//     cis_rejected_publications and shown, the previous version kept
//     (T9). A version is used only when its publisher's signature
//     verifies: GET /v1/{dataset}/versions/{v} and X-Publisher-Signature
//     over those bytes, with the authority's publication keys for its
//     own datasets and the ANSP's for the restrictions; a version without
//     one (a version the CISP made itself, a restriction expiring) or
//     whose signature does not verify is held, counted
//     (cis_publisher_untrusted) and shown, never used. The version held
//     is in cis_cache with when it was fetched and when the CISP last
//     confirmed it; cis_age_s is the time since that confirmation, and a
//     dataset older than the policy's cis_stale_bound_s, or never read,
//     is stale (cis_stale on the status line and the console, its
//     transitions logged). A restart serves the cached versions with
//     their age on the database clock.
//   - Restrictions projection (migration 00010 in the telemetry tree):
//     every feature of the restrictions version held, with its state and
//     window from the CISP block (an unknown state is projected
//     "unknown", never dropped), written whole with the version in
//     proj_restrictions_state (an older version never replaces a newer
//     one), then announced on cis.v1.<dataset> (schemas/cache/cis/v1)
//     for detect (WP-12, Z-12). A known empty dataset is projected as
//     version 0 with no rows, so "no restriction" never looks like
//     "never projected".
//   - Receiver, POST /v1/cis/notifications (M1), served outside the
//     generated server (x-cis-delivery): application/jose of at most
//     256 KiB, a compact JWS verified by core's CompactVerifier against
//     AUTHORITY_CIS_NOTIFY_ISSUERS (the CISP and the ANSP's direct
//     delivery, M5), aud one of AUTHORITY_AUDIENCES (M19), iat at most
//     five minutes old; the jti remembered in cis_delivery_jtis for ten
//     minutes (a repeat is acknowledged 204 and not acted on; beyond
//     CIS_JTI_MAX_LIVE live ids 503, E-10). publication and the
//     restriction_* reasons start a pull; subscription_test, republished
//     and any reason unknown here are acknowledged 204 without one (M16).
//     A pull_url is followed only when it is https on the configured
//     CISP's host and port; any other is counted and the configured
//     CISP is read instead. An ANSP restriction notification whose
//     pull_url is on the ANSP's issuer URL goes to the direct path
//     (direct.go, H-2): its version is the restriction's ansp_version,
//     the signed restriction/direct/v1 is pulled from the ANSP and
//     projected over the CISP's restrictions until the CISP holds it. Refusals are
//     counted and logged once per interval.
//   - GET /v1/publications: the outbox rows with their state and, while
//     pending or sent, their "not yet published" age (02 F1), beside the
//     cache's state per dataset, the heartbeat and the subscription.
//
// Decisions and spec gaps (in the pull request and the runbook):
//
//   - Reads are unfiltered (no ?at=): the provenance check needs the
//     version as published, and the detectors judge the window of every
//     restriction themselves (WP-12), so a planned restriction is
//     projected before it applies.
//   - The collection served by GET /v1/{dataset} is built by the CISP
//     and is not the publisher's bytes, so the signature verified is the
//     publisher's over the version's bytes; the CISP's own
//     X-CIS-Signature is not verified.
//   - Versions the CISP makes itself carry no publisher signature and are
//     held until the publisher's next signed version (the CISP's
//     contract, shared with the USSPs).
//   - The authority's own versions are verified with the publication key
//     configured now; a version signed by an earlier publication key is
//     held until the next publication.
package cisp
