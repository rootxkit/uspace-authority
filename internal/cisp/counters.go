package cisp

// Counter names of the CISP client: every refusal, drop, fallback and
// degraded state is one of these on the status line and /metrics
// (E-09). Each has a named test.
const (
	// Publisher (F1).
	CounterPublicationsQueued       = "cis_publications_queued"        // a signed row written pending
	CounterPublicationsRefused      = "cis_publications_refused"       // a payload that failed the CISP's checks, refused before signing
	CounterPublicationsUnsigned     = "cis_publications_unsigned"      // refused: no publication key, or signing failed
	CounterPublicationsSuperseded   = "cis_publications_superseded"    // a pending row replaced by a newer snapshot (E-10)
	CounterPublicationsSent         = "cis_publications_sent"          // a PUT attempted
	CounterPublicationsAcknowledged = "cis_publications_acknowledged"  // the CISP's 2xx, its version stored
	CounterPublicationsAckAfter412  = "cis_publications_ack_after_412" // a 412 whose current version is this row's own bytes
	CounterPublicationsConflict     = "cis_publications_conflict"      // a 412: another version is current; stopped for an operator
	CounterPublicationsRetried      = "cis_publications_retried"       // a 5xx, a network error or a retryable 4xx: backoff
	CounterPublicationsFailed       = "cis_publications_failed"        // given up (a refusal, or 24 h of retries)
	CounterSenderSkipped            = "cis_sender_skipped"             // another replica held the sender's lock
	CounterSenderErrors             = "cis_sender_errors"              // the outbox could not be read or written

	// Heartbeat (M3).
	CounterHeartbeats       = "cis_heartbeats"        // a heartbeat the CISP answered 204
	CounterHeartbeatsFailed = "cis_heartbeats_failed" // any other answer or no answer
	CounterHeartbeatSkipped = "cis_heartbeat_skipped" // another replica held the heartbeat's lock

	// Subscriber (F3).
	CounterPulls               = "cis_pulls"
	CounterPullFailed          = "cis_pull_failed"
	CounterNotModified         = "cis_not_modified"
	CounterHeads               = "cis_heads"
	CounterDeltaPulls          = "cis_delta_pulls"
	CounterDeltaUnusable       = "cis_delta_unusable"
	CounterRejectedPublication = "cis_rejected_publications" // a version refused whole (ed318.Parse or the pinned schema), the previous one kept (T9)
	CounterUntrusted           = "cis_publisher_untrusted"   // a version held: its publisher's signature is missing or does not verify
	CounterVersionReplays      = "cis_version_replays"
	CounterReconcileCatchups   = "cis_reconcile_catchups" // a newer version found by the 60 s reconciliation, not by a notification
	CounterStoreFailed         = "cis_store_failed"
	CounterProjectionFailed    = "cis_projection_failed"
	CounterProjectionOlder     = "cis_projection_older" // a restrictions write older than the projection's, skipped
	CounterAnnounceFailed      = "cis_announce_failed"
	CounterSubscribeFailed     = "cis_subscribe_failed"
	CounterStaleTransitions    = "cis_stale"

	// Receiver (POST /v1/cis/notifications).
	CounterWebhooks           = "cis_webhooks"
	CounterBadSignature       = "cis_webhook_bad_signature"
	CounterWebhookMalformed   = "cis_webhook_malformed"
	CounterWebhookReplayed    = "cis_webhook_replayed"
	CounterWebhookAckOnly     = "cis_webhook_ack_only"
	CounterWebhookUnknown     = "cis_webhook_unknown_reason"
	CounterWebhookJTIFull     = "cis_webhook_jti_full"
	CounterWebhookStoreFailed = "cis_webhook_store_failed"
	CounterPullURLMismatch    = "cis_pull_url_mismatch"
	CounterANSPDirect         = "cis_ansp_direct_notifications"
)
