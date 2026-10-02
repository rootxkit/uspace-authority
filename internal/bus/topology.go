package bus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Stream names (docs/PLAN.md §6).
const (
	StreamTRK    = "TRK"
	StreamALRT   = "ALRT"
	StreamIDENT  = "IDENT"
	StreamCIS    = "CIS"
	StreamINGEST = "INGEST"
	StreamTSW    = "TSW"
)

// Bucket names (docs/PLAN.md §6). The source-control and key-set buckets
// can be renamed by configuration (tests isolate themselves that way).
const (
	BucketSourceControl   = "source_control"
	BucketPolicy          = "policy"
	BucketCells           = "cells"
	BucketRegistryVersion = "registry_version"
	BucketZonesVersion    = "zones_version"
	BucketRIDReceiverKeys = "rid_receiver_keys"
)

// BucketHistory is the history of every bucket.
const BucketHistory = 8

// Value and message bounds (E-10). The server's own max_payload is 1 MiB
// by default, so no stream admits more.
const (
	MaxPayloadBytes = 1 << 20
	// DefaultSourceControlValueBytes bounds the whole source-control
	// state (BUS_SOURCE_CONTROL_MAX_VALUE_BYTES).
	DefaultSourceControlValueBytes = 256 << 10
	// PolicyValueBytes bounds the published policy.
	PolicyValueBytes = 64 << 10
	// CellsValueBytes bounds the ownership map.
	CellsValueBytes = 64 << 10
	// VersionValueBytes bounds a version announcement.
	VersionValueBytes = 1 << 10
	// RIDReceiverKeyValueBytes bounds one receiver's key-set entry.
	RIDReceiverKeyValueBytes = 16 << 10
	// DefaultIngestMaxMsgs is the INGEST hard bound: the work queue's
	// shedding bound plus the batches in flight, doubled, at rid-ingest's
	// defaults (2 x (60000 + 256)).
	DefaultIngestMaxMsgs = 120512
)

// Limits are the configurable parts of the topology.
type Limits struct {
	// TRKStorage is the TRK stream's storage (BUS_TRK_STORAGE).
	TRKStorage jetstream.StorageType
	// IngestMaxMsgs is INGEST's hard bound (discard new).
	IngestMaxMsgs int64
	// SourceControlBucket and SourceControlValueBytes name and bound the
	// source-control bucket.
	SourceControlBucket     string
	SourceControlValueBytes int32
	// RIDReceiverKeysBucket names the receiver key-set bucket.
	RIDReceiverKeysBucket string
}

// DefaultLimits are the documented defaults.
func DefaultLimits() Limits {
	return Limits{
		TRKStorage: jetstream.FileStorage, IngestMaxMsgs: DefaultIngestMaxMsgs,
		SourceControlBucket: BucketSourceControl, SourceControlValueBytes: DefaultSourceControlValueBytes,
		RIDReceiverKeysBucket: BucketRIDReceiverKeys,
	}
}

// ParseStorage maps BUS_TRK_STORAGE onto a storage type.
func ParseStorage(s string) (jetstream.StorageType, error) {
	switch s {
	case "file", "":
		return jetstream.FileStorage, nil
	case "memory":
		return jetstream.MemoryStorage, nil
	}
	return 0, core.Fieldf("BUS_TRK_STORAGE", "must be file or memory")
}

// Topology is every stream and bucket of this system.
type Topology struct {
	Streams []jetstream.StreamConfig
	Buckets []jetstream.KeyValueConfig
}

// dedupe is the duplicate window of every stream: a retried publish
// with the same Nats-Msg-Id inside it is stored once.
const dedupe = 2 * time.Minute

// NewTopology is the topology under l.
func NewTopology(l Limits) Topology {
	def := DefaultLimits()
	if l.IngestMaxMsgs <= 0 {
		l.IngestMaxMsgs = def.IngestMaxMsgs
	}
	if l.SourceControlBucket == "" {
		l.SourceControlBucket = def.SourceControlBucket
	}
	if l.SourceControlValueBytes <= 0 {
		l.SourceControlValueBytes = def.SourceControlValueBytes
	}
	if l.RIDReceiverKeysBucket == "" {
		l.RIDReceiverKeysBucket = def.RIDReceiverKeysBucket
	}
	stream := func(name, subject, desc string, storage jetstream.StorageType, age time.Duration, maxMsg int32) jetstream.StreamConfig {
		return jetstream.StreamConfig{
			Name: name, Description: desc, Subjects: []string{subject}, Retention: jetstream.LimitsPolicy,
			MaxAge: age, MaxMsgs: -1, MaxBytes: -1, MaxMsgSize: maxMsg, Storage: storage, Discard: jetstream.DiscardOld,
			Duplicates: dedupe, Replicas: 1,
		}
	}
	ingest := stream(StreamINGEST, SubjectIngestAll,
		"rid-ingest work queue (WP-7): acknowledged receiver batches awaiting decode and storage; the consumer sheds the oldest by age with a writer_gaps record",
		jetstream.FileStorage, 0, MaxPayloadBytes)
	ingest.Retention, ingest.Discard, ingest.MaxMsgs = jetstream.WorkQueuePolicy, jetstream.DiscardNew, l.IngestMaxMsgs
	bucket := func(name, desc string, maxValue int32) jetstream.KeyValueConfig {
		return jetstream.KeyValueConfig{
			Bucket: name, Description: desc, History: BucketHistory, MaxValueSize: maxValue, MaxBytes: -1,
			Storage: jetstream.FileStorage, Replicas: 1,
		}
	}
	return Topology{
		Streams: []jetstream.StreamConfig{
			stream(StreamTRK, SubjectTrkAll, "track hot path mirror for replay after a restart (1 h)", l.TRKStorage, time.Hour, 64<<10),
			stream(StreamALRT, SubjectAlrtAll, "violations raised and cleared by detect (7 d)", jetstream.FileStorage, 7*24*time.Hour, 256<<10),
			stream(StreamIDENT, SubjectIdentAll, "identification changes (24 h)", jetstream.FileStorage, 24*time.Hour, 64<<10),
			stream(StreamCIS, SubjectCisAll, "CIS cache updates (30 d)", jetstream.FileStorage, 30*24*time.Hour, MaxPayloadBytes),
			ingest,
			stream(StreamTSW, SubjectTswAll, "rows and gap records towards tsdb-writer (10 min spill)", jetstream.FileStorage, 10*time.Minute, MaxPayloadBytes),
		},
		Buckets: []jetstream.KeyValueConfig{
			bucket(l.SourceControlBucket, "source switches by type and instance (U-15): one key, the whole state", l.SourceControlValueBytes),
			bucket(BucketPolicy, "the active authority policy (INV-03)", PolicyValueBytes),
			bucket(BucketCells, "cell3 -> detect worker ownership map", CellsValueBytes),
			bucket(BucketRegistryVersion, "registry projection version", VersionValueBytes),
			bucket(BucketZonesVersion, "zones projection version", VersionValueBytes),
			bucket(l.RIDReceiverKeysBucket, "Remote ID receiver key set: receiver id -> bearer hash, HMAC secret, status", RIDReceiverKeyValueBytes),
		},
	}
}

// Stream returns the configuration of the stream name.
func (t Topology) Stream(name string) (jetstream.StreamConfig, bool) {
	i := slices.IndexFunc(t.Streams, func(c jetstream.StreamConfig) bool { return c.Name == name })
	if i < 0 {
		return jetstream.StreamConfig{}, false
	}
	return t.Streams[i], true
}

// Bucket returns the configuration of the bucket name.
func (t Topology) Bucket(name string) (jetstream.KeyValueConfig, bool) {
	i := slices.IndexFunc(t.Buckets, func(c jetstream.KeyValueConfig) bool { return c.Bucket == name })
	if i < 0 {
		return jetstream.KeyValueConfig{}, false
	}
	return t.Buckets[i], true
}

// Actions of a Change.
const (
	ActionCreated   = "created"
	ActionUpdated   = "updated"
	ActionUnchanged = "unchanged"
)

// Change is what Ensure did to one stream or bucket.
type Change struct {
	Kind   string // "stream" or "bucket"
	Name   string
	Action string
	// Diff names the settings an update changed.
	Diff []string
}

// Report is what Ensure did.
type Report struct {
	Changes []Change
}

// Count is the number of changes with action.
func (r Report) Count(action string) int {
	n := 0
	for _, c := range r.Changes {
		if c.Action == action {
			n++
		}
	}
	return n
}

// NothingToDo is true when every stream and bucket was already as
// configured.
func (r Report) NothingToDo() bool { return r.Count(ActionUnchanged) == len(r.Changes) }

func norm(v int64) int64 {
	if v <= 0 {
		return -1
	}
	return v
}

// streamDiff names the managed settings in which have differs from want.
func streamDiff(have, want jetstream.StreamConfig) []string {
	var d []string
	if !slices.Equal(have.Subjects, want.Subjects) {
		d = append(d, "subjects")
	}
	if have.Retention != want.Retention {
		d = append(d, "retention")
	}
	if have.MaxAge != want.MaxAge {
		d = append(d, "max_age")
	}
	if norm(have.MaxMsgs) != norm(want.MaxMsgs) {
		d = append(d, "max_msgs")
	}
	if norm(have.MaxBytes) != norm(want.MaxBytes) {
		d = append(d, "max_bytes")
	}
	if norm(int64(have.MaxMsgSize)) != norm(int64(want.MaxMsgSize)) {
		d = append(d, "max_msg_size")
	}
	if have.Storage != want.Storage {
		d = append(d, "storage")
	}
	if have.Discard != want.Discard {
		d = append(d, "discard")
	}
	if have.Duplicates != want.Duplicates {
		d = append(d, "duplicate_window")
	}
	if have.Description != want.Description {
		d = append(d, "description")
	}
	return d
}

func bucketDiff(have, want jetstream.KeyValueConfig) []string {
	var d []string
	if have.History != want.History {
		d = append(d, "history")
	}
	if norm(int64(have.MaxValueSize)) != norm(int64(want.MaxValueSize)) {
		d = append(d, "max_value_size")
	}
	if norm(have.MaxBytes) != norm(want.MaxBytes) {
		d = append(d, "max_bytes")
	}
	if have.Storage != want.Storage {
		d = append(d, "storage")
	}
	if have.Description != want.Description {
		d = append(d, "description")
	}
	return d
}

// ErrNotUpdatable is a difference JetStream cannot apply in place
// (storage or retention): an operator deletes the stream or changes the
// configuration.
var ErrNotUpdatable = errors.New("a stream's storage and retention cannot be changed in place")

// Ensure makes every stream and bucket of t exist as configured: it
// creates what is missing and updates what differs in a managed setting,
// and reports each. It is idempotent: a second run reports every item
// unchanged and logs "bus provisioning: nothing to do".
func Ensure(ctx context.Context, js jetstream.JetStream, t Topology, logger *slog.Logger) (Report, error) {
	var r Report
	for i := range t.Streams {
		want := &t.Streams[i]
		c := Change{Kind: "stream", Name: want.Name}
		s, err := js.Stream(ctx, want.Name)
		switch {
		case errors.Is(err, jetstream.ErrStreamNotFound):
			if _, err := js.CreateStream(ctx, *want); err != nil {
				return r, fmt.Errorf("create stream %s: %w", want.Name, err)
			}
			c.Action = ActionCreated
		case err != nil:
			return r, fmt.Errorf("stream %s: %w", want.Name, err)
		default:
			c.Diff = streamDiff(s.CachedInfo().Config, *want)
			if slices.Contains(c.Diff, "storage") || slices.Contains(c.Diff, "retention") {
				return r, fmt.Errorf("stream %s differs in %s: %w", want.Name, strings.Join(c.Diff, ", "), ErrNotUpdatable)
			}
			c.Action = ActionUnchanged
			if len(c.Diff) > 0 {
				if _, err := js.UpdateStream(ctx, *want); err != nil {
					return r, fmt.Errorf("update stream %s (%s): %w", want.Name, strings.Join(c.Diff, ", "), err)
				}
				c.Action = ActionUpdated
			}
		}
		r.Changes = append(r.Changes, c)
	}
	for i := range t.Buckets {
		want := &t.Buckets[i]
		c := Change{Kind: "bucket", Name: want.Bucket}
		kv, err := js.KeyValue(ctx, want.Bucket)
		switch {
		case errors.Is(err, jetstream.ErrBucketNotFound):
			if _, err := js.CreateKeyValue(ctx, *want); err != nil {
				return r, fmt.Errorf("create bucket %s: %w", want.Bucket, err)
			}
			c.Action = ActionCreated
		case err != nil:
			return r, fmt.Errorf("bucket %s: %w", want.Bucket, err)
		default:
			st, err := kv.Status(ctx)
			if err != nil {
				return r, fmt.Errorf("bucket %s: %w", want.Bucket, err)
			}
			c.Diff = bucketDiff(st.Config(), *want)
			if slices.Contains(c.Diff, "storage") {
				return r, fmt.Errorf("bucket %s differs in storage: %w", want.Bucket, ErrNotUpdatable)
			}
			c.Action = ActionUnchanged
			if len(c.Diff) > 0 {
				if _, err := js.UpdateKeyValue(ctx, *want); err != nil {
					return r, fmt.Errorf("update bucket %s (%s): %w", want.Bucket, strings.Join(c.Diff, ", "), err)
				}
				c.Action = ActionUpdated
			}
		}
		r.Changes = append(r.Changes, c)
	}
	if logger != nil {
		for _, c := range r.Changes {
			if c.Action != ActionUnchanged {
				logger.Info("bus provisioned", slog.String("kind", c.Kind), slog.String("name", c.Name),
					slog.String("action", c.Action), slog.Any("changed", c.Diff))
			}
		}
		if r.NothingToDo() {
			logger.Info("bus provisioning: nothing to do", slog.Int("unchanged", len(r.Changes)))
		} else {
			logger.Info("bus provisioning done", slog.Int("created", r.Count(ActionCreated)),
				slog.Int("updated", r.Count(ActionUpdated)), slog.Int("unchanged", r.Count(ActionUnchanged)))
		}
	}
	return r, nil
}

// OpenStream returns the stream cfg names, creating it from cfg when it
// does not exist and leaving an existing one as it is (api's Ensure owns
// its configuration): every process may run before api.
func OpenStream(ctx context.Context, js jetstream.JetStream, cfg jetstream.StreamConfig) (jetstream.Stream, error) {
	s, err := js.Stream(ctx, cfg.Name)
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		s, err = js.CreateStream(ctx, cfg)
		if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
			s, err = js.Stream(ctx, cfg.Name)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("stream %s: %w", cfg.Name, err)
	}
	return s, nil
}

// OpenBucket returns the bucket cfg names, creating it from cfg when it
// does not exist and leaving an existing one as it is.
func OpenBucket(ctx context.Context, js jetstream.JetStream, cfg jetstream.KeyValueConfig) (jetstream.KeyValue, error) {
	kv, err := js.KeyValue(ctx, cfg.Bucket)
	if errors.Is(err, jetstream.ErrBucketNotFound) {
		kv, err = js.CreateKeyValue(ctx, cfg)
		if errors.Is(err, jetstream.ErrBucketExists) {
			kv, err = js.KeyValue(ctx, cfg.Bucket)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("bucket %s: %w", cfg.Bucket, err)
	}
	return kv, nil
}

// ensureRetry is the wait between provisioning attempts.
const ensureRetry = 2 * time.Second

// EnsureUntilDone runs Ensure until it succeeds or ctx ends: api starts
// with NATS down (B-08) and provisions once it is back. Each attempt is
// bounded by attempt per stream and bucket; a failure is logged at a
// bounded rate (E-09) and retried.
func EnsureUntilDone(ctx context.Context, js jetstream.JetStream, t Topology, attempt time.Duration, logger *slog.Logger, lim *logging.Limiter) {
	for {
		actx, cancel := context.WithTimeout(ctx, attempt*time.Duration(len(t.Streams)+len(t.Buckets)))
		_, err := Ensure(actx, js, t, logger)
		cancel()
		if err == nil || ctx.Err() != nil {
			return
		}
		if lim != nil {
			lim.Limited("bus_ensure").Warn("bus provisioning failed; retrying", slog.String("error", err.Error()))
		}
		wait(ctx, ensureRetry)
	}
}
