package tswriter

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// JetSource is a table's durable pull consumer on the TSW stream,
// opened on first use and again after a failure (the bus may be down at
// start, B-08).
type JetSource struct {
	// Open returns the stream and the consumer.
	Open func(ctx context.Context) (jetstream.Stream, jetstream.Consumer, error)
	// MaxDeletedDetails bounds the interior deletes read to count a hole
	// (E-10); beyond it a hole counts the head losses only.
	MaxDeletedDetails int

	mu       sync.Mutex
	stream   jetstream.Stream
	consumer jetstream.Consumer
}

var _ Source = (*JetSource)(nil)

func (s *JetSource) get(ctx context.Context) (jetstream.Stream, jetstream.Consumer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumer == nil {
		st, c, err := s.Open(ctx)
		if err != nil {
			return nil, nil, err
		}
		s.stream, s.consumer = st, c
	}
	return s.stream, s.consumer, nil
}

// reset makes the next call open the consumer again.
func (s *JetSource) reset() {
	s.mu.Lock()
	s.stream, s.consumer = nil, nil
	s.mu.Unlock()
}

// Fetch implements Source.
func (s *JetSource) Fetch(ctx context.Context, n int, wait time.Duration) ([]Msg, error) {
	_, c, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	b, err := c.Fetch(n, jetstream.FetchMaxWait(wait))
	if err != nil {
		s.reset()
		return nil, err
	}
	var out []Msg
	for m := range b.Messages() {
		out = append(out, m)
	}
	if err := b.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && len(out) == 0 {
		s.reset()
		return nil, err
	}
	return out, nil
}

// AckFloor implements Source.
func (s *JetSource) AckFloor(ctx context.Context) (uint64, error) {
	_, c, err := s.get(ctx)
	if err != nil {
		return 0, err
	}
	info, err := c.Info(ctx)
	if err != nil {
		s.reset()
		return 0, err
	}
	return info.AckFloor.Stream, nil
}

// Cursor implements Source: the stream first, then the consumer.
func (s *JetSource) Cursor(ctx context.Context) (Cursor, error) {
	st, c, err := s.get(ctx)
	if err != nil {
		return Cursor{}, err
	}
	si, err := st.Info(ctx)
	if err != nil {
		s.reset()
		return Cursor{}, err
	}
	ci, err := c.Info(ctx)
	if err != nil {
		s.reset()
		return Cursor{}, err
	}
	return Cursor{StreamLast: si.State.LastSeq, AckFloor: ci.AckFloor.Stream, NumPending: ci.NumPending}, nil
}

// Holes implements Source: the stream's limits remove messages from its
// head, so every sequence of a jump below the stream's first sequence is
// gone; interior deletes (an operator's DeleteMsg) are read from the
// stream's deleted list when it has any.
func (s *JetSource) Holes(ctx context.Context, jumps []Jump) ([]Hole, error) {
	st, _, err := s.get(ctx)
	if err != nil {
		return nil, err
	}
	info, err := st.Info(ctx)
	if err != nil {
		return nil, err
	}
	first := info.State.FirstSeq
	var deleted []uint64
	if info.State.NumDeleted > 0 && (s.MaxDeletedDetails <= 0 || info.State.NumDeleted <= s.MaxDeletedDetails) {
		di, err := st.Info(ctx, jetstream.WithDeletedDetails(true))
		if err != nil {
			return nil, err
		}
		deleted = di.State.Deleted
		if di.State.FirstSeq > first {
			first = di.State.FirstSeq
		}
	}
	return holesOf(jumps, first, deleted), nil
}

// holesOf computes, per jump, the sequences gone from a stream whose
// first sequence is first and whose interior deletes are deleted.
func holesOf(jumps []Jump, first uint64, deleted []uint64) []Hole {
	out := make([]Hole, len(jumps))
	for i, j := range jumps {
		var h Hole
		add := func(seq uint64) {
			if h.Count == 0 || seq < h.FromSeq {
				h.FromSeq = seq
			}
			if seq > h.ToSeq {
				h.ToSeq = seq
			}
			h.Count++
		}
		// Head: (After, min(Before, first)).
		if end := min(j.Before, first); end > j.After+1 {
			h.FromSeq, h.ToSeq, h.Count = j.After+1, end-1, end-1-j.After
		}
		for _, d := range deleted {
			if d > j.After && d < j.Before && d >= first {
				add(d)
			}
		}
		out[i] = h
	}
	return out
}
