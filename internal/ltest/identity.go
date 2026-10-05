package ltest

import (
	"fmt"
	"time"
)

// SourceAccount is one source's no-silent-loss identity in the results:
// what the simulator sent, what the ingest said, and what reached
// storage.
type SourceAccount struct {
	Source string `json:"source"`
	Tally
	// IngestAccepted is the ingest's own observations_accepted counter
	// (every receiver of the process together) and IngestRefused its
	// batches_refused.
	IngestAccepted *uint64 `json:"ingest_observations_accepted,omitempty"`
	IngestRefused  *uint64 `json:"ingest_batches_refused,omitempty"`
	// StoredRows are rid_observations rows of this receiver written by
	// tsdb-writer, when it runs.
	StoredRows *int64 `json:"stored_rows,omitempty"`
	Balanced   bool   `json:"balanced"`
}

// CheckIdentity proves that nothing was lost silently: for every
// simulated receiver, sent = accepted + duplicates + refused + dropped
// with nothing failed; the ingest's own counters say the same totals;
// and, when writer is true (tsdb-writer runs), rid_observations holds
// exactly the accepted observations of each receiver and the tracks
// table holds every track trk.v1 carried. It fails the test on any
// difference and records the accounts in the results.
func (s *Stack) CheckIdentity(ri *RIDIngest, writer bool) []SourceAccount {
	s.T.Helper()
	s.mu.Lock()
	sims := append([]*Receiver(nil), s.sims...)
	s.mu.Unlock()
	accounts := make([]SourceAccount, 0, len(sims))
	var accepted, refusedBatches uint64
	for _, r := range sims {
		t := r.Tally()
		a := SourceAccount{Source: r.ID, Tally: t, Balanced: t.Balanced() && t.Failed == 0}
		if !t.Balanced() {
			s.T.Errorf("%s: sent %d != accepted %d + duplicates %d + refused %d + dropped %d + failed %d",
				r.ID, t.Sent, t.Accepted, t.Duplicates, t.Refused, t.Dropped, t.Failed)
		}
		if t.Failed != 0 {
			s.T.Errorf("%s: %d observations got no answer from the ingest", r.ID, t.Failed)
		}
		accepted += uint64(t.Accepted)
		refusedBatches += uint64(t.RefusedBatch)
		accounts = append(accounts, a)
	}
	if ri != nil {
		since := time.Now()
		if ri.statusAfter(since, 10*time.Second) == nil {
			s.T.Errorf("rid-ingest wrote no status line after %v", since)
		}
		got := ri.Counter("rid_ingest", "observations_accepted")
		ref := ri.Counter("rid_ingest", "batches_refused")
		for i := range accounts {
			accounts[i].IngestAccepted, accounts[i].IngestRefused = &got, &ref
		}
		if got != accepted || ref != refusedBatches {
			s.T.Errorf("rid-ingest counted %d observations accepted and %d batches refused; the receivers were told %d and %d",
				got, ref, accepted, refusedBatches)
		}
	}
	if writer {
		for i := range accounts {
			a := &accounts[i]
			var n int64
			ok := s.awaitQuiet(30*time.Second, func() bool {
				if err := s.TSAdmin.QueryRow(`SELECT count(*) FROM rid_observations WHERE receiver_id = $1`, a.Source).Scan(&n); err != nil {
					return false
				}
				return n == int64(a.Accepted)
			})
			a.StoredRows = &n
			if !ok {
				s.T.Errorf("%s: %d rid_observations rows stored, %d observations accepted", a.Source, n, a.Accepted)
				a.Balanced = false
			}
		}
		s.checkTracksStored()
	}
	s.Note("sources", accounts)
	for _, a := range accounts {
		s.T.Logf("%s: sent %d = accepted %d + duplicates %d + refused %d (%v) + dropped %d + failed %d; stored %s",
			a.Source, a.Sent, a.Accepted, a.Duplicates, a.Refused, a.RefusedBy, a.Dropped, a.Failed, stored(a.StoredRows))
	}
	return accounts
}

func stored(n *int64) string {
	if n == nil {
		return "not checked (no tsdb-writer)"
	}
	return fmt.Sprintf("%d rows", *n)
}

// checkTracksStored waits until the tracks hypertable holds, for every
// track id trk.v1 carried, as many rows as were published.
func (s *Stack) checkTracksStored() {
	s.T.Helper()
	published := map[string]int64{}
	tracks := s.Rec.Tracks("")
	for i := range tracks {
		published[tracks[i].Msg.Body.TrackID]++
	}
	got := map[string]int64{}
	ok := s.awaitQuiet(30*time.Second, func() bool {
		rows, err := s.TSAdmin.Query(`SELECT track_id, count(*) FROM tracks GROUP BY track_id`)
		if err != nil {
			return false
		}
		defer func() { _ = rows.Close() }()
		got = map[string]int64{}
		for rows.Next() {
			var id string
			var n int64
			if rows.Scan(&id, &n) == nil {
				got[id] = n
			}
		}
		for id, n := range published {
			if got[id] != n {
				return false
			}
		}
		return true
	})
	if !ok {
		for id, n := range published {
			if got[id] != n {
				s.T.Errorf("track %s: %d published on trk.v1, %d rows in tracks", id, n, got[id])
			}
		}
	}
	s.Note("tracks_published", published)
	s.Note("tracks_stored", got)
}
