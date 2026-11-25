// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nathole

import (
	"sync"
	"time"
)

// Audit outcomes. They are bounded and safe to use as low-cardinality metrics
// labels. Backend/user/time remain searchable in records and logs but are not
// metric dimensions.
const (
	OutcomeDirect   = "direct"
	OutcomeRelay    = "relay"
	OutcomeFailed   = "failed"
	OutcomeRejected = "rejected"
)

// Stable reason codes. Never put addresses, credentials or wrapped network
// errors in these values.
const (
	ReasonNotFound         = "backend_not_found"
	ReasonUnauthorized     = "unauthorized"
	ReasonAuthFailed       = "auth_failed"
	ReasonPeerTimeout      = "peer_timeout"
	ReasonNoResponse       = "no_response"
	ReasonNoData           = "no_data"
	ReasonPeerFailed       = "peer_failed"
	ReasonAnalysisFailed   = "analysis_failed"
	ReasonPolicyDirectOnly = "relay_denied_by_policy"
	ReasonPeerUnsupported  = "relay_unsupported_peer"
	ReasonBackendNoRelay   = "relay_not_enabled_for_backend"
	ReasonRelayUnavailable = "relay_unavailable"
	ReasonAdmissionClosed  = "backend_closed"
	ReasonInternal         = "internal"
)

// AttemptRecord is the single terminal audit record for one negotiation.
type AttemptRecord struct {
	Backend     string    `json:"backend"`
	VisitorUser string    `json:"visitorUser,omitempty"`
	ProxyUser   string    `json:"proxyUser,omitempty"`
	Outcome     string    `json:"outcome"`
	Reason      string    `json:"reason,omitempty"`
	Relayed     bool      `json:"relayed"`
	StartedAt   time.Time `json:"startedAt"`
	FinishedAt  time.Time `json:"finishedAt"`
	DurationMs  int64     `json:"durationMs"`
}

// AttemptFilter selects audit records.
type AttemptFilter struct {
	Backend string
	Since   time.Time
	Until   time.Time
	Limit   int
}

// RecordStore is a bounded in-memory audit ring. It gives tests and operators
// a deterministic way to retrieve terminal records by backend and time.
type RecordStore struct {
	mu      sync.Mutex
	records []AttemptRecord
	limit   int
	ttl     time.Duration
	now     func() time.Time
}

func NewRecordStore(limit int, ttl time.Duration) *RecordStore {
	if limit <= 0 {
		limit = 1000
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &RecordStore{
		records: make([]AttemptRecord, 0, min(limit, 64)),
		limit:   limit,
		ttl:     ttl,
		now:     time.Now,
	}
}

func (s *RecordStore) Add(r AttemptRecord) AttemptRecord {
	if s == nil {
		return r
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(s.now())
	s.records = append(s.records, r)
	if overflow := len(s.records) - s.limit; overflow > 0 {
		s.records = append(s.records[:0], s.records[overflow:]...)
	}
	return r
}

func (s *RecordStore) Query(f AttemptFilter) []AttemptRecord {
	if s == nil {
		return nil
	}
	limit := f.Limit
	if limit <= 0 || limit > s.limit {
		limit = s.limit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictExpiredLocked(s.now())

	out := make([]AttemptRecord, 0, min(limit, len(s.records)))
	for i := len(s.records) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.records[i]
		if f.Backend != "" && r.Backend != f.Backend {
			continue
		}
		if !f.Since.IsZero() && r.FinishedAt.Before(f.Since) {
			continue
		}
		if !f.Until.IsZero() && r.FinishedAt.After(f.Until) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *RecordStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func (s *RecordStore) evictExpiredLocked(now time.Time) {
	cutoff := now.Add(-s.ttl)
	first := 0
	for first < len(s.records) && s.records[first].FinishedAt.Before(cutoff) {
		first++
	}
	if first > 0 {
		s.records = append(s.records[:0], s.records[first:]...)
	}
}

// AttemptCounters aggregates terminal outcomes. Map keys are created only from
// bounded outcome/reason/relayed combinations.
type AttemptCounters struct {
	mu     sync.Mutex
	counts map[string]int64
}

func NewAttemptCounters() *AttemptCounters {
	return &AttemptCounters{counts: make(map[string]int64)}
}

func (c *AttemptCounters) Inc(outcome, reason string, relayed bool) {
	if c == nil {
		return
	}
	key := outcome + "|" + reason + "|" + boolString(relayed)
	c.mu.Lock()
	c.counts[key]++
	c.mu.Unlock()
}

func (c *AttemptCounters) Snapshot() map[string]int64 {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.counts))
	for k, v := range c.counts {
		out[k] = v
	}
	return out
}

func boolString(v bool) string {
	if v {
		return "relay"
	}
	return "direct"
}

// terminalOnce ensures an attempt has exactly one terminal decision.
type terminalOnce struct {
	once    sync.Once
	done    chan struct{}
	outcome string
	reason  string
	relay   bool
}

func newTerminalOnce() *terminalOnce {
	return &terminalOnce{done: make(chan struct{})}
}

// finish reports whether this caller won the terminal-state race.
func (t *terminalOnce) finish(outcome, reason string, relay bool) bool {
	won := false
	t.once.Do(func() {
		won = true
		t.outcome = outcome
		t.reason = reason
		t.relay = relay
		close(t.done)
	})
	return won
}

func (t *terminalOnce) result() (string, string, bool) {
	<-t.done
	return t.outcome, t.reason, t.relay
}
