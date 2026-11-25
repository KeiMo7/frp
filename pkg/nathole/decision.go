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

	"github.com/fatedier/frp/pkg/msg"
)

// DecisionWaiter receives the single server decision for one sid.
type DecisionWaiter struct {
	ch chan *msg.NatHoleDecision
}

func (w *DecisionWaiter) C() <-chan *msg.NatHoleDecision {
	if w == nil {
		return nil
	}
	return w.ch
}

// DecisionHub routes asynchronous NatHoleDecision messages to the local xtcp
// participant that owns the sid. It is process-local and does not persist
// decisions after a waiter is unregistered.
type DecisionHub struct {
	mu      sync.Mutex
	waiters map[string]chan *msg.NatHoleDecision
}

func NewDecisionHub() *DecisionHub {
	return &DecisionHub{waiters: make(map[string]chan *msg.NatHoleDecision)}
}

func (h *DecisionHub) Register(sid string) *DecisionWaiter {
	if sid == "" {
		return &DecisionWaiter{ch: make(chan *msg.NatHoleDecision)}
	}
	ch := make(chan *msg.NatHoleDecision, 1)
	h.mu.Lock()
	// A duplicate registration should never happen for a live sid. If it does,
	// replace the stale waiter so a leaked previous attempt cannot consume the
	// new decision.
	h.waiters[sid] = ch
	h.mu.Unlock()
	return &DecisionWaiter{ch: ch}
}

func (h *DecisionHub) Unregister(sid string, w *DecisionWaiter) {
	if sid == "" || w == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if current, ok := h.waiters[sid]; ok && current == w.ch {
		delete(h.waiters, sid)
	}
}

// Notify delivers a decision without blocking the control dispatcher. A
// decision has no effect if the sid is unknown or its waiter has gone.
func (h *DecisionHub) Notify(d *msg.NatHoleDecision) bool {
	if h == nil || d == nil || d.Sid == "" {
		return false
	}
	h.mu.Lock()
	ch, ok := h.waiters[d.Sid]
	h.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- d:
		return true
	default:
		// Buffered capacity one and terminal decisions are idempotent by sid.
		return true
	}
}

// DefaultDecisionHub is used by client control message dispatch. A process
// normally contains one frpc instance; tests may create isolated hubs.
var DefaultDecisionHub = NewDecisionHub()

func NotifyDecision(d *msg.NatHoleDecision) bool {
	return DefaultDecisionHub.Notify(d)
}
