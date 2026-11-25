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

package v1

import (
	"strings"
	"time"
)

// NatHoleServerConfig configures server-side xtcp negotiation policy.
//
// The zero value preserves the historical behavior: frps coordinates hole
// punching but never offers or establishes a relay fallback.
type NatHoleServerConfig struct {
	// RelayPolicy controls server-side takeover after a direct attempt fails.
	// Supported values are "", "legacy", "direct-only" and "allow-relay".
	// "direct-only" explicitly rejects relay fallback with a diagnostic code.
	// "allow-relay" lets frps bridge a new visitor connection to the backend.
	RelayPolicy string `json:"relayPolicy,omitempty"`

	// Policy is an alias for RelayPolicy. It is accepted to keep configuration
	// ergonomic but RelayPolicy takes precedence when both are set.
	Policy string `json:"policy,omitempty"`

	// AttemptTimeoutMs bounds address exchange and the wait for data readiness.
	// It is exposed to capable clients so their deadlines can be aligned.
	AttemptTimeoutMs int64 `json:"attemptTimeoutMs,omitempty"`

	// AddressTimeoutMs bounds waiting for the backend's NatHoleClient address
	// advertisement. It defaults to four seconds, safely below the five second
	// client exchange deadline.
	AddressTimeoutMs int64 `json:"addressTimeoutMs,omitempty"`

	// DataTimeoutMs bounds the interval between hole-punch success and a
	// data-ready report from a capable peer.
	DataTimeoutMs int64 `json:"dataTimeoutMs,omitempty"`

	// RecordLimit is the bounded number of in-memory attempt records retained
	// for diagnostics and aggregate counters.
	RecordLimit int `json:"recordLimit,omitempty"`

	// RecordTTLHours controls attempt record retention.
	RecordTTLHours int `json:"recordTTLHours,omitempty"`
}

const (
	NatHoleRelayPolicyLegacy     = "legacy"
	NatHoleRelayPolicyDirectOnly = "direct-only"
	NatHoleRelayPolicyAllowRelay = "allow-relay"
)

func (c NatHoleServerConfig) effectivePolicy() string {
	policy := c.RelayPolicy
	if policy == "" {
		policy = c.Policy
	}
	switch strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(policy)) {
	case "allowrelay", "relay", "relayfallback", "serverrelay", "enabled", "on":
		return NatHoleRelayPolicyAllowRelay
	case "directonly", "direct", "disabled", "off":
		return NatHoleRelayPolicyDirectOnly
	case "legacy", "":
		return NatHoleRelayPolicyLegacy
	default:
		return policy
	}
}

// ModernLifecycle reports whether the server should enforce terminal state,
// explicit timeout conclusions and records. It is false for the zero/legacy
// configuration to preserve old behavior exactly.
func (c NatHoleServerConfig) ModernLifecycle() bool {
	switch c.effectivePolicy() {
	case NatHoleRelayPolicyDirectOnly, NatHoleRelayPolicyAllowRelay:
		return true
	default:
		return false
	}
}

// RelayAllowed reports whether failed direct attempts may fall back to frps.
func (c NatHoleServerConfig) RelayAllowed() bool {
	return c.effectivePolicy() == NatHoleRelayPolicyAllowRelay
}

// ExplicitDirectOnly reports whether relay requests must receive an explicit,
// diagnosable rejection.
func (c NatHoleServerConfig) ExplicitDirectOnly() bool {
	return c.effectivePolicy() == NatHoleRelayPolicyDirectOnly
}

// ResolvedNatHole overlays flat legacy-friendly aliases onto the nested
// NatHole configuration.
func (c *ServerConfig) ResolvedNatHole() NatHoleServerConfig {
	out := c.NatHole
	if out.RelayPolicy == "" && out.Policy == "" && c.NatHoleRelayPolicy != "" {
		out.RelayPolicy = c.NatHoleRelayPolicy
	}
	if out.AttemptTimeoutMs == 0 && c.NatHoleAttemptTimeoutMs > 0 {
		out.AttemptTimeoutMs = c.NatHoleAttemptTimeoutMs
	}
	if out.RecordLimit == 0 && c.NatHoleRecordLimit > 0 {
		out.RecordLimit = c.NatHoleRecordLimit
	}
	if out.RecordTTLHours == 0 && c.NatHoleRecordTTLHours > 0 {
		out.RecordTTLHours = c.NatHoleRecordTTLHours
	}
	return out
}

func (c NatHoleServerConfig) AddressTimeout() time.Duration {
	if c.AddressTimeoutMs > 0 {
		return time.Duration(c.AddressTimeoutMs) * time.Millisecond
	}
	if c.AttemptTimeoutMs > 0 {
		return time.Duration(c.AttemptTimeoutMs) * time.Millisecond
	}
	return 4 * time.Second
}

func (c NatHoleServerConfig) DataTimeout() time.Duration {
	if c.DataTimeoutMs > 0 {
		return time.Duration(c.DataTimeoutMs) * time.Millisecond
	}
	if c.AttemptTimeoutMs > 0 {
		return time.Duration(c.AttemptTimeoutMs) * time.Millisecond
	}
	return 10 * time.Second
}

func (c NatHoleServerConfig) RecordTTL() time.Duration {
	if c.RecordTTLHours > 0 {
		return time.Duration(c.RecordTTLHours) * time.Hour
	}
	return 24 * time.Hour
}
