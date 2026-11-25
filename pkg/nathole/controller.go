// Copyright 2023 The frp Authors
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
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/util"
)

// NatHoleTimeout seconds.
var NatHoleTimeout int64 = 10

func NewTransactionID() string {
	id, _ := util.RandID()
	return fmt.Sprintf("%d%s", time.Now().Unix(), id)
}

type ClientCfg struct {
	name       string
	sk         string
	allowUsers []string
	proxyUser  string
	// relayEnabled reports that the backend has a live server-relay listener.
	relayEnabled bool
	// relayCapable reports that the provider frpc understands relay work conns.
	relayCapable bool
	sidCh        chan string
	closedCh     chan struct{}
	closeOnce    sync.Once
}

func (cfg *ClientCfg) close() {
	cfg.closeOnce.Do(func() {
		close(cfg.closedCh)
	})
}

type Policy struct {
	// ModernLifecycle enables terminal-state arbitration, explicit timeout
	// conclusions and audit records.
	ModernLifecycle bool
	// RelayAllowed allows relay terminal decisions.
	RelayAllowed bool
	// ExplicitDirectOnly sends a diagnosable failed decision instead of merely
	// withholding relay when policy is direct-only.
	ExplicitDirectOnly bool
	AddressTimeout     time.Duration
	DataTimeout        time.Duration
	RecordLimit        int
	RecordTTL          time.Duration
}

func DefaultPolicy() Policy {
	return Policy{
		AddressTimeout: 4 * time.Second,
		DataTimeout:    10 * time.Second,
		RecordLimit:    1000,
		RecordTTL:      24 * time.Hour,
	}
}

type Session struct {
	sid            string
	analysisKey    string
	recommandMode  int
	recommandIndex int

	visitorMsg         *msg.NatHoleVisitor
	visitorTransporter transport.MessageTransporter
	vResp              *msg.NatHoleResp
	vNatFeature        *NatFeature
	vBehavior          RecommandBehavior

	clientMsg         *msg.NatHoleClient
	clientTransporter transport.MessageTransporter
	cResp             *msg.NatHoleResp
	cNatFeature       *NatFeature
	cBehavior         RecommandBehavior

	notifyCh chan struct{}

	startedAt time.Time
	// visitorUser is the authenticated control user that created the attempt.
	visitorUser string
	// proxyUser is the authenticated owner of the target backend.
	proxyUser string
	terminal  *terminalOnce
	// dataReadyCh is closed when a capable peer reports end-to-end readiness.
	dataReadyCh   chan struct{}
	dataReadyOnce sync.Once
}

func (s *Session) markDataReady() {
	s.dataReadyOnce.Do(func() {
		close(s.dataReadyCh)
	})
}

func (s *Session) visitorRelayCapable() bool {
	return s.visitorMsg != nil && s.visitorMsg.RelayCapable
}

func (s *Session) clientRelayCapable() bool {
	return s.clientMsg != nil && s.clientMsg.RelayCapable
}

func (s *Session) genAnalysisKey() {
	hash := md5.New()
	vIPs := slices.Compact(parseIPs(s.visitorMsg.MappedAddrs))
	if len(vIPs) > 0 {
		hash.Write([]byte(vIPs[0]))
	}
	hash.Write([]byte(s.vNatFeature.NatType))
	hash.Write([]byte(s.vNatFeature.Behavior))
	hash.Write([]byte(strconv.FormatBool(s.vNatFeature.RegularPortsChange)))

	cIPs := slices.Compact(parseIPs(s.clientMsg.MappedAddrs))
	if len(cIPs) > 0 {
		hash.Write([]byte(cIPs[0]))
	}
	hash.Write([]byte(s.cNatFeature.NatType))
	hash.Write([]byte(s.cNatFeature.Behavior))
	hash.Write([]byte(strconv.FormatBool(s.cNatFeature.RegularPortsChange)))
	s.analysisKey = hex.EncodeToString(hash.Sum(nil))
}

type Controller struct {
	clientCfgs map[string]*ClientCfg
	sessions   map[string]*Session
	analyzer   *Analyzer

	policy   Policy
	records  *RecordStore
	counters *AttemptCounters

	mu sync.RWMutex
}

func NewController(analysisDataReserveDuration time.Duration) (*Controller, error) {
	policy := DefaultPolicy()
	return &Controller{
		clientCfgs: make(map[string]*ClientCfg),
		sessions:   make(map[string]*Session),
		analyzer:   NewAnalyzer(analysisDataReserveDuration),
		policy:     policy,
		records:    NewRecordStore(policy.RecordLimit, policy.RecordTTL),
		counters:   NewAttemptCounters(),
	}, nil
}

// NewControllerWithPolicy creates a controller with explicit fallback policy.
func NewControllerWithPolicy(analysisDataReserveDuration time.Duration, policy Policy) (*Controller, error) {
	if policy.AddressTimeout <= 0 {
		policy.AddressTimeout = DefaultPolicy().AddressTimeout
	}
	if policy.DataTimeout <= 0 {
		policy.DataTimeout = DefaultPolicy().DataTimeout
	}
	if policy.RecordLimit <= 0 {
		policy.RecordLimit = DefaultPolicy().RecordLimit
	}
	if policy.RecordTTL <= 0 {
		policy.RecordTTL = DefaultPolicy().RecordTTL
	}
	c, err := NewController(analysisDataReserveDuration)
	if err != nil {
		return nil, err
	}
	c.policy = policy
	c.records = NewRecordStore(policy.RecordLimit, policy.RecordTTL)
	return c, nil
}

func (c *Controller) Records() *RecordStore { return c.records }

func (c *Controller) Counters() *AttemptCounters { return c.counters }

func (c *Controller) CleanWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			start := time.Now()
			count, total := c.analyzer.Clean()
			log.Tracef("clean %d/%d nathole analysis data, cost %v", count, total, time.Since(start))
		case <-ctx.Done():
			return
		}
	}
}

// ListenClient registers an xtcp backend. Variadic owner preserves the
// historical four-argument call shape while allowing audit records to include
// the backend owner.
func (c *Controller) ListenClient(name string, sk string, allowUsers []string, owner ...string) (chan string, error) {
	proxyUser := ""
	if len(owner) > 0 {
		proxyUser = owner[0]
	}
	return c.ListenClientWithOptions(name, sk, allowUsers, ClientListenOptions{ProxyUser: proxyUser})
}

type ClientListenOptions struct {
	ProxyUser    string
	RelayEnabled bool
	RelayCapable bool
}

func (c *Controller) ListenClientWithOptions(name string, sk string, allowUsers []string, opts ClientListenOptions) (chan string, error) {
	cfg := &ClientCfg{
		name:         name,
		sk:           sk,
		allowUsers:   allowUsers,
		proxyUser:    opts.ProxyUser,
		relayEnabled: opts.RelayEnabled,
		relayCapable: opts.RelayCapable,
		sidCh:        make(chan string),
		closedCh:     make(chan struct{}),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.clientCfgs[name]; ok {
		return nil, fmt.Errorf("proxy [%s] is repeated", name)
	}
	c.clientCfgs[name] = cfg
	return cfg.sidCh, nil
}

func (c *Controller) SetClientRelayEnabled(name string, enabled bool) {
	c.mu.Lock()
	if cfg, ok := c.clientCfgs[name]; ok {
		cfg.relayEnabled = enabled
	}
	c.mu.Unlock()
}

func (c *Controller) CloseClient(name string) {
	c.mu.Lock()
	cfg, ok := c.clientCfgs[name]
	if ok {
		delete(c.clientCfgs, name)
	}
	c.mu.Unlock()
	if ok {
		cfg.close()
	}
}

func (c *Controller) GenSid() string {
	t := time.Now().Unix()
	id, _ := util.RandID()
	return fmt.Sprintf("%d%s", t, id)
}

func (c *Controller) HandleVisitor(m *msg.NatHoleVisitor, transporter transport.MessageTransporter, visitorUser string) {
	if m.PreCheck {
		cfg, reason, safeErr := c.authorizeVisitor(m.ProxyName, visitorUser, false, "", 0)
		if safeErr != nil {
			proxyUser := ""
			if cfg != nil {
				proxyUser = cfg.proxyUser
			}
			c.recordTerminal(m.ProxyName, visitorUser, proxyUser, OutcomeRejected, reason, false)
			_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, safeErr.Error()))
			return
		}
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, ""))
		return
	}

	if !c.policy.ModernLifecycle {
		c.handleVisitorLegacy(m, transporter, visitorUser)
		return
	}
	c.handleVisitorModern(m, transporter, visitorUser)
}

func (c *Controller) authorizeVisitor(proxyName, visitorUser string, verifySign bool, signKey string, timestamp int64) (*ClientCfg, string, error) {
	c.mu.RLock()
	cfg, ok := c.clientCfgs[proxyName]
	c.mu.RUnlock()
	if !ok {
		return nil, ReasonNotFound, errBackendNotFound(proxyName)
	}
	if !allowUser(cfg.allowUsers, visitorUser) {
		// Externally identical to a missing backend to avoid backend/user
		// enumeration. The bounded internal reason and audit record retain the
		// diagnosable cause.
		return cfg, ReasonUnauthorized, errBackendNotFound(proxyName)
	}
	if verifySign && !util.ConstantTimeEqString(signKey, util.GetAuthKey(cfg.sk, timestamp)) {
		return cfg, ReasonAuthFailed, fmt.Errorf("xtcp connection of [%s] auth failed", proxyName)
	}
	return cfg, "", nil
}

func allowUser(allowUsers []string, user string) bool {
	return slices.Contains(allowUsers, user) || slices.Contains(allowUsers, "*")
}

func errBackendNotFound(proxyName string) error {
	return fmt.Errorf("xtcp server for [%s] doesn't exist", proxyName)
}

func (c *Controller) recordTerminal(backend, visitorUser, proxyUser, outcome, reason string, relayed bool) AttemptRecord {
	rec := AttemptRecord{
		Backend:     backend,
		VisitorUser: visitorUser,
		ProxyUser:   proxyUser,
		Outcome:     outcome,
		Reason:      reason,
		Relayed:     relayed,
		StartedAt:   time.Now(),
		FinishedAt:  time.Now(),
	}
	rec.DurationMs = rec.FinishedAt.Sub(rec.StartedAt).Milliseconds()
	c.records.Add(rec)
	c.counters.Inc(outcome, reason, relayed)
	log.Infof("nathole attempt finished: backend=%s proxyUser=%s visitorUser=%s outcome=%s reason=%s relay=%t durationMs=%d",
		backend, proxyUser, visitorUser, outcome, reason, relayed, rec.DurationMs)
	return rec
}

func (c *Controller) finishSession(s *Session, outcome, reason string, relay bool) (*AttemptRecord, bool) {
	if !s.terminal.finish(outcome, reason, relay) {
		return nil, false
	}
	rec := AttemptRecord{
		Backend:     s.visitorMsg.ProxyName,
		VisitorUser: s.visitorUserValue(),
		ProxyUser:   s.proxyUserValue(),
		Outcome:     outcome,
		Reason:      reason,
		Relayed:     relay,
		StartedAt:   s.startedAt,
		FinishedAt:  time.Now(),
	}
	rec.DurationMs = rec.FinishedAt.Sub(s.startedAt).Milliseconds()
	c.records.Add(rec)
	c.counters.Inc(outcome, reason, relay)
	log.Infof("nathole attempt finished: backend=%s proxyUser=%s visitorUser=%s outcome=%s reason=%s relay=%t durationMs=%d",
		rec.Backend, rec.ProxyUser, rec.VisitorUser, outcome, reason, relay, rec.DurationMs)
	return &rec, true
}

func (s *Session) visitorUserValue() string { return s.visitorUser }

func (s *Session) proxyUserValue() string { return s.proxyUser }

func (c *Controller) handleVisitorLegacy(m *msg.NatHoleVisitor, transporter transport.MessageTransporter, visitorUser string) {
	sid := c.GenSid()
	session := &Session{
		sid:                sid,
		visitorMsg:         m,
		visitorTransporter: transporter,
		notifyCh:           make(chan struct{}, 1),
		startedAt:          time.Now(),
	}
	clientCfg, reason, err := c.authorizeVisitor(m.ProxyName, visitorUser, true, m.SignKey, m.Timestamp)
	if err != nil {
		log.Warnf("handle visitorMsg error, reason=%s: %v", reason, err)
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, err.Error()))
		return
	}
	session.proxyUser = clientCfg.proxyUser

	c.mu.Lock()
	c.sessions[sid] = session
	c.mu.Unlock()
	log.Tracef("handle visitor message, sid [%s], server name: %s", sid, m.ProxyName)

	defer c.deleteSession(sid)

	select {
	case clientCfg.sidCh <- sid:
	case <-clientCfg.closedCh:
		return
	}

	select {
	case <-session.notifyCh:
	case <-time.After(time.Duration(NatHoleTimeout) * time.Second):
		log.Debugf("wait for NatHoleClient message timeout, sid [%s]", sid)
		return
	}

	vResp, cResp, err := c.analysis(session)
	if err != nil {
		log.Debugf("sid [%s] analysis error: %v", sid, err)
		vResp = c.GenNatHoleResponse(session.visitorMsg.TransactionID, nil, err.Error())
		cResp = c.GenNatHoleResponse(session.clientMsg.TransactionID, nil, err.Error())
	}
	session.cResp = cResp
	session.vResp = vResp

	var g errgroup.Group
	g.Go(func() error {
		if vResp.DetectBehavior.Role == "sender" {
			time.Sleep(1 * time.Second)
		}
		_ = session.visitorTransporter.Send(vResp)
		return nil
	})
	g.Go(func() error {
		if cResp.DetectBehavior.Role == "sender" {
			time.Sleep(1 * time.Second)
		}
		_ = session.clientTransporter.Send(cResp)
		return nil
	})
	_ = g.Wait()

	time.Sleep(time.Duration(cResp.DetectBehavior.ReadTimeoutMs+30000) * time.Millisecond)
}

func (c *Controller) deleteSession(sid string) {
	c.mu.Lock()
	delete(c.sessions, sid)
	c.mu.Unlock()
}

func (c *Controller) handleVisitorModern(m *msg.NatHoleVisitor, transporter transport.MessageTransporter, visitorUser string) {
	sid := c.GenSid()
	session := &Session{
		sid:                sid,
		visitorMsg:         m,
		visitorTransporter: transporter,
		notifyCh:           make(chan struct{}, 1),
		startedAt:          time.Now(),
		visitorUser:        visitorUser,
		terminal:           newTerminalOnce(),
		dataReadyCh:        make(chan struct{}),
	}

	clientCfg, reason, err := c.authorizeVisitor(m.ProxyName, visitorUser, true, m.SignKey, m.Timestamp)
	if err != nil {
		proxyUser := ""
		if clientCfg != nil {
			proxyUser = clientCfg.proxyUser
		}
		c.recordTerminal(m.ProxyName, visitorUser, proxyUser, OutcomeRejected, reason, false)
		log.Warnf("reject nathole visitor, backend=%s reason=%s: %v", m.ProxyName, reason, err)
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, err.Error()))
		return
	}
	session.proxyUser = clientCfg.proxyUser

	c.mu.Lock()
	c.sessions[sid] = session
	c.mu.Unlock()
	defer c.deleteSession(sid)

	select {
	case clientCfg.sidCh <- sid:
	case <-clientCfg.closedCh:
		c.finishSession(session, OutcomeFailed, ReasonAdmissionClosed, false)
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, session, safeReasonError(ReasonAdmissionClosed)))
		return
	case <-time.After(c.policy.AddressTimeout):
		c.finishSession(session, OutcomeFailed, ReasonPeerTimeout, false)
		resp := c.GenNatHoleResponse(m.TransactionID, session, safeReasonError(ReasonPeerTimeout))
		resp.Outcome = msg.NatHoleOutcomeFailed
		resp.Reason = ReasonPeerTimeout
		resp.AttemptTimeoutMs = int(c.policy.AddressTimeout.Milliseconds())
		_ = transporter.Send(resp)
		return
	}

	addressTimer := time.NewTimer(c.policy.AddressTimeout)
	defer addressTimer.Stop()
	select {
	case <-session.notifyCh:
		if !addressTimer.Stop() {
			select {
			case <-addressTimer.C:
			default:
			}
		}
	case <-addressTimer.C:
		_, won := c.finishSession(session, OutcomeFailed, ReasonPeerTimeout, false)
		if won {
			resp := c.GenNatHoleResponse(m.TransactionID, session, safeReasonError(ReasonPeerTimeout))
			resp.Outcome = msg.NatHoleOutcomeFailed
			resp.Reason = ReasonPeerTimeout
			resp.AttemptTimeoutMs = int(c.policy.AddressTimeout.Milliseconds())
			_ = transporter.Send(resp)
		}
		return
	}

	vResp, cResp, err := c.analysis(session)
	if err != nil {
		log.Debugf("sid [%s] analysis error: %v", sid, err)
		vResp = c.GenNatHoleResponse(session.visitorMsg.TransactionID, nil, err.Error())
		cResp = c.GenNatHoleResponse(session.clientMsg.TransactionID, nil, err.Error())
		_, canRelay := c.relayDecision(session, ReasonAnalysisFailed)
		c.finishAndSendDecision(session, ReasonAnalysisFailed, canRelay)
	}
	session.cResp = cResp
	session.vResp = vResp
	timeoutMs := int(c.policy.AddressTimeout.Milliseconds() + c.policy.DataTimeout.Milliseconds())
	vResp.AttemptTimeoutMs = timeoutMs
	cResp.AttemptTimeoutMs = timeoutMs

	var g errgroup.Group
	g.Go(func() error {
		if vResp.DetectBehavior.Role == "sender" {
			time.Sleep(1 * time.Second)
		}
		_ = session.visitorTransporter.Send(vResp)
		return nil
	})
	g.Go(func() error {
		if cResp.DetectBehavior.Role == "sender" {
			time.Sleep(1 * time.Second)
		}
		_ = session.clientTransporter.Send(cResp)
		return nil
	})
	_ = g.Wait()

	dataTimeout := c.policy.DataTimeout
	if cResp != nil && cResp.DetectBehavior.ReadTimeoutMs > 0 {
		dataTimeout = max(dataTimeout, time.Duration(cResp.DetectBehavior.ReadTimeoutMs+2000)*time.Millisecond)
	}
	dataTimer := time.NewTimer(dataTimeout)
	defer dataTimer.Stop()

	select {
	case <-session.terminal.done:
	case <-session.dataReadyCh:
		c.finishAndSendDirect(session)
	case <-dataTimer.C:
		c.finishAndSendDecision(session, ReasonNoData, false)
	}
}

// relayDecision determines whether a relay is possible and the bounded reason
// for the final outcome. It does not mutate terminal state.
func (c *Controller) relayDecision(s *Session, triggerReason string) (outcomeReason string, relay bool) {
	if !c.policy.RelayAllowed {
		if c.policy.ExplicitDirectOnly {
			return ReasonPolicyDirectOnly, false
		}
		return triggerReason, false
	}
	c.mu.RLock()
	cfg, ok := c.clientCfgs[s.visitorMsg.ProxyName]
	ready := ok && cfg.relayEnabled
	providerCapable := ok && cfg.relayCapable
	c.mu.RUnlock()
	if !s.visitorRelayCapable() || !providerCapable {
		return ReasonPeerUnsupported, false
	}
	if !ready {
		return ReasonBackendNoRelay, false
	}
	return triggerReason, true
}

func (c *Controller) finishAndSendDecision(s *Session, triggerReason string, forceNoRelay bool) {
	reason, relay := c.relayDecision(s, triggerReason)
	if forceNoRelay {
		relay = false
	}
	outcome := OutcomeFailed
	msgOutcome := msg.NatHoleOutcomeFailed
	if relay {
		outcome = OutcomeRelay
		msgOutcome = msg.NatHoleOutcomeRelay
	}
	_, won := c.finishSession(s, outcome, reason, relay)
	if !won {
		return
	}

	decision := &msg.NatHoleDecision{
		Sid:     s.sid,
		Outcome: msgOutcome,
		Reason:  reason,
		Error:   safeReasonError(reason),
	}
	c.sendDecisionOnce(s, decision)
}

func (c *Controller) finishAndSendDirect(s *Session) {
	_, won := c.finishSession(s, OutcomeDirect, "", false)
	if !won {
		return
	}
	decision := &msg.NatHoleDecision{
		Sid:     s.sid,
		Outcome: msg.NatHoleOutcomeDirect,
	}
	c.sendDecisionOnce(s, decision)
}

// sendDecisionOnce sends at most one decision to each capable participant.
// The caller must have won terminal-state arbitration.
func (c *Controller) sendDecisionOnce(s *Session, decision *msg.NatHoleDecision) {
	if s.visitorRelayCapable() && s.visitorTransporter != nil {
		decision.TransactionID = s.visitorMsg.TransactionID
		_ = s.visitorTransporter.Send(decision)
	}
	if s.clientRelayCapable() && s.clientTransporter != nil && s.clientMsg != nil {
		clientDecision := *decision
		clientDecision.TransactionID = s.clientMsg.TransactionID
		_ = s.clientTransporter.Send(&clientDecision)
	}
}

func safeReasonError(reason string) string {
	switch reason {
	case ReasonNotFound:
		return "xtcp backend does not exist"
	case ReasonUnauthorized:
		return "xtcp visitor is not allowed"
	case ReasonAuthFailed:
		return "xtcp authentication failed"
	case ReasonPeerTimeout:
		return "xtcp negotiation timed out waiting for the peer"
	case ReasonNoResponse:
		return "xtcp peer did not respond"
	case ReasonNoData:
		return "xtcp direct tunnel did not become data-ready"
	case ReasonPeerFailed:
		return "xtcp hole punching failed"
	case ReasonAnalysisFailed:
		return "xtcp NAT analysis failed"
	case ReasonPolicyDirectOnly:
		return "xtcp relay fallback is disabled by server policy"
	case ReasonPeerUnsupported:
		return "xtcp peer does not support server relay fallback"
	case ReasonBackendNoRelay:
		return "xtcp backend relay path is not ready"
	case ReasonRelayUnavailable:
		return "xtcp relay path is unavailable"
	case ReasonAdmissionClosed:
		return "xtcp backend is closed"
	default:
		return "xtcp negotiation failed"
	}
}

func (c *Controller) HandleClient(m *msg.NatHoleClient, transporter transport.MessageTransporter) {
	c.mu.RLock()
	session, ok := c.sessions[m.Sid]
	c.mu.RUnlock()
	if !ok {
		return
	}
	log.Tracef("handle client message, sid [%s], server name: %s", session.sid, m.ProxyName)
	session.clientMsg = m
	session.clientTransporter = transporter
	select {
	case session.notifyCh <- struct{}{}:
	default:
	}
}

func (c *Controller) HandleReport(m *msg.NatHoleReport) {
	c.mu.RLock()
	session, ok := c.sessions[m.Sid]
	modern := c.policy.ModernLifecycle
	c.mu.RUnlock()
	if !ok {
		log.Tracef("sid [%s] report make hole success: %v, but session not found", m.Sid, m.Success)
		return
	}
	if m.Success {
		c.analyzer.ReportSuccess(session.analysisKey, session.recommandMode, session.recommandIndex)
	}
	log.Infof("sid [%s] report make hole success: %v dataReady=%v mode %v index %v",
		m.Sid, m.Success, m.DataReady, session.recommandMode, session.recommandIndex)

	if !modern {
		return
	}

	switch {
	case !m.Success:
		// A client-provided Reason is intentionally not propagated: it is
		// untrusted and may contain a wrapped raw network address.
		c.finishAndSendDecision(session, ReasonPeerFailed, false)
	case m.DataReady:
		session.markDataReady()
		c.finishAndSendDirect(session)
	default:
		// Hole punching reported success. Wait for the capable peer's
		// data-ready report or the server-side data timeout.
	}
}

func (c *Controller) GenNatHoleResponse(transactionID string, session *Session, errInfo string) *msg.NatHoleResp {
	var sid string
	if session != nil {
		sid = session.sid
	}
	return &msg.NatHoleResp{
		TransactionID: transactionID,
		Sid:           sid,
		Error:         errInfo,
	}
}

// analysis analyzes the NAT type and behavior of the visitor and client, then makes hole-punching decisions.
// return the response to the visitor and client.
func (c *Controller) analysis(session *Session) (*msg.NatHoleResp, *msg.NatHoleResp, error) {
	cm := session.clientMsg
	vm := session.visitorMsg

	cNatFeature, err := ClassifyNATFeature(cm.MappedAddrs, parseIPs(cm.AssistedAddrs))
	if err != nil {
		return nil, nil, fmt.Errorf("classify client nat feature error: %v", err)
	}

	vNatFeature, err := ClassifyNATFeature(vm.MappedAddrs, parseIPs(vm.AssistedAddrs))
	if err != nil {
		return nil, nil, fmt.Errorf("classify visitor nat feature error: %v", err)
	}
	session.cNatFeature = cNatFeature
	session.vNatFeature = vNatFeature
	session.genAnalysisKey()

	mode, index, cBehavior, vBehavior := c.analyzer.GetRecommandBehaviors(session.analysisKey, cNatFeature, vNatFeature)
	session.recommandMode = mode
	session.recommandIndex = index
	session.cBehavior = cBehavior
	session.vBehavior = vBehavior

	timeoutMs := max(cBehavior.SendDelayMs, vBehavior.SendDelayMs) + 5000
	if cBehavior.ListenRandomPorts > 0 || vBehavior.ListenRandomPorts > 0 {
		timeoutMs += 30000
	}

	protocol := vm.Protocol
	vResp := newNatHoleResponse(
		vm.TransactionID, session.sid, protocol, mode,
		cm.MappedAddrs, cm.AssistedAddrs, vBehavior,
		timeoutMs-vBehavior.SendDelayMs, cNatFeature.PortsDifference,
	)
	cResp := newNatHoleResponse(
		cm.TransactionID, session.sid, protocol, mode,
		vm.MappedAddrs, vm.AssistedAddrs, cBehavior,
		timeoutMs-cBehavior.SendDelayMs, vNatFeature.PortsDifference,
	)

	log.Debugf("sid [%s] visitor nat type: %s/%s, candidateAddrs: %d; client nat type: %s/%s, candidateAddrs: %d, protocol: %s",
		session.sid, vNatFeature.NatType, vNatFeature.Behavior, len(vm.MappedAddrs),
		cNatFeature.NatType, cNatFeature.Behavior, len(cm.MappedAddrs), protocol)
	log.Debugf("sid [%s] visitor detect behavior: %+v", session.sid, vResp.DetectBehavior)
	log.Debugf("sid [%s] client detect behavior: %+v", session.sid, cResp.DetectBehavior)
	return vResp, cResp, nil
}

func newNatHoleResponse(
	transactionID string,
	sid string,
	protocol string,
	mode int,
	candidateAddrs []string,
	assistedAddrs []string,
	behavior RecommandBehavior,
	readTimeoutMs int,
	portsDifference int,
) *msg.NatHoleResp {
	compactCandidateAddrs := slices.Compact(candidateAddrs)
	compactAssistedAddrs := slices.Compact(assistedAddrs)
	return &msg.NatHoleResp{
		TransactionID:  transactionID,
		Sid:            sid,
		Protocol:       protocol,
		CandidateAddrs: compactCandidateAddrs,
		AssistedAddrs:  compactAssistedAddrs,
		DetectBehavior: msg.NatHoleDetectBehavior{
			Mode:              mode,
			Role:              behavior.Role,
			TTL:               behavior.TTL,
			SendDelayMs:       behavior.SendDelayMs,
			ReadTimeoutMs:     readTimeoutMs,
			SendRandomPorts:   behavior.PortsRandomNumber,
			ListenRandomPorts: behavior.ListenRandomPorts,
			CandidatePorts:    getRangePorts(candidateAddrs, portsDifference, behavior.PortsRangeNumber),
		},
	}
}

func getRangePorts(addrs []string, difference, maxNumber int) []msg.PortsRange {
	if maxNumber <= 0 {
		return nil
	}

	addr, isLast := lo.Last(addrs)
	if !isLast {
		return nil
	}
	ports := make([]msg.PortsRange, 0, 1)
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	ports = append(ports, msg.PortsRange{
		From: max(port-difference-5, port-maxNumber, 1),
		To:   min(port+difference+5, port+maxNumber, 65535),
	})
	return ports
}
