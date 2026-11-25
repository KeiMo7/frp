// Copyright 2017 fatedier, fatedier@gmail.com
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

package visitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	libio "github.com/fatedier/golib/io"
	fmux "github.com/fatedier/yamux"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/naming"
	"github.com/fatedier/frp/pkg/nathole"
	"github.com/fatedier/frp/pkg/transport"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/fatedier/frp/pkg/util/xlog"
)

var ErrNoTunnelSession = errors.New("no tunnel session")

type XTCPVisitor struct {
	*BaseVisitor
	session       TunnelSession
	startTunnelCh chan struct{}
	retryLimiter  *rate.Limiter
	cancel        context.CancelFunc

	cfg *v1.XTCPVisitorConfig

	fallbackMu       sync.Mutex
	fallbackSignalCh chan struct{}
	fallbackDecision *msg.NatHoleDecision
}

var ErrServerRelayFallback = errors.New("server relay fallback required")

func (sv *XTCPVisitor) Run() (err error) {
	sv.ctx, sv.cancel = context.WithCancel(sv.ctx)
	sv.resetFallbackSignal()

	if sv.cfg.Protocol == "kcp" {
		sv.session = NewKCPTunnelSession()
	} else {
		sv.session = NewQUICTunnelSession(sv.clientCfg)
	}

	if sv.cfg.BindPort > 0 {
		sv.l, err = net.Listen("tcp", net.JoinHostPort(sv.cfg.BindAddr, strconv.Itoa(sv.cfg.BindPort)))
		if err != nil {
			return
		}
		go sv.acceptLoop(sv.l, "xtcp local", sv.handleConn)
	}

	go sv.acceptLoop(sv.internalLn, "xtcp internal", sv.handleConn)
	go sv.processTunnelStartEvents()
	if sv.cfg.KeepTunnelOpen {
		sv.retryLimiter = rate.NewLimiter(rate.Every(time.Hour/time.Duration(sv.cfg.MaxRetriesAnHour)), sv.cfg.MaxRetriesAnHour)
		go sv.keepTunnelOpenWorker()
	}

	if sv.plugin != nil {
		sv.plugin.Start()
	}
	return
}

func (sv *XTCPVisitor) Close() {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.BaseVisitor.Close()
	if sv.cancel != nil {
		sv.cancel()
	}
	if sv.session != nil {
		sv.session.Close()
	}
}

func (sv *XTCPVisitor) processTunnelStartEvents() {
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-sv.startTunnelCh:
			start := time.Now()
			sv.makeNatHole()
			duration := time.Since(start)
			// avoid too frequently
			if duration < 10*time.Second {
				time.Sleep(10*time.Second - duration)
			}
		}
	}
}

func (sv *XTCPVisitor) keepTunnelOpenWorker() {
	xl := xlog.FromContextSafe(sv.ctx)
	ticker := time.NewTicker(time.Duration(sv.cfg.MinRetryInterval) * time.Second)
	defer ticker.Stop()

	sv.startTunnelCh <- struct{}{}
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-ticker.C:
			xl.Debugf("keepTunnelOpenWorker try to check tunnel...")
			conn, err := sv.getTunnelConn(sv.ctx)
			if err != nil {
				xl.Warnf("keepTunnelOpenWorker get tunnel connection error: %v", err)
				_ = sv.retryLimiter.Wait(sv.ctx)
				continue
			}
			xl.Debugf("keepTunnelOpenWorker check success")
			if conn != nil {
				conn.Close()
			}
		}
	}
}

func (sv *XTCPVisitor) resetFallbackSignal() <-chan struct{} {
	sv.fallbackMu.Lock()
	old := sv.fallbackSignalCh
	sv.fallbackDecision = nil
	sv.fallbackSignalCh = make(chan struct{})
	ch := sv.fallbackSignalCh
	sv.fallbackMu.Unlock()

	if old != nil {
		select {
		case <-old:
		default:
			close(old)
		}
	}
	return ch
}

func (sv *XTCPVisitor) fallbackSignal() (<-chan struct{}, *msg.NatHoleDecision) {
	sv.fallbackMu.Lock()
	defer sv.fallbackMu.Unlock()
	return sv.fallbackSignalCh, sv.fallbackDecision
}

func (sv *XTCPVisitor) notifyFallbackDecision(d *msg.NatHoleDecision) {
	if d == nil || (d.Outcome != msg.NatHoleOutcomeRelay && d.Outcome != msg.NatHoleOutcomeFailed) {
		return
	}
	sv.fallbackMu.Lock()
	defer sv.fallbackMu.Unlock()
	if sv.fallbackDecision != nil {
		return
	}
	sv.fallbackDecision = d
	select {
	case <-sv.fallbackSignalCh:
	default:
		close(sv.fallbackSignalCh)
	}
}

func (sv *XTCPVisitor) handleConn(userConn net.Conn) {
	xl := xlog.FromContextSafe(sv.ctx)
	isConnTransferred := false
	var tunnelErr error
	defer func() {
		if !isConnTransferred {
			// If there was an error and connection supports CloseWithError, use it
			if tunnelErr != nil {
				if eConn, ok := userConn.(interface{ CloseWithError(error) error }); ok {
					_ = eConn.CloseWithError(tunnelErr)
					return
				}
			}
			userConn.Close()
		}
	}()

	xl.Debugf("get a new xtcp user connection")

	// Open a tunnel connection to the server. If there is already a successful hole-punching connection,
	// it will be reused. Otherwise, it will block and wait for a successful hole-punching connection until timeout.
	ctx := sv.ctx
	if sv.cfg.FallbackTo != "" {
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(sv.cfg.FallbackTimeoutMs)*time.Millisecond)
		defer cancel()
		ctx = timeoutCtx
	}
	var tunnelConn net.Conn
	var err error
	if sv.cfg.FallbackTo == "" && sv.cfg.ServerRelayFallbackEnabled() {
		tunnelConn, err = sv.openTunnelOrRelay(ctx)
	} else {
		tunnelConn, err = sv.openTunnel(ctx)
	}
	if err != nil {
		if errors.Is(err, ErrServerRelayFallback) {
			tunnelErr = sv.joinServerRelay(userConn)
			if tunnelErr != nil {
				xl.Warnf("server relay fallback error: %v", tunnelErr)
			}
			return
		}
		xl.Errorf("open tunnel error: %v", err)
		tunnelErr = err

		// no static fallback, just return
		if sv.cfg.FallbackTo == "" {
			return
		}

		xl.Debugf("try to transfer connection to visitor: %s", sv.cfg.FallbackTo)
		if err := sv.helper.TransferConn(sv.cfg.FallbackTo, userConn); err != nil {
			xl.Errorf("transfer connection to visitor %s error: %v", sv.cfg.FallbackTo, err)
			return
		}
		isConnTransferred = true
		return
	}

	muxConnRWCloser, recycleFn, err := wrapVisitorConn(tunnelConn, sv.cfg.GetBaseConfig())
	if err != nil {
		xl.Errorf("%v", err)
		tunnelConn.Close()
		tunnelErr = err
		return
	}
	defer recycleFn()

	_, _, errs := libio.Join(userConn, muxConnRWCloser)
	xl.Debugf("join connections closed")
	if len(errs) > 0 {
		xl.Tracef("join connections errors: %v", errs)
	}
}

func (sv *XTCPVisitor) openTunnelOrRelay(ctx context.Context) (net.Conn, error) {
	type tunnelResult struct {
		conn net.Conn
		err  error
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	tunnelCh := make(chan tunnelResult)
	go func() {
		conn, err := sv.openTunnel(ctx)
		res := tunnelResult{conn: conn, err: err}
		select {
		case tunnelCh <- res:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		case <-sv.ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()

	for {
		signalCh, decision := sv.fallbackSignal()
		if decision != nil {
			cancel()
			if decision.Outcome == msg.NatHoleOutcomeFailed {
				if decision.Error != "" {
					return nil, fmt.Errorf("xtcp server relay fallback rejected: %s", decision.Error)
				}
				return nil, errRelayRejected
			}
			return nil, ErrServerRelayFallback
		}
		select {
		case res := <-tunnelCh:
			return res.conn, res.err
		case <-signalCh:
			// The broadcast may be a relay decision or a generation reset.
			// Re-read the current state and retry with the new channel.
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-sv.ctx.Done():
			return nil, sv.ctx.Err()
		}
	}
}

func (sv *XTCPVisitor) joinServerRelay(userConn net.Conn) error {
	xl := xlog.FromContextSafe(sv.ctx)
	baseCfg := sv.cfg.GetBaseConfig()
	rawConn, err := sv.dialRawVisitorConn(baseCfg)
	if err != nil {
		xl.Warnf("dial server relay admission failed: %v", err)
		return errRelayUnavailable
	}

	rwc, recycleFn, err := wrapVisitorConn(rawConn, baseCfg)
	if err != nil {
		rawConn.Close()
		return errRelayUnavailable
	}
	defer recycleFn()

	rw := msg.NewReadWriter(rwc, sv.clientCfg.Transport.WireProtocol)
	if tcpConn, ok := rawConn.(*msg.Conn); ok {
		_ = tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}
	var sidMsg msg.NatHoleSid
	if err := rw.ReadMsgInto(&sidMsg); err != nil {
		_ = rawConn.Close()
		return errRelayUnavailable
	}
	if tcpConn, ok := rawConn.(*msg.Conn); ok {
		_ = tcpConn.SetReadDeadline(time.Time{})
	}
	if sidMsg.Error != "" || !sidMsg.Relay {
		_ = rawConn.Close()
		if sidMsg.Error != "" {
			return fmt.Errorf("%w: %s", errRelayRejected, sidMsg.Error)
		}
		return errRelayUnavailable
	}

	xl.Infof("using server relay fallback for xtcp connection")
	_, _, errs := libio.Join(userConn, rwc)
	if len(errs) > 0 {
		xl.Tracef("server relay join errors: %v", errs)
	}
	return nil
}

var (
	errRelayUnavailable = errors.New("xtcp server relay is unavailable")
	errRelayRejected    = errors.New("xtcp server relay was rejected")
)

// openTunnel will open a tunnel connection to the target server.
func (sv *XTCPVisitor) openTunnel(ctx context.Context) (conn net.Conn, err error) {
	xl := xlog.FromContextSafe(sv.ctx)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-sv.ctx.Done():
			return nil, sv.ctx.Err()
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("open tunnel timeout")
			}
			return nil, ctx.Err()
		case <-timer.C:
			conn, err = sv.getTunnelConn(ctx)
			if err != nil {
				if !errors.Is(err, ErrNoTunnelSession) {
					xl.Warnf("get tunnel connection error: %v", err)
				}
				timer.Reset(500 * time.Millisecond)
				continue
			}
			return conn, nil
		}
	}
}

func (sv *XTCPVisitor) getTunnelConn(ctx context.Context) (net.Conn, error) {
	conn, err := sv.session.OpenConn(ctx)
	if err == nil {
		return conn, nil
	}
	sv.session.Close()

	select {
	case sv.startTunnelCh <- struct{}{}:
	default:
	}
	return nil, err
}

// 0. PreCheck
// 1. Prepare
// 2. ExchangeInfo
// 3. MakeNATHole
// 4. Create a tunnel session using an underlying UDP connection.
func (sv *XTCPVisitor) makeNatHole() {
	xl := xlog.FromContextSafe(sv.ctx)
	targetProxyName := naming.BuildTargetServerProxyName(sv.clientCfg.User, sv.cfg.ServerUser, sv.cfg.ServerName)
	xl.Tracef("makeNatHole start")
	sv.resetFallbackSignal()
	if err := nathole.PreCheck(sv.ctx, sv.helper.MsgTransporter(), targetProxyName, 5*time.Second); err != nil {
		xl.Warnf("nathole precheck error: %v", err)
		return
	}

	xl.Tracef("nathole prepare start")

	// Prepare NAT traversal options
	var opts nathole.PrepareOptions
	if sv.cfg.NatTraversal != nil && sv.cfg.NatTraversal.DisableAssistedAddrs {
		opts.DisableAssistedAddrs = true
	}

	prepareResult, err := nathole.Prepare([]string{sv.clientCfg.NatHoleSTUNServer}, opts)
	if err != nil {
		xl.Warnf("nathole prepare error: %v", err)
		return
	}

	xl.Infof("nathole prepare success, nat type: %s, behavior: %s, addresses: %d, assistedAddresses: %d",
		prepareResult.NatType, prepareResult.Behavior, len(prepareResult.Addrs), len(prepareResult.AssistedAddrs))

	listenConn := prepareResult.ListenConn

	// send NatHoleVisitor to server
	now := time.Now().Unix()
	transactionID := nathole.NewTransactionID()
	natHoleVisitorMsg := &msg.NatHoleVisitor{
		TransactionID: transactionID,
		ProxyName:     targetProxyName,
		Protocol:      sv.cfg.Protocol,
		SignKey:       util.GetAuthKey(sv.cfg.SecretKey, now),
		Timestamp:     now,
		MappedAddrs:   prepareResult.Addrs,
		AssistedAddrs: prepareResult.AssistedAddrs,
		RelayCapable:  sv.cfg.ServerRelayFallbackEnabled(),
	}

	xl.Tracef("nathole exchange info start")
	natHoleRespMsg, err := nathole.ExchangeInfo(sv.ctx, sv.helper.MsgTransporter(), transactionID, natHoleVisitorMsg, 5*time.Second)
	if err != nil {
		listenConn.Close()
		xl.Warnf("nathole exchange info error: %v", err)
		return
	}

	xl.Infof("get natHoleRespMsg, sid [%s], protocol [%s], candidate addresses: %d, assisted addresses: %d",
		natHoleRespMsg.Sid, natHoleRespMsg.Protocol, len(natHoleRespMsg.CandidateAddrs),
		len(natHoleRespMsg.AssistedAddrs))

	sv.listenForDecision(natHoleRespMsg.Sid)

	newListenConn, raddr, err := nathole.MakeHole(sv.ctx, listenConn, natHoleRespMsg, []byte(sv.cfg.SecretKey))
	if err != nil {
		listenConn.Close()
		xl.Warnf("make hole error: %v", err)
		_ = sv.helper.MsgTransporter().Send(&msg.NatHoleReport{
			Sid:     natHoleRespMsg.Sid,
			Success: false,
			Reason:  "make_hole_failed",
		})
		return
	}
	listenConn = newListenConn
	xl.Infof("establishing nat hole connection successful, sid [%s]", natHoleRespMsg.Sid)

	if err := sv.session.Init(listenConn, raddr); err != nil {
		listenConn.Close()
		xl.Warnf("init tunnel session error: %v", err)
		_ = sv.helper.MsgTransporter().Send(&msg.NatHoleReport{
			Sid:     natHoleRespMsg.Sid,
			Success: false,
			Reason:  "session_init_failed",
		})
		return
	}
	_ = sv.helper.MsgTransporter().Send(&msg.NatHoleReport{
		Sid:       natHoleRespMsg.Sid,
		Success:   true,
		DataReady: true,
	})
}

func (sv *XTCPVisitor) listenForDecision(sid string) {
	if !sv.cfg.ServerRelayFallbackEnabled() || sid == "" {
		return
	}
	w := nathole.DefaultDecisionHub.Register(sid)
	go func() {
		timer := time.NewTimer(45 * time.Second)
		defer timer.Stop()
		defer nathole.DefaultDecisionHub.Unregister(sid, w)
		select {
		case d := <-w.C():
			if d == nil {
				return
			}
			if d.Outcome == msg.NatHoleOutcomeRelay {
				sv.notifyFallbackDecision(d)
			}
		case <-timer.C:
		case <-sv.ctx.Done():
		}
	}()
}

type TunnelSession interface {
	Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error
	OpenConn(context.Context) (net.Conn, error)
	Close()
}

type KCPTunnelSession struct {
	session *fmux.Session
	lConn   *net.UDPConn
	mu      sync.RWMutex
}

func NewKCPTunnelSession() TunnelSession {
	return &KCPTunnelSession{}
}

func (ks *KCPTunnelSession) Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error {
	listenConn.Close()
	laddr, _ := net.ResolveUDPAddr("udp", listenConn.LocalAddr().String())
	lConn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return fmt.Errorf("dial udp error: %v", err)
	}
	remote, err := netpkg.NewKCPConnFromUDP(lConn, true, raddr.String())
	if err != nil {
		lConn.Close()
		return fmt.Errorf("create kcp connection from udp connection error: %v", err)
	}

	fmuxCfg := fmux.DefaultConfig()
	fmuxCfg.KeepAliveInterval = 10 * time.Second
	fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024
	fmuxCfg.LogOutput = io.Discard
	session, err := fmux.Client(remote, fmuxCfg)
	if err != nil {
		remote.Close()
		return fmt.Errorf("initial client session error: %v", err)
	}
	ks.mu.Lock()
	ks.session = session
	ks.lConn = lConn
	ks.mu.Unlock()
	return nil
}

func (ks *KCPTunnelSession) OpenConn(_ context.Context) (net.Conn, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	session := ks.session
	if session == nil {
		return nil, ErrNoTunnelSession
	}
	return session.Open()
}

func (ks *KCPTunnelSession) Close() {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if ks.session != nil {
		_ = ks.session.Close()
		ks.session = nil
	}
	if ks.lConn != nil {
		_ = ks.lConn.Close()
		ks.lConn = nil
	}
}

type QUICTunnelSession struct {
	session    *quic.Conn
	listenConn *net.UDPConn
	mu         sync.RWMutex

	clientCfg *v1.ClientCommonConfig
}

func NewQUICTunnelSession(clientCfg *v1.ClientCommonConfig) TunnelSession {
	return &QUICTunnelSession{
		clientCfg: clientCfg,
	}
}

func (qs *QUICTunnelSession) Init(listenConn *net.UDPConn, raddr *net.UDPAddr) error {
	tlsConfig, err := transport.NewClientTLSConfig("", "", "", raddr.String())
	if err != nil {
		return fmt.Errorf("create tls config error: %v", err)
	}
	tlsConfig.NextProtos = []string{"frp"}
	quicConn, err := quic.Dial(context.Background(), listenConn, raddr, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:     time.Duration(qs.clientCfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams: int64(qs.clientCfg.Transport.QUIC.MaxIncomingStreams),
			KeepAlivePeriod:    time.Duration(qs.clientCfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		})
	if err != nil {
		return fmt.Errorf("dial quic error: %v", err)
	}
	qs.mu.Lock()
	qs.session = quicConn
	qs.listenConn = listenConn
	qs.mu.Unlock()
	return nil
}

func (qs *QUICTunnelSession) OpenConn(ctx context.Context) (net.Conn, error) {
	qs.mu.RLock()
	defer qs.mu.RUnlock()
	session := qs.session
	if session == nil {
		return nil, ErrNoTunnelSession
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return netpkg.QuicStreamToNetConn(stream, session), nil
}

func (qs *QUICTunnelSession) Close() {
	qs.mu.Lock()
	defer qs.mu.Unlock()
	if qs.session != nil {
		_ = qs.session.CloseWithError(0, "")
		qs.session = nil
	}
	if qs.listenConn != nil {
		_ = qs.listenConn.Close()
		qs.listenConn = nil
	}
}
