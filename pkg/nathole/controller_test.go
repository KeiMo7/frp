package nathole

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

type fakeTransporter struct {
	mu   sync.Mutex
	sent []msg.Message
}

func (f *fakeTransporter) Send(m msg.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeTransporter) Do(_ context.Context, req msg.Message, _, _ string) (msg.Message, error) {
	return req, nil
}

func (f *fakeTransporter) Dispatch(msg.Message, string) bool { return false }

func (f *fakeTransporter) DispatchWithType(msg.Message, string, string) bool {
	return false
}

func (f *fakeTransporter) messages() []msg.Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]msg.Message, len(f.sent))
	copy(out, f.sent)
	return out
}

func newTestModernController(t *testing.T, policy Policy) *Controller {
	t.Helper()
	if policy.AddressTimeout == 0 {
		policy.AddressTimeout = 20 * time.Millisecond
	}
	if policy.DataTimeout == 0 {
		policy.DataTimeout = 20 * time.Millisecond
	}
	policy.ModernLifecycle = true
	c, err := NewControllerWithPolicy(time.Hour, policy)
	require.NoError(t, err)
	return c
}

func TestHandleVisitorPreCheckHidesAllowListExistence(t *testing.T) {
	c := newTestModernController(t, DefaultPolicy())
	_, err := c.ListenClient("user.backend", "secret", []string{"allowed-user"}, "owner")
	require.NoError(t, err)

	missingFT := &fakeTransporter{}
	c.HandleVisitor(&msg.NatHoleVisitor{
		TransactionID: "tx-missing",
		ProxyName:     "user.missing",
		PreCheck:      true,
	}, missingFT, "random-user")

	deniedFT := &fakeTransporter{}
	c.HandleVisitor(&msg.NatHoleVisitor{
		TransactionID: "tx-denied",
		ProxyName:     "user.backend",
		PreCheck:      true,
	}, deniedFT, "not-allowed-user")

	require.Len(t, missingFT.messages(), 1)
	require.Len(t, deniedFT.messages(), 1)
	missingResp := missingFT.messages()[0].(*msg.NatHoleResp)
	deniedResp := deniedFT.messages()[0].(*msg.NatHoleResp)

	require.Equal(t, "xtcp server for [user.missing] doesn't exist", missingResp.Error)
	require.Equal(t, "xtcp server for [user.backend] doesn't exist", deniedResp.Error)
	require.NotContains(t, deniedResp.Error, "not-allowed-user")
	require.NotContains(t, deniedResp.Error, "not allowed")
	require.NotContains(t, deniedResp.Error, "192.0.2.")

	records := c.Records().Query(AttemptFilter{Limit: 10})
	require.Len(t, records, 2)
	require.Equal(t, ReasonNotFound, records[1].Reason)
	require.Equal(t, ReasonUnauthorized, records[0].Reason)
	for _, r := range records {
		require.Equal(t, OutcomeRejected, r.Outcome)
		require.False(t, r.Relayed)
	}
}

func TestTimeoutAndFailureReportRaceRecordsOneDecision(t *testing.T) {
	for i := 0; i < 20; i++ {
		c := newTestModernController(t, Policy{ExplicitDirectOnly: true})
		sidCh, err := c.ListenClient("user.backend", "secret", []string{"*"}, "owner")
		require.NoError(t, err)

		ft := &fakeTransporter{}
		now := time.Now().Unix()
		m := &msg.NatHoleVisitor{
			TransactionID: "tx",
			ProxyName:     "user.backend",
			SignKey:       util.GetAuthKey("secret", now),
			Timestamp:     now,
			RelayCapable:  true,
			MappedAddrs:   []string{"198.51.100.10:40000"},
			AssistedAddrs: []string{"127.0.0.1:40000"},
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			c.HandleVisitor(m, ft, "visitor")
		}()

		var sid string
		select {
		case sid = <-sidCh:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for sid")
		}

		go c.HandleReport(&msg.NatHoleReport{Sid: sid, Success: false, Reason: "raw error with 198.51.100.10:40000"})
		<-done

		records := c.Records().Query(AttemptFilter{Backend: "user.backend", Limit: 10})
		require.Len(t, records, 1, "exactly one terminal record on iteration %d", i)

		var total int64
		for _, n := range c.Counters().Snapshot() {
			total += n
		}
		require.Equal(t, int64(1), total, "counter must increment once on iteration %d", i)

		terminalConclusions := 0
		for _, sent := range ft.messages() {
			switch mm := sent.(type) {
			case *msg.NatHoleDecision:
				if mm.Outcome == msg.NatHoleOutcomeFailed || mm.Outcome == msg.NatHoleOutcomeRelay {
					terminalConclusions++
					require.NotContains(t, mm.Reason, "198.51.100.10")
					require.NotContains(t, mm.Error, "198.51.100.10")
				}
			case *msg.NatHoleResp:
				if mm.Outcome == msg.NatHoleOutcomeFailed {
					terminalConclusions++
				}
			}
		}
		require.Equal(t, 1, terminalConclusions, "exactly one conclusion on iteration %d: %#v", i, ft.messages())
	}
}

func TestSendDecisionSkipsLegacyPeers(t *testing.T) {
	c := newTestModernController(t, DefaultPolicy())
	visitorFT := &fakeTransporter{}
	clientFT := &fakeTransporter{}
	s := &Session{
		sid:                "sid",
		visitorMsg:         &msg.NatHoleVisitor{TransactionID: "v-tx", RelayCapable: false},
		visitorTransporter: visitorFT,
		clientMsg:          &msg.NatHoleClient{TransactionID: "c-tx", RelayCapable: true},
		clientTransporter:  clientFT,
	}

	c.sendDecisionOnce(s, &msg.NatHoleDecision{Sid: "sid", Outcome: msg.NatHoleOutcomeRelay})
	require.Empty(t, visitorFT.messages())
	require.Len(t, clientFT.messages(), 1)
}

func TestConcurrentVisitorsUseIndependentSessions(t *testing.T) {
	c := newTestModernController(t, Policy{RelayAllowed: true})
	sidCh, err := c.ListenClient("user.backend", "secret", []string{"*"}, "owner")
	require.NoError(t, err)

	const n = 16
	var wg sync.WaitGroup
	transporters := make([]*fakeTransporter, n)
	sids := make([]string, n)
	for i := 0; i < n; i++ {
		transporters[i] = &fakeTransporter{}
		now := time.Now().Unix()
		m := &msg.NatHoleVisitor{
			TransactionID: "tx-" + string(rune('a'+i)),
			ProxyName:     "user.backend",
			SignKey:       util.GetAuthKey("secret", now),
			Timestamp:     now,
			RelayCapable:  true,
			MappedAddrs:   []string{"198.51.100.10:" + strconv.Itoa(40000+i)},
		}
		wg.Add(1)
		go func(mm *msg.NatHoleVisitor, ft *fakeTransporter) {
			defer wg.Done()
			c.HandleVisitor(mm, ft, "visitor")
		}(m, transporters[i])
	}

	received := make(map[string]int, n)
	for i := 0; i < n; i++ {
		select {
		case sid := <-sidCh:
			sids[i] = sid
			received[sid]++
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for sid")
		}
	}
	require.Len(t, received, n, "sids must be unique")

	for _, sid := range sids {
		clientFT := &fakeTransporter{}
		c.HandleClient(&msg.NatHoleClient{
			TransactionID: "ctx-" + sid,
			ProxyName:     "user.backend",
			Sid:           sid,
			MappedAddrs:   []string{"198.51.100.20:50000"},
			RelayCapable:  true,
		}, clientFT)
	}

	// Give the short data-timeout lifecycle time to finish all attempts.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Records().Len() >= n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	wg.Wait()

	records := c.Records().Query(AttemptFilter{Backend: "user.backend", Limit: 100})
	require.Len(t, records, n)
	for _, r := range records {
		require.Equal(t, "visitor", r.VisitorUser)
		require.Equal(t, "owner", r.ProxyUser)
	}
}
