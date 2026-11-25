package msg

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/proto/wire"
)

func TestNatHoleDecisionRoundTripsInLegacyAndV2(t *testing.T) {
	newMsg := func() *NatHoleDecision {
		return &NatHoleDecision{
			TransactionID: "tx-1",
			Sid:           "sid-1",
			Outcome:       NatHoleOutcomeRelay,
			Reason:        "peer_failed",
			Error:         "xtcp hole punching failed",
		}
	}

	t.Run("legacy", func(t *testing.T) {
		var buf bytes.Buffer
		rw := NewReadWriter(&buf, "")
		require.NoError(t, rw.WriteMsg(newMsg()))
		require.Equal(t, TypeNatHoleDecision, buf.Bytes()[0])

		got, err := rw.ReadMsg()
		require.NoError(t, err)
		require.Equal(t, newMsg(), got)
	})

	t.Run("v2", func(t *testing.T) {
		var buf bytes.Buffer
		rw := NewV2ReadWriter(&buf)
		require.NoError(t, rw.WriteMsg(newMsg()))

		raw := append([]byte(nil), buf.Bytes()...)
		frame, err := wire.NewConn(bytes.NewBuffer(raw)).ReadFrame()
		require.NoError(t, err)
		require.Equal(t, wire.FrameTypeMessage, frame.Type)
		require.Equal(t, V2TypeNatHoleDecision, binary.BigEndian.Uint16(frame.Payload[:2]))

		got, err := NewV2ReadWriter(bytes.NewBuffer(raw)).ReadMsg()
		require.NoError(t, err)
		require.Equal(t, newMsg(), got)
	})
}

func TestRelayCapabilityAndSidFieldsRoundTrip(t *testing.T) {
	visitor := &NatHoleVisitor{TransactionID: "tx", ProxyName: "p", RelayCapable: true}
	client := &NatHoleClient{TransactionID: "tx", Sid: "sid", RelayCapable: true}
	sid := &NatHoleSid{Sid: "sid", Relay: true, Error: "safe"}

	for _, tc := range []struct {
		name  string
		proto string
	}{
		{name: "legacy", proto: ""},
		{name: "v2", proto: "v2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, in := range []Message{visitor, client, sid} {
				var buf bytes.Buffer
				rw := NewReadWriter(&buf, tc.proto)
				require.NoError(t, rw.WriteMsg(in))
				out, err := rw.ReadMsg()
				require.NoError(t, err)
				require.Equal(t, in, out)
			}
		})
	}
}
