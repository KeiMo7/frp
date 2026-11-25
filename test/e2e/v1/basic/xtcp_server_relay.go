package basic

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/onsi/ginkgo/v2"

	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/pkg/port"
	"github.com/fatedier/frp/test/e2e/pkg/request"
	"github.com/fatedier/frp/test/e2e/pkg/rpc"
)

const (
	stunBindingRequest = 0x0001
	stunBindingSuccess = 0x0101
	stunMagicCookie    = 0x2112A442
	attrXORMapped      = 0x0020
	attrOtherAddress   = 0x802C
)

type loopbackSTUN struct {
	conn       *net.UDPConn
	blackhole1 *net.UDPConn
	blackhole2 *net.UDPConn
	reflect    bool

	mu     sync.Mutex
	visits map[string]int
}

func startLoopbackSTUN() (*loopbackSTUN, error) {
	return newLoopbackSTUN(false)
}

func startReflectiveLoopbackSTUN() (*loopbackSTUN, error) {
	return newLoopbackSTUN(true)
}

func newLoopbackSTUN(reflect bool) (*loopbackSTUN, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	bh1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		conn.Close()
		return nil, err
	}
	bh2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		conn.Close()
		bh1.Close()
		return nil, err
	}
	s := &loopbackSTUN{
		conn:       conn,
		blackhole1: bh1,
		blackhole2: bh2,
		reflect:    reflect,
		visits:     make(map[string]int),
	}
	go s.serve()
	return s, nil
}

func (s *loopbackSTUN) Close() {
	_ = s.conn.Close()
	_ = s.blackhole1.Close()
	_ = s.blackhole2.Close()
}

func (s *loopbackSTUN) Addr() string {
	return s.conn.LocalAddr().String()
}

func (s *loopbackSTUN) serve() {
	buf := make([]byte, 1500)
	for {
		n, source, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		go func(source *net.UDPAddr) {
			s.mu.Lock()
			key := source.String()
			s.visits[key]++
			visit := s.visits[key]
			s.mu.Unlock()

			var attrs []stunTestAttr
			if s.reflect {
				attrs = append(attrs, stunTestAttr{
					typ:   attrXORMapped,
					value: stunIPv4Value(source.IP, source.Port, true),
				})
				if visit == 1 {
					attrs = append(attrs, stunTestAttr{
						typ:   attrOtherAddress,
						value: stunIPv4Value(net.IPv4(127, 0, 0, 1), s.conn.LocalAddr().(*net.UDPAddr).Port, false),
					})
				}
			} else if visit == 1 {
				attrs = append(attrs,
					stunTestAttr{typ: attrXORMapped, value: stunIPv4Value(net.IPv4(127, 0, 0, 1), s.blackhole1.LocalAddr().(*net.UDPAddr).Port, true)},
					stunTestAttr{typ: attrOtherAddress, value: stunIPv4Value(net.IPv4(127, 0, 0, 1), s.conn.LocalAddr().(*net.UDPAddr).Port, false)},
				)
			} else {
				attrs = append(attrs, stunTestAttr{
					typ:   attrXORMapped,
					value: stunIPv4Value(net.IPv4(127, 0, 0, 1), s.blackhole2.LocalAddr().(*net.UDPAddr).Port, true),
				})
			}
			resp, err := buildSTUNResponse(req, attrs...)
			if err == nil {
				_, _ = s.conn.WriteToUDP(resp, source)
			}
		}(source)
	}
}

type stunTestAttr struct {
	typ   uint16
	value []byte
}

func buildSTUNResponse(request []byte, attrs ...stunTestAttr) ([]byte, error) {
	if len(request) < 20 || binary.BigEndian.Uint16(request[0:2]) != stunBindingRequest ||
		binary.BigEndian.Uint32(request[4:8]) != stunMagicCookie {
		return nil, fmt.Errorf("invalid STUN binding request")
	}
	length := 0
	for _, attr := range attrs {
		length += 4 + (len(attr.value)+3)&^3
	}
	resp := make([]byte, 20, 20+length)
	binary.BigEndian.PutUint16(resp[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(resp[2:4], uint16(length))
	binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
	copy(resp[8:20], request[8:20])
	for _, attr := range attrs {
		start := len(resp)
		padded := (len(attr.value) + 3) &^ 3
		resp = append(resp, make([]byte, 4+padded)...)
		binary.BigEndian.PutUint16(resp[start:start+2], attr.typ)
		binary.BigEndian.PutUint16(resp[start+2:start+4], uint16(len(attr.value)))
		copy(resp[start+4:], attr.value)
	}
	return resp, nil
}

func stunIPv4Value(ip net.IP, port int, xor bool) []byte {
	v := make([]byte, 8)
	v[1] = 0x01
	binary.BigEndian.PutUint16(v[2:4], uint16(port))
	copy(v[4:], ip.To4())
	if xor {
		binary.BigEndian.PutUint16(v[2:4], binary.BigEndian.Uint16(v[2:4])^uint16(stunMagicCookie>>16))
		for i := range 4 {
			v[4+i] ^= byte(uint32(stunMagicCookie) >> uint(24-8*i))
		}
	}
	return v
}

var _ = ginkgo.Describe("[Feature: XTCP Server Relay Fallback]", func() {
	f := framework.NewDefaultFramework()

	ginkgo.It("takes over failed hole punching and serves concurrent requesters", func() {
		stun, err := startLoopbackSTUN()
		framework.ExpectNoError(err)
		ginkgo.DeferCleanup(stun.Close)

		visitorPortName := port.GenName("ServerRelayVisitor")
		serverConf := fmt.Sprintf(`%s

[natHole]
relayPolicy = "allow-relay"
addressTimeoutMs = 1000
dataTimeoutMs = 2000
`, consts.DefaultServerConfig)

		proxyConf := fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = {{ .%s }}
loginFailExit = false
log.level = "trace"
natHoleStunServer = "%s"
user = "relay-owner"

[[proxies]]
name = "hole"
type = "xtcp"
secretKey = "relay-secret"
localPort = {{ .%s }}
allowUsers = ["*"]

[proxies.natTraversal]
disableAssistedAddrs = true
`, consts.PortServerName, stun.Addr(), framework.TCPEchoServerPort)

		visitorConf := fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = {{ .%s }}
loginFailExit = false
log.level = "trace"
natHoleStunServer = "%s"
user = "relay-visitor"

[[visitors]]
name = "hole-visitor"
type = "xtcp"
serverUser = "relay-owner"
serverName = "hole"
secretKey = "relay-secret"
bindPort = {{ .%s }}
keepTunnelOpen = false

[visitors.natTraversal]
disableAssistedAddrs = true
`, consts.PortServerName, stun.Addr(), visitorPortName)

		serverProc, clients := f.RunProcesses(serverConf, []string{proxyConf, visitorConf})
		framework.ExpectTrue(len(clients) == 2, "two frpc processes should start")

		framework.NewRequestExpect(f).
			PortName(visitorPortName).
			RequestModify(func(r *request.Request) { r.Timeout(25 * time.Second) }).
			Ensure()

		framework.ExpectNoError(clients[1].WaitForOutput("using server relay fallback for xtcp connection", 1, 10*time.Second))
		framework.ExpectNoError(serverProc.WaitForOutput("xtcp server relay fallback listener ready", 1, 5*time.Second))
		framework.ExpectNoError(serverProc.WaitForOutput("join connections, workConn", 1, 10*time.Second))

		// Concurrent requests each get an independent NewVisitorConn relay leg.
		var wg sync.WaitGroup
		errCh := make(chan error, 8)
		visitorPort := f.PortByName(visitorPortName)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", visitorPort), 20*time.Second)
				if err != nil {
					errCh <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				if _, err := rpc.WriteBytes(conn, []byte(consts.TestString)); err != nil {
					errCh <- err
					return
				}
				resp, err := rpc.ReadBytes(conn)
				if err != nil {
					errCh <- err
					return
				}
				if string(resp) != consts.TestString {
					errCh <- fmt.Errorf("unexpected echo %q", string(resp))
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			framework.ExpectNoError(err)
		}
	})

	ginkgo.It("keeps the direct successful path off the server data plane", func() {
		stun, err := startReflectiveLoopbackSTUN()
		framework.ExpectNoError(err)
		ginkgo.DeferCleanup(stun.Close)

		visitorPortName := port.GenName("DirectXTCP")
		serverConf := `
bindPort = {{ .Port_Server }}
log.level = "trace"

[natHole]
relayPolicy = "allow-relay"
`
		proxyConf := fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = {{ .Port_Server }}
loginFailExit = false
log.level = "trace"
natHoleStunServer = "%s"
user = "direct-owner"

[[proxies]]
name = "hole"
type = "xtcp"
secretKey = "direct-secret"
localPort = {{ .TCPEchoServerPort }}
allowUsers = ["*"]

[proxies.natTraversal]
disableAssistedAddrs = true
`, stun.Addr())

		visitorConf := fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = {{ .Port_Server }}
loginFailExit = false
log.level = "trace"
natHoleStunServer = "%s"
user = "direct-visitor"

[[visitors]]
name = "hole-visitor"
type = "xtcp"
serverUser = "direct-owner"
serverName = "hole"
secretKey = "direct-secret"
bindPort = {{ .%s }}
keepTunnelOpen = true

[visitors.natTraversal]
disableAssistedAddrs = true
`, stun.Addr(), visitorPortName)

		serverProc, clients := f.RunProcesses(serverConf, []string{proxyConf, visitorConf})
		framework.NewRequestExpect(f).
			PortName(visitorPortName).
			RequestModify(func(r *request.Request) { r.Timeout(20 * time.Second) }).
			Ensure()

		framework.ExpectNoError(clients[1].WaitForOutput("establishing nat hole connection successful", 1, 15*time.Second))
		output := clients[1].Output()
		framework.ExpectTrue(!strings.Contains(output, "using server relay fallback"), "direct success must not use relay")
		framework.ExpectTrue(!strings.Contains(serverProc.Output(), "xtcp work connection attached to server relay"), "server must not join direct data plane")
	})

	ginkgo.It("rejects unauthorized visitors indistinguishably from a missing backend", func() {
		visitorPortName := port.GenName("UnauthXTCP")
		proxyConf := `
serverAddr = "127.0.0.1"
serverPort = {{ .Port_Server }}
loginFailExit = false
log.level = "trace"
user = "owner"

[[proxies]]
name = "hole"
type = "xtcp"
secretKey = "relay-secret"
localPort = {{ .TCPEchoServerPort }}
allowUsers = ["allowed-user"]
`
		visitorConf := fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = {{ .Port_Server }}
loginFailExit = false
log.level = "trace"
user = "attacker"

[[visitors]]
name = "hole-visitor"
type = "xtcp"
serverUser = "owner"
serverName = "hole"
secretKey = "relay-secret"
bindPort = {{ .%s }}
`, visitorPortName)

		_, clients := f.RunProcesses(consts.DefaultServerConfig, []string{proxyConf, visitorConf})
		framework.NewRequestExpect(f).
			PortName(visitorPortName).
			ExpectError(true).
			RequestModify(func(r *request.Request) { r.Timeout(4 * time.Second) }).
			Ensure()

		framework.ExpectNoError(clients[1].WaitForOutput("xtcp server for [owner.hole] doesn't exist", 1, 5*time.Second))
		output := clients[1].Output()
		framework.ExpectTrue(!strings.Contains(output, "not allowed"), "client must not observe allow-list distinction")
	})

	ginkgo.It("ends address negotiation at the server deadline and tells the visitor", func() {
		stun, err := startLoopbackSTUN()
		framework.ExpectNoError(err)
		ginkgo.DeferCleanup(stun.Close)

		blackhole, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		framework.ExpectNoError(err)
		ginkgo.DeferCleanup(func() { _ = blackhole.Close() })

		visitorPortName := port.GenName("TimeoutXTCP")
		serverConf := `
bindPort = {{ .Port_Server }}
log.level = "trace"

[natHole]
relayPolicy = "direct-only"
addressTimeoutMs = 250
dataTimeoutMs = 500
`
		proxyConf := fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = {{ .Port_Server }}
loginFailExit = false
log.level = "trace"
natHoleStunServer = "%s"
user = "owner"

[[proxies]]
name = "hole"
type = "xtcp"
secretKey = "relay-secret"
localPort = {{ .TCPEchoServerPort }}
allowUsers = ["*"]
`, blackhole.LocalAddr().String())

		visitorConf := fmt.Sprintf(`
serverAddr = "127.0.0.1"
serverPort = {{ .Port_Server }}
loginFailExit = false
log.level = "trace"
natHoleStunServer = "%s"
user = "visitor"

[[visitors]]
name = "hole-visitor"
type = "xtcp"
serverUser = "owner"
serverName = "hole"
secretKey = "relay-secret"
bindPort = {{ .%s }}
`, stun.Addr(), visitorPortName)

		_, clients := f.RunProcesses(serverConf, []string{proxyConf, visitorConf})
		framework.NewRequestExpect(f).
			PortName(visitorPortName).
			ExpectError(true).
			RequestModify(func(r *request.Request) { r.Timeout(6 * time.Second) }).
			Ensure()

		framework.ExpectNoError(clients[1].WaitForOutput("negotiation timed out waiting for the peer", 1, 5*time.Second))
	})
})
