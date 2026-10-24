package quic

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

type testFilteredAddr struct{ net.Addr }
type testFilteredSocket struct {
	net.PacketConn
	socket       *net.UDPConn
	reads, sends int
}

func (s *testFilteredSocket) QUICSendSocket() *net.UDPConn { return s.socket }
func (s *testFilteredSocket) QUICSendAddr(a net.Addr) net.Addr {
	if wrapped, ok := a.(testFilteredAddr); ok {
		return wrapped.Addr
	}
	return a
}
func (s *testFilteredSocket) QUICBeforeSend(_ []byte, _ net.Addr, _ uint16) { s.sends++ }
func (s *testFilteredSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	s.reads++
	return copy(p, "admitted"), testFilteredAddr{s.socket.LocalAddr()}, nil
}

func TestFilteredSendKeepsReceiveAndTupleBoundary(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) { testFilteredSend(t, network) })
	}
}

func testFilteredSend(t *testing.T, network string) {
	ip := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		ip = net.IPv6loopback
	}
	socket, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	pc := &testFilteredSocket{PacketConn: socket, socket: socket}
	c, err := wrapConn(pc)
	if err != nil {
		t.Fatal(err)
	}
	if c.capabilities().DF || c.capabilities().ECN {
		t.Fatal("active probe capabilities changed")
	}
	t.Logf("filtered send native GSO=%v; DF/ECN=false", c.capabilities().GSO)
	packet, err := c.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer packet.buffer.Release()
	if pc.reads != 1 || string(packet.data) != "admitted" {
		t.Fatal("receive wrapper bypassed")
	}
	if _, ok := packet.remoteAddr.(testFilteredAddr); !ok {
		t.Fatal("Retry address type lost")
	}

	peer, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	// Some Windows hosts block ::1 UDP in another VPN/firewall. Only skip
	// IPv6 when the unwrapped socket fails the same path first.
	if network == "udp6" {
		_ = peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, sendErr := socket.WriteTo([]byte{1}, peer.LocalAddr())
		var probe [1]byte
		_, _, readErr := peer.ReadFrom(probe[:])
		if sendErr != nil || readErr != nil {
			t.Skipf("native IPv6 UDP baseline unavailable: send=%v read=%v", sendErr, readErr)
		}
	}
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	data := bytes.Repeat([]byte{7}, 2400+23)
	size := uint16(0)
	if c.capabilities().GSO {
		size = 1200
	} else {
		data = data[:23]
	}
	n, err := c.WritePacket(data, testFilteredAddr{peer.LocalAddr()}, nil, size, protocol.ECNUnsupported)
	if err != nil || n != len(data) {
		t.Fatalf("send: n=%d err=%v", n, err)
	}
	if pc.sends != 1 {
		t.Fatal("CID registration callback bypassed")
	}
	var received []byte
	for len(received) < len(data) {
		var buf [4096]byte
		n, _, err := peer.ReadFrom(buf[:])
		if err != nil {
			t.Fatal(err)
		}
		want := len(data)
		if size > 0 {
			want = min(int(size), len(data)-len(received))
		}
		if n != want {
			t.Fatalf("datagram boundaries: got=%d want=%d", n, want)
		}
		received = append(received, buf[:n]...)
	}
	if !bytes.Equal(data, received) {
		t.Fatal("datagram content changed")
	}
	if _, err := c.WritePacket([]byte{1}, testFilteredAddr{&net.TCPAddr{}}, nil, 0, protocol.ECNUnsupported); err == nil {
		t.Fatal("invalid peer accepted")
	}
}
