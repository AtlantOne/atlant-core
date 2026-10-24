//go:build linux

package quic

import (
	"net"
	"testing"
)

type passiveTestSocket struct{ *net.UDPConn }

func (*passiveTestSocket) QUICDisableActiveProbing() bool { return true }

func TestPassiveOptimizedSocketKeepsGSOWithoutActiveProbes(t *testing.T) {
	open := func() *net.UDPConn {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	plain, err := wrapConn(open())
	if err != nil {
		t.Fatal(err)
	}
	passive, err := wrapConn(&passiveTestSocket{open()})
	if err != nil {
		t.Fatal(err)
	}
	caps := passive.capabilities()
	if caps.ECN || caps.DF || caps.GSO != plain.capabilities().GSO {
		t.Fatalf("unexpected passive capabilities: %+v native=%+v", caps, plain.capabilities())
	}
}
