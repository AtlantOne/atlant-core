package wire

import (
	"net"
	"testing"
)

func TestStreamAddr(t *testing.T) {
	for _, in := range []net.Addr{nil, (*net.UDPAddr)(nil), (*net.TCPAddr)(nil), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}, &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 4321, Zone: "eth0"}, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 99}} {
		out := StreamAddr(in)
		if out == nil || out.Network() != "tcp" {
			t.Fatalf("not a TCP stream address for %v", in)
		}
		switch a := in.(type) {
		case *net.UDPAddr:
			if a != nil && (out.Port != a.Port || out.Zone != a.Zone || !out.IP.Equal(a.IP)) {
				t.Fatal("lost UDP endpoint")
			}
		case *net.TCPAddr:
			if a != nil && (out.Port != a.Port || out.Zone != a.Zone || !out.IP.Equal(a.IP)) {
				t.Fatal("lost TCP endpoint")
			}
		}
	}
}
