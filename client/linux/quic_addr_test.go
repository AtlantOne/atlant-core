package main

import (
	"net"
	"testing"
)

func TestQUICStreamAddressesAreSOCKSCompatible(t *testing.T) {
	q := &quicNetStream{localAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}, remoteAddr: &net.UDPAddr{IP: net.ParseIP("::1"), Port: 443}}
	if a, ok := q.LocalAddr().(*net.TCPAddr); !ok || a.Port != 1234 {
		t.Fatalf("SOCKS CONNECT local address incompatible: %T", q.LocalAddr())
	}
	if a, ok := q.RemoteAddr().(*net.TCPAddr); !ok || a.Port != 443 {
		t.Fatalf("remote stream address incompatible: %T", q.RemoteAddr())
	}
}
