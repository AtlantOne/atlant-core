package quicpeer

import (
	"net"
	"testing"

	quic "github.com/quic-go/quic-go"
	browser "github.com/refraction-networking/uquic"
)

type opaqueSocket struct{ net.PacketConn }

func TestNativeClientSocketRetainsOOBAndPolicy(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	optimized := NativeClientSocket(conn)
	if _, ok := optimized.(browser.OOBCapablePacketConn); !ok {
		t.Fatal("browser QUIC OOB hidden")
	}
	if _, ok := optimized.(quic.OOBCapablePacketConn); !ok {
		t.Fatal("maintained QUIC OOB hidden")
	}
	if policy, ok := optimized.(interface{ QUICDisableActiveProbing() bool }); !ok || !policy.QUICDisableActiveProbing() {
		t.Fatal("native socket added active probes")
	}
	opaque := &opaqueSocket{conn}
	if NativeClientSocket(opaque) != opaque {
		t.Fatal("admission wrapper removed")
	}
	if legacyClientSocket(opaque) != opaque {
		t.Fatal("legacy admission wrapper changed")
	}
	if _, ok := legacyClientSocket(optimized).(quic.OOBCapablePacketConn); ok {
		t.Fatal("legacy stock transport acquired active probing capabilities")
	}
}
