package quicpeer

import "net"

// NativeClientSocket retains batch I/O and GSO without adding active ECN/MTU
// probes that the previous basic PacketConn path could not send. Non-native
// admission wrappers are intentionally left untouched.
func NativeClientSocket(conn net.PacketConn) net.PacketConn {
	if udp, ok := conn.(*net.UDPConn); ok {
		return &clientUDPSocket{UDPConn: udp}
	}
	return conn
}

type clientUDPSocket struct{ *net.UDPConn }

func (*clientUDPSocket) QUICDisableActiveProbing() bool { return true }

type basicClientSocket struct{ net.PacketConn }

// The maintained stock stack doesn't implement the optional passive policy.
// Keep its old basic-socket behavior on legacy formats instead of silently
// enabling active probes there as a side effect of the wire7 optimization.
func legacyClientSocket(conn net.PacketConn) net.PacketConn {
	if _, ok := conn.(*clientUDPSocket); ok {
		return &basicClientSocket{PacketConn: conn}
	}
	return conn
}
