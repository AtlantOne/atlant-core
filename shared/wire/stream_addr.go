package wire

import "net"

// StreamAddr adapts the UDP endpoint of a QUIC transport to a TCP stream
// address. SOCKS CONNECT implementations can require *net.TCPAddr even when
// the stream is carried over QUIC rather than a kernel TCP connection.
func StreamAddr(address net.Addr) *net.TCPAddr {
	switch a := address.(type) {
	case *net.TCPAddr:
		if a != nil {
			return &net.TCPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
		}
	case *net.UDPAddr:
		if a != nil {
			return &net.TCPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
		}
	}
	return &net.TCPAddr{IP: net.IPv4zero}
}
