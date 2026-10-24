package main

import "net"

// quic-go intentionally binds Retry tokens to IP only for *net.UDPAddr. The
// generic Addr encoding includes String(), so expose the full observed tuple
// on the wire6 PacketConn boundary. The underlying UDP socket still receives
// its native address on WriteTo. No packet bytes or token format are changed.
type retryPeerAddr struct{ addr net.Addr }

func (a retryPeerAddr) Network() string { return a.addr.Network() }
func (a retryPeerAddr) String() string  { return a.addr.String() }

func retryAddressVersion(addr net.Addr, version int) net.Addr {
	if version == 6 || version == 7 {
		return retryPeerAddr{addr}
	}
	return addr
}

func rawPeerAddress(addr net.Addr) net.Addr {
	if a, ok := addr.(retryPeerAddr); ok {
		return a.addr
	}
	return addr
}

// The QUIC fork borrows this socket for sends only. Reads and Retry token
// addresses continue through DemuxPacketConn; never expose SyscallConn here.
func (d *DemuxPacketConn) QUICSendSocket() *net.UDPConn {
	if d.wireVersion != 7 {
		return nil
	}
	socket, _ := d.rawConn.(*net.UDPConn)
	return socket
}

func (d *DemuxPacketConn) QUICSendAddr(addr net.Addr) net.Addr {
	return rawPeerAddress(addr)
}

func (d *DemuxPacketConn) QUICBeforeSend(packet []byte, peer net.Addr, segment uint16) {
	if segment == 0 {
		d.recordOutgoingQUIC(packet, peer)
		return
	}
	for len(packet) > 0 {
		n := min(len(packet), int(segment))
		d.recordOutgoingQUIC(packet[:n], peer)
		packet = packet[n:]
	}
}
