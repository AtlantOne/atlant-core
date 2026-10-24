package atlant

import (
	"errors"
	"github.com/quic-go/quic-go"
	"net"
)

// HTTP/3 uses >=1200-byte QUIC Initial packets and can grow its UDP payloads.
// An outer QUIC DATAGRAM adds our destination header and is bounded by PMTU;
// it cannot fragment/retransmit those packets. The existing authenticated 0x12
// stream supports packet framing without a server/wire-format change.
func preferQUICUDPStream(destination string) bool {
	_, port, err := net.SplitHostPort(destination)
	return err == nil && port == "443"
}

// A packet-size error is not evidence that UDP is blocked on this network.
func isQUICDatagramTooLarge(err error) bool {
	var sizeError *quic.DatagramTooLargeError
	return errors.As(err, &sizeError)
}
