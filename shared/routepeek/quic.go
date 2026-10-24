package routepeek

import (
	"atlant.local/protocol/quicreality"
	"errors"
	"net"
	"time"
)

// packetPrefixConn replays complete datagrams, never a concatenated byte stream.
type packetPrefixConn struct {
	net.Conn
	packets [][]byte
}

func (c *packetPrefixConn) Read(p []byte) (int, error) {
	if len(c.packets) == 0 {
		return c.Conn.Read(p)
	}
	packet := c.packets[0]
	c.packets[0] = nil
	c.packets = c.packets[1:]
	return copy(p, packet), nil
}

// ReadQUIC collects only a bounded client Initial flight. QUIC Initial keys are
// public; this extracts visible SNI, not encrypted application data or ECH's
// inner name. Unknown names must keep the caller's protected-route policy.
// The returned connection must replace conn even when no name was recovered.
func ReadQUIC(conn net.Conn, timeout time.Duration) (net.Conn, []byte) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return conn, nil
	}
	defer conn.SetReadDeadline(time.Time{})
	replay := &packetPrefixConn{Conn: conn}
	var observer quicreality.Observer
	buffer := make([]byte, 65535)
	total := 0
	for len(replay.packets) < 8 && total < 24<<10 {
		n, readErr := conn.Read(buffer)
		if n > 0 {
			packet := append([]byte(nil), buffer[:n]...)
			replay.packets = append(replay.packets, packet)
			total += n
			hello, err := observer.Feed(packet)
			if err == nil {
				record := []byte{22, 3, 3, byte(len(hello) >> 8), byte(len(hello))}
				return replay, append(record, hello...)
			}
			if !errors.Is(err, quicreality.ErrIncomplete) {
				break
			}
		}
		if readErr != nil || n == 0 {
			break
		}
	}
	return replay, nil
}
