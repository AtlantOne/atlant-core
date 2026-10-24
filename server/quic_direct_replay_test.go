package main

import (
	"atlant.local/protocol/quicreality"
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/quicvarint"
)

// Browser wire7 splits its ClientHello over two Initial datagrams. Do not wait
// for a response to the first fragment: that would deadlock a full-Hello gate.
type replayDirectFlight struct {
	net.PacketConn
	attacker net.PacketConn
	t        *testing.T
	flights  [2][][]byte
	seen     [2]bool
}

func (c *replayDirectFlight) WriteTo(p []byte, addr net.Addr) (int, error) {
	_, initial := quicreality.InitialID(p)
	if !initial {
		return c.PacketConn.WriteTo(p, addr)
	}
	offset := 7 + int(p[5])
	length, _, err := quicvarint.Parse(p[offset:])
	if err != nil {
		return 0, err
	}
	stage := 0
	if length != 0 {
		stage = 1
	}
	if c.seen[stage] {
		return c.PacketConn.WriteTo(p, addr)
	}
	c.flights[stage] = append(c.flights[stage], bytes.Clone(p))
	if len(c.flights[stage]) < 2 {
		return len(p), nil
	}
	for _, packet := range c.flights[stage] {
		if _, err := c.attacker.WriteTo(packet, addr); err != nil {
			return 0, err
		}
	}
	_ = c.attacker.SetReadDeadline(time.Now().Add(time.Second))
	var response [4096]byte
	if _, _, err := c.attacker.ReadFrom(response[:]); err != nil {
		return 0, err
	}
	c.t.Logf("wire7 copied flight presented first from competing UDP port: stage=%d", stage)
	for _, packet := range c.flights[stage] {
		if _, err := c.PacketConn.WriteTo(packet, addr); err != nil {
			return 0, err
		}
	}
	c.seen[stage] = true
	c.flights[stage] = nil
	return len(p), nil
}

func TestDirectQUICRealityCopiedFlightsDoNotStealAdmission(t *testing.T) {
	testSecureQUICServer(t, 1, 7, false, true)
}
