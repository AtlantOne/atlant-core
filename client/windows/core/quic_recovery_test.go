package main

import (
	"atlant.local/protocol/quicpeer"
	"context"
	quic "github.com/quic-go/quic-go"
	"net"
	"strings"
	"testing"
)

type recoveryTestConn struct {
	quicpeer.ClientConn
	ctx    context.Context
	closed bool
}

func (c *recoveryTestConn) Context() context.Context { return c.ctx }
func (c *recoveryTestConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	c.closed = true
	return nil
}

type recoveryTestCloser struct{ closed bool }

func (c *recoveryTestCloser) Close() error { c.closed = true; return nil }

type recoveryTestPacket struct {
	net.PacketConn
	closed bool
}

func (c *recoveryTestPacket) Close() error { c.closed = true; return nil }

func TestUDPRecoveryDoesNotCloseSharedHealthyCarrier(t *testing.T) {
	oldConn, oldTransport, oldPacket := quicClientConn, quicClientTransport, quicClientPacket
	oldBlocked := isUDPBlocked()
	t.Cleanup(func() {
		quicClientConn = oldConn
		quicClientTransport = oldTransport
		quicClientPacket = oldPacket
		setUDPBlocked(oldBlocked)
	})
	conn := &recoveryTestConn{ctx: context.Background()}
	transport := &recoveryTestCloser{}
	packet := &recoveryTestPacket{}
	quicClientConn = conn
	quicClientTransport = transport
	quicClientPacket = packet
	setUDPBlocked(true)
	cfg := &Config{ServerAddr: "127.0.0.1:1026", SNI: "example.com", User: "recovery", PBK: strings.Repeat("01", 32)}
	if err := recoverUDPChannel(cfg); err != nil {
		t.Fatal(err)
	}
	if conn.closed || transport.closed || packet.closed {
		t.Fatal("recovery interrupted an active shared carrier")
	}
	if isUDPBlocked() {
		t.Fatal("recovery did not restore UDP routing")
	}
}
