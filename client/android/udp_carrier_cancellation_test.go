//go:build linux && atlanttest

package atlant

import (
	"atlant.local/protocol/quicpeer"
	"bytes"
	"context"

	"github.com/quic-go/quic-go"
	"net"
	"testing"
	"time"
)

type cancellationDatagramConn struct {
	quicpeer.ClientConn
	ctx  context.Context
	sent chan int
}

func (c *cancellationDatagramConn) Context() context.Context { return c.ctx }
func (c *cancellationDatagramConn) SendDatagram(b []byte) error {
	c.sent <- len(b)
	if len(b) > 1150 {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1150}
	}
	return nil
}
func cancellationUDPFlow(t *testing.T) (*cancellationDatagramConn, net.Conn, chan struct{}, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	conn := &cancellationDatagramConn{ctx: ctx, sent: make(chan int, 8)}
	quicClientMu.Lock()
	previous := quicClientConn
	quicClientConn = conn
	quicClientMu.Unlock()
	t.Cleanup(func() { quicClientMu.Lock(); quicClientConn = previous; quicClientMu.Unlock(); cancel() })
	packet, app := net.Pipe()
	t.Cleanup(func() { app.Close(); packet.Close() })
	cfg := &Config{runCtx: ctx, ServerAddr: "127.0.0.1:1026", SNI: "example.com", PBK: "audit-key", User: "alice"}
	done := make(chan struct{})
	go func() { defer close(done); handleUDPViaDatagramTunnel(packet, cfg, "203.0.113.1:22023") }()
	app.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := app.Write(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.sent:
	case <-time.After(time.Second):
		t.Fatal("First packet not sent")
	}
	return conn, app, done, cancel
}
func TestQUICDatagramCarrierCancellationStopsFlow(t *testing.T) {
	_, app, done, cancel := cancellationUDPFlow(t)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UDP flow did not stop after carrier cancellation")
	}
	app.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Cleanup stuck")
	}

}
