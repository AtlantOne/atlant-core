package routepeek

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type recordingPacketConn struct {
	net.Conn
	packets [][]byte
}

func (c *recordingPacketConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.packets = append(c.packets, bytes.Clone(p[:n]))
	}
	return n, err
}

func TestReadQUICRealInitialAndReplay(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, _ := quic.DialAddr(ctx, listener.LocalAddr().String(),
					&tls.Config{ServerName: "www.example.ru", NextProtos: []string{"h3"}},
					&quic.Config{Versions: []quic.Version{version}})
				if conn != nil {
					_ = conn.CloseWithError(0, "test complete")
				}
			}()
			defer func() { cancel(); <-done }()
			recorded := &recordingPacketConn{Conn: listener}
			replay, hello := ReadQUIC(recorded, time.Second)
			if got := ServerName(hello); got != "www.example.ru" {
				t.Fatalf("QUIC SNI missing: %q, packets=%d", got, len(recorded.packets))
			}
			if len(recorded.packets) < 2 {
				t.Fatal("fixture must exercise a multi-datagram post-quantum ClientHello")
			}
			buffer := make([]byte, 65535)
			for i, packet := range recorded.packets {
				n, err := replay.Read(buffer)
				if err != nil || !bytes.Equal(buffer[:n], packet) {
					t.Fatalf("datagram %d changed or lost: %v", i, err)
				}
			}
		})
	}
}

func TestReadQUICUnknownPacketPreserved(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	want := []byte("not QUIC")
	go b.Write(want)
	replay, hello := ReadQUIC(a, time.Second)
	if len(hello) != 0 {
		t.Fatal("unknown packet granted a domain identity")
	}
	buffer := make([]byte, 64)
	n, err := replay.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], want) {
		t.Fatal("non-QUIC UDP payload lost", err)
	}
}

func TestReadQUICTimeoutDoesNotPoisonRelay(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	replay, hello := ReadQUIC(a, time.Millisecond)
	if len(hello) != 0 {
		t.Fatal("timeout produced a name")
	}
	go b.Write([]byte{42})
	_ = replay.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if n, err := replay.Read(buffer); err != nil || n != 1 || buffer[0] != 42 {
		t.Fatal("sniff deadline broke subsequent UDP reads", err)
	}
}
