package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestUnauthenticatedFragmentedProbeBytes(t *testing.T) {
	if os.Getenv("ATLANT_TEST_UDP_TARGET") != "192.0.2.1" {
		t.Skip("isolated namespace required")
	}
	isolateUsers(t)
	cfg.SNI = "192.0.2.1"
	hello := parserHello([]byte{0x13, 1}, nil)[5:]
	for _, input := range [][]byte{
		{0x16, 3},
		helloRecord(hello)[:9],
		append(helloRecord(hello[:4]), 0x16, 3),
		append(helloRecord(hello[:4]), helloRecord(hello[4:])[:8]...),
		append(helloRecord(hello[:4]), []byte{0x17, 3, 3, 0, 1, 7}...),
		append(helloRecord(hello[:2]), helloRecord(hello[2:])...),
	} {
		donor, err := net.Listen("tcp", "192.0.2.1:443")
		if err != nil {
			t.Fatal(err)
		}
		received := make(chan []byte, 1)
		go func() {
			conn, err := donor.Accept()
			if err != nil {
				received <- nil
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			data, _ := io.ReadAll(conn)
			received <- data
		}()
		vpn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			donor.Close()
			t.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := vpn.Accept()
			if err == nil {
				handleFork(conn)
			}
		}()
		conn, err := net.DialTimeout("tcp", vpn.Addr().String(), time.Second)
		if err != nil {
			vpn.Close()
			donor.Close()
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		if err := writeFull(conn, input); err != nil {
			conn.Close()
			vpn.Close()
			donor.Close()
			t.Fatal(err)
		}
		_ = conn.(*net.TCPConn).CloseWrite()
		select {
		case got := <-received:
			if !bytes.Equal(got, input) {
				t.Errorf("donor bytes changed: got=%x want=%x", got, input)
			}
		case <-time.After(4 * time.Second):
			t.Error("donor did not receive probe")
		}
		conn.Close()
		vpn.Close()
		donor.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("probe handler leaked")
		}
	}
}

// Only the isolated namespace runner owns 192.0.2.1 and its port 443.
// Never change SSRF guards or host routing to get a green probe test.
func TestUnauthenticatedProbesReachGenuineLocalDonor(t *testing.T) {
	if os.Getenv("ATLANT_TEST_UDP_TARGET") != "192.0.2.1" {
		t.Skip("isolated namespace required")
	}
	isolateUsers(t)
	cfg.SNI = "192.0.2.1"
	cfg.WireVersion = 3
	cfg.LegacyWire = false
	gate, _ := newAdmissionGate()
	previous := activeAdmission.Swap(gate)
	defer activeAdmission.Store(previous)
	certPEM, keyPEM := testSubscriptionCertificate(t, cfg.SNI, time.Hour)
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h3", "h2", "http/1.1"}}
	clientTLS := &tls.Config{RootCAs: roots, ServerName: cfg.SNI, NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS13}
	t.Run("TCP-TLS", func(t *testing.T) {
		donor, err := tls.Listen("tcp", "192.0.2.1:443", serverTLS)
		if err != nil {
			t.Fatal(err)
		}
		defer donor.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, err := donor.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(c, "donor")
		}()
		vpn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer vpn.Close()
		go func() {
			c, err := vpn.Accept()
			if err == nil {
				handleFork(c)
			}
		}()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", vpn.Addr().String(), clientTLS)
		if err != nil {
			t.Fatal("unauthenticated TLS probe did not get verified donor handshake", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		var reply [5]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "donor" {
			t.Fatal("probe got VPN data or unexpected donor response", err)
		}
		if conn.ConnectionState().NegotiatedProtocol != "h2" {
			t.Fatal("donor ALPN changed")
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("donor handler leaked")
		}
	})
	t.Run("QUIC", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		donor, err := quic.ListenAddr("192.0.2.1:443", serverTLS, &quic.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer donor.Close()
		go func() {
			c, err := donor.Accept(ctx)
			if err != nil {
				return
			}
			s, err := c.AcceptStream(ctx)
			if err != nil {
				return
			}
			var marker [1]byte
			if _, err := io.ReadFull(s, marker[:]); err == nil {
				_, _ = io.WriteString(s, "donor")
				_ = s.Close()
			}
		}()
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		demux, err := NewDemuxPacketConn(socket, nil, "192.0.2.1:443")
		if err != nil {
			socket.Close()
			t.Fatal(err)
		}
		defer demux.Close()
		outerTLS := clientTLS.Clone()
		outerTLS.NextProtos = []string{"h3"}
		conn, err := quic.DialAddr(ctx, demux.LocalAddr().String(), outerTLS, &quic.Config{})
		if err != nil {
			t.Fatal("unauthenticated QUIC probe did not get verified donor handshake", err)
		}
		defer conn.CloseWithError(0, "finished")
		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := stream.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		var reply [5]byte
		if _, err := io.ReadFull(stream, reply[:]); err != nil || string(reply[:]) != "donor" {
			t.Fatal("unexpected probe response", err)
		}
		if n, _ := gate.store.Counts(); n != 0 || len(gate.pending) != 0 {
			t.Fatal("probe created admission state")
		}
	})
}
