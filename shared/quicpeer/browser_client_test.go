package quicpeer

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestDirectClientRejectsUnboundServerCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate(t)}, NextProtos: []string{"h3"}}, ClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	conn, closer, err := DialClient(ctx, &quic.Transport{Conn: packet}, listener.Addr(), &tls.Config{ServerName: "localhost", InsecureSkipVerify: true}, ClientConfig(), 7, DirectCredentials{User: "alice", Key: bytes.Repeat([]byte{9}, 32), ServerPublicKey: serverKey.PublicKey().Bytes()})
	if closer != nil {
		defer closer.Close()
	}
	if conn != nil {
		defer conn.CloseWithError(0, "done")
	}
	if err == nil || !strings.Contains(err.Error(), "direct QUIC REALITY authentication failed") {
		t.Fatalf("unbound self-signed server accepted or failed for unrelated reason: %v", err)
	}
}

func TestBrowserClientRejectsUnsupportedVerificationPolicy(t *testing.T) {
	transport := &quic.Transport{}
	conn, closer, err := DialClient(context.Background(), transport,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443},
		&tls.Config{VerifyConnection: func(tls.ConnectionState) error { return nil }},
		&quic.Config{}, 6)
	if err == nil || conn != nil || closer != transport {
		t.Fatalf("verification policy must fail before network use: conn=%v closer=%T err=%v", conn, closer, err)
	}
}

func TestBrowserClientInteroperatesWithMaintainedServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cert := certificate(t)
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	key := bytes.Repeat([]byte{9}, 32)
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.CloseWithError(0, "test complete")
		_, err = Server(ctx, conn, func(user string) ([]byte, bool) { return key, user == "alice" })
		if err != nil {
			done <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		payload := make([]byte, 32768)
		_, err = io.ReadFull(stream, payload)
		if err == nil {
			_, err = stream.Write(payload)
		}
		if err == nil {
			_, err = conn.ReceiveDatagram(ctx)
		}
		done <- err
	}()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	transport := &quic.Transport{Conn: packet}
	conn, closer, err := DialClient(ctx, transport, listener.Addr(), &tls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: []string{"h3"}}, ClientConfig(), 6)
	defer closer.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test complete")
	if err := AuthenticateClient(ctx, conn, "alice", key); err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0x5a}, 32768)
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
	if err := conn.SendDatagram([]byte("complete")); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
