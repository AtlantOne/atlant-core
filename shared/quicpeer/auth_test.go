package quicpeer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"github.com/quic-go/quic-go"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func certificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestAuthenticatedQUICCarriesStreamsAndDatagrams(t *testing.T) {
	t.Run("v1", func(t *testing.T) { testAuthenticatedQUIC(t, quic.Version1) })
	t.Run("v2", func(t *testing.T) { testAuthenticatedQUIC(t, quic.Version2) })
}

func testAuthenticatedQUIC(t *testing.T, version quic.Version) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate(t)}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true, Versions: []quic.Version{version}})
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
		defer conn.CloseWithError(0, "server test finished")
		user, err := Server(ctx, conn, func(user string) ([]byte, bool) { return key, user == "alice" })
		if err != nil {
			done <- err
			return
		}
		if user != "alice" {
			done <- io.ErrUnexpectedEOF
			return
		}
		if err = conn.SendDatagram([]byte("ready")); err != nil {
			done <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
		payload := make([]byte, 7)
		if _, err = io.ReadFull(stream, payload); err == nil {
			_, err = stream.Write(payload)
		}
		if err == nil {
			_, err = io.ReadFull(stream, make([]byte, 1))
		}
		done <- err
	}()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	transport := &quic.Transport{Conn: packet, ConnectionIDGenerator: NewCIDGenerator("alice", key)}
	defer transport.Close()
	conn, err := transport.Dial(ctx, listener.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true, Versions: []quic.Version{version}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test finished")
	if err = Client(ctx, conn, "alice", key); err != nil {
		t.Fatal(err)
	}
	dgram, err := conn.ReceiveDatagram(ctx)
	if err != nil || string(dgram) != "ready" {
		t.Fatalf("datagram=%q error=%v", dgram, err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 7)
	if _, err = io.ReadFull(stream, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "payload" {
		t.Fatal("corrupt authenticated payload")
	}
	if _, err = stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
