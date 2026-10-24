package main

import (
	"atlant.local/protocol/quicpeer"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestDirectUnauthenticatedBrowserReachesRealQUICDonor(t *testing.T) {
	isolateUsers(t)
	cfg.WireVersion, cfg.LegacyWire = 7, false
	previous := serverStaticECDH
	serverStaticECDH, _ = ecdh.X25519().GenerateKey(rand.Reader)
	defer func() { serverStaticECDH = previous }()
	certPEM, keyPEM := testSubscriptionCertificate(t, "localhost", time.Hour)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	donor, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer donor.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := donor.Accept(ctx)
		if err != nil {
			done <- err
			return
		}
		defer conn.CloseWithError(0, "done")
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		var request [4]byte
		_, err = io.ReadFull(stream, request[:])
		if err == nil && string(request[:]) == "PING" {
			_, err = stream.Write([]byte("PONG"))
			if err == nil {
				err = stream.Close()
			}
		}
		done <- err
		<-ctx.Done()
	}()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	demux, err := NewDemuxPacketConn(raw, nil, donor.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer demux.Close()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	conn, closer, err := quicpeer.DialClient(ctx, &quic.Transport{Conn: packet}, demux.LocalAddr(), &tls.Config{ServerName: "localhost", RootCAs: roots}, quicpeer.ClientConfig(), 6)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	if _, err := stream.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	var response [4]byte
	if _, err := io.ReadFull(stream, response[:]); err != nil || string(response[:]) != "PONG" {
		t.Fatal("donor response", err, string(response[:]))
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-demux.authQueue:
		t.Fatal("unauthenticated browser entered private TLS queue")
	default:
	}
	t.Log("Unauthenticated browser-profile QUIC verified the real donor certificate and exchanged data; no private TLS response")
}
