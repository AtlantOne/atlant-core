//go:build android || (linux && atlanttest)

package atlant

import (
	"atlant.local/protocol/quicpeer"
	"atlant.local/protocol/wire"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/quic-go/quic-go"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestQUICUDPStreamKeepsVideoPacketsWithoutTCPFallback(t *testing.T) {
	for _, target := range []string{"video.example:443", "video.example:4443"} {
		t.Run(target, func(t *testing.T) { testVideoUDPStream(t, target) })
	}
}

func testVideoUDPStream(t *testing.T, target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	key := bytes.Repeat([]byte{7}, 32)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	releaseServer := make(chan struct{})
	defer close(releaseServer)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.CloseWithError(0, "test finished")
		user, err := quicpeer.Server(ctx, conn, func(user string) ([]byte, bool) { return key, user == "alice" })
		if err != nil || user != "alice" {
			serverDone <- fmt.Errorf("peer authentication: %v", err)
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		_ = stream.SetDeadline(time.Now().Add(8 * time.Second))
		header, err := wire.ReadQUICHeader(stream)
		if err != nil || header.Protocol != 0x12 || header.Destination != target {
			serverDone <- fmt.Errorf("UDP header: %+v %v", header, err)
			return
		}
		buffer := make([]byte, 2+65535)
		for i := 0; i < 16; i++ {
			if _, err = io.ReadFull(stream, buffer[:2]); err != nil {
				serverDone <- err
				return
			}
			n := int(binary.BigEndian.Uint16(buffer[:2]))
			if _, err = io.ReadFull(stream, buffer[2:2+n]); err != nil {
				serverDone <- err
				return
			}
			if err = wire.WriteFull(stream, buffer[:2+n]); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
		<-releaseServer // keep the pooled QUIC connection alive during relay cancellation
	}()
	protectorMu.RLock()
	previousProtector := protector
	protectorMu.RUnlock()
	SetSocketProtector(testSocketProtector{})
	defer SetSocketProtector(previousProtector)
	previousFallback := IsAutoFallbackEnabled()
	SetAutoFallback(false)
	defer SetAutoFallback(previousFallback)
	setUDPBlocked(false)
	closeQUICClient("test setup")
	defer closeQUICClient("test cleanup")
	packet, app := net.Pipe()
	defer app.Close()
	_ = app.SetDeadline(time.Now().Add(8 * time.Second))
	cfg := &Config{runCtx: ctx, ServerAddr: listener.Addr().String(), SNI: "localhost", PBK: hex.EncodeToString(key), User: "alice", UDPProto: "quic", UDPMode: "quic", PaddingEnabled: true, MinPadding: 32, MaxPadding: 256}
	relayDone := make(chan struct{})
	go func() { defer close(relayDone); handleUDPViaDatagramTunnel(packet, cfg, target) }()
	var total int
	for i := 0; i < 16; i++ {
		size := []int{1200, 1350, 8192, 65507}[i%4]
		if i == 0 && !preferQUICUDPStream(target) {
			size = 8192
		} // first DATAGRAM cannot fit; stay on QUIC
		payload := bytes.Repeat([]byte{byte(i + 1)}, size)
		if err := wire.WriteFull(app, payload); err != nil {
			t.Fatalf("send packet %d: %v", i, err)
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(app, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("video packet %d size %d: %v", i, size, err)
		}
		total += size
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	if isUDPBlocked() {
		t.Fatal("MTU limitation incorrectly marked the UDP network blocked")
	}
	cancel()
	select {
	case <-relayDone:
	case <-time.After(time.Second):
		t.Fatal("QUIC UDP relay did not stop with VPN context")
	}
	quicClientMu.Lock()
	pooled := quicClientConn
	quicClientMu.Unlock()
	if pooled == nil || pooled.Context().Err() != nil {
		t.Fatal("closing a UDP stream must not kill the pooled QUIC connection")
	}
	t.Logf("%d bytes echoed intact over authenticated QUIC, with TCP fallback disabled", total)
}
