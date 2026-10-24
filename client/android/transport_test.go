//go:build android || (linux && atlanttest)

package atlant

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type testSocketProtector struct{}

func (testSocketProtector) Protect(int) bool { return true }

func TestDNSUsesSharedCarrierWithoutChangingTrafficPolicy(t *testing.T) {
	cfg := &Config{ServerAddr: "127.0.0.1:1026", User: "alice", PBK: "secret", WireVersion: 4, Transport: "tcp"}
	for _, target := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53"} {
		got := udpTCPConfig(cfg, target)
		if !got.Mux || got.ServerAddr != cfg.ServerAddr || got.PBK != cfg.PBK || got.User != cfg.User || got.WireVersion != cfg.WireVersion {
			t.Fatal("DNS carrier changed authentication or failed to enable stream reuse")
		}
	}
	if cfg.Mux || udpTCPConfig(cfg, "1.1.1.1:443") != cfg {
		t.Fatal("DNS reuse changed the original or non-DNS configuration")
	}
}

func TestRealityFailureIdentifiesServerHelloStage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	protectorMu.RLock()
	previous := protector
	protectorMu.RUnlock()
	SetSocketProtector(testSocketProtector{})
	defer SetSocketProtector(previous)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	peerDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peerDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var header [5]byte
		_, err = io.ReadFull(conn, header[:])
		if err == nil {
			_, err = io.CopyN(io.Discard, conn, int64(header[3])<<8|int64(header[4]))
		}
		peerDone <- err
	}()
	_, err = dialRealityConn(&Config{runCtx: ctx, ServerAddr: listener.Addr().String(), SNI: "example.com", User: "test", PBK: "test"})
	if err == nil || !strings.Contains(err.Error(), "wait for REALITY ServerHello after sending") {
		t.Fatalf("missing handshake stage in error: %v", err)
	}
	if err := <-peerDone; err != nil {
		t.Fatalf("local peer could not receive complete ClientHello: %v", err)
	}
}

type fragmentedConn struct{ net.Conn }

func (c fragmentedConn) Write(p []byte) (int, error) {
	if len(p) > 31 {
		p = p[:31]
	}
	return c.Conn.Write(p)
}

func TestRealityRecordsSurvivePartialWrites(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(3 * time.Second))
	_ = right.SetDeadline(time.Now().Add(3 * time.Second))
	key := bytes.Repeat([]byte{7}, 32)
	iv := bytes.Repeat([]byte{9}, 12)
	sender, err := newRealityConn(fragmentedConn{left}, 0x1303, key, iv, key, iv, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := newRealityConn(right, 0x1303, key, iv, key, iv, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("framed-payload"), 4000)
	done := make(chan error, 1)
	go func() {
		n, err := sender.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		done <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("encrypted records corrupted after partial writes")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A TCP fallback must still use TCP when the original profile selects QUIC.
// The local peer need not complete TLS: receiving ClientHello on TCP proves
// that DNS was not accidentally sent back through the failing QUIC transport.
func TestUDPOverTCPDoesNotReselectQUIC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	protectorMu.RLock()
	previous := protector
	protectorMu.RUnlock()
	SetSocketProtector(testSocketProtector{})
	defer SetSocketProtector(previous)
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	cfg := &Config{
		ServerAddr: listener.Addr().String(),
		SNI:        "example.com",
		PBK:        "local-regression-test",
		Transport:  "quic",
		UDPProto:   "quic",
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		routeUDPViaTCP(client, cfg, "1.1.1.1:53", []byte{0, 1})
	}()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("TCP fallback never reached local TCP listener: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var header [5]byte
	_, err = io.ReadFull(conn, header[:])
	_ = conn.Close()
	if err != nil {
		t.Fatalf("read TLS ClientHello: %v", err)
	}
	if header[0] != 0x16 || header[1] != 0x03 {
		t.Fatalf("expected TLS handshake over TCP, got %x", header)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fallback did not release failed TCP connection")
	}
}

func TestCanceledQUICDialDoesNotOpenSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := getOrDialQUICClient(&Config{runCtx: ctx, ServerAddr: "127.0.0.1:1"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestQUICWaiterCanBeCanceled(t *testing.T) {
	quicClientMu.Lock()
	quicDialInProgress = true
	quicDialWaitChan = make(chan struct{})
	quicClientMu.Unlock()
	defer func() {
		quicClientMu.Lock()
		quicDialInProgress = false
		close(quicDialWaitChan)
		quicClientMu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := getOrDialQUICClient(&Config{runCtx: ctx, ServerAddr: "127.0.0.1:1", SNI: "example.com", PBK: "key", User: "alice"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter did not cancel: %v", err)
	}
}

func TestRecoveryStopsWithVPNContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setUDPBlocked(true)
	defer setUDPBlocked(false)
	startUDPRecoveryProbe(&Config{runCtx: ctx})
	cancel()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recoveryMu.Lock()
		active := recoveryActive
		recoveryMu.Unlock()
		if !active {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("recovery still runs after stopping the VPN")
}

func TestDetachedTUNDoesNotStartReader(t *testing.T) {
	ep := &linkEndpoint{ctx: context.Background()}
	ep.Attach(nil)
	if ep.IsAttached() {
		t.Fatal("detached endpoint is still attached")
	}
	ep.SetMTU(1400)
	if ep.MTU() != 1400 {
		t.Fatalf("configured MTU ignored: %d", ep.MTU())
	}
}

func TestDirectDNSRelaysWithoutVPNTransport(t *testing.T) {
	upstream, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	query := []byte{1, 2, 3, 4}
	response := []byte{5, 6, 7, 8}
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 100)
		n, from, err := upstream.ReadFrom(buf)
		if err == nil && !bytes.Equal(buf[:n], query) {
			err = errors.New("unexpected DNS query")
		}
		if err == nil {
			_, err = upstream.WriteTo(response, from)
		}
		serverErr <- err
	}()
	protectorMu.RLock()
	previous := protector
	protectorMu.RUnlock()
	SetSocketProtector(testSocketProtector{})
	defer SetSocketProtector(previous)
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	_ = peer.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); routeDNSDirect(client, upstream.LocalAddr().String()) }()
	if _, err := peer.Write(query); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("unexpected DNS response: %x", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DNS relay leaked after client closed")
	}
}
