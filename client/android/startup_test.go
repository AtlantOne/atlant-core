//go:build android || (linux && atlanttest)

package atlant

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestQUICStartupDoesNotDependOnTCP(t *testing.T) {
	for _, mode := range []string{"quic", "udp"} {
		quicCalls, tcpCalls := 0, 0
		err := authenticateTunnelCarrier(&Config{Transport: mode}, false, func(*Config) error {
			quicCalls++
			return nil
		}, func(*Config) (net.Conn, error) {
			tcpCalls++
			return nil, errors.New("TCP is unavailable")
		})
		if err != nil || quicCalls != 1 || tcpCalls != 0 {
			t.Fatalf("%s startup used the wrong carrier: quic=%d tcp=%d err=%v", mode, quicCalls, tcpCalls, err)
		}
	}
}

func TestStartupChecksSelectedCarrierFailure(t *testing.T) {
	failure := errors.New("authentication failed")
	for _, mode := range []string{"quic", "tcp", "xhttp"} {
		err := authenticateTunnelCarrier(&Config{Transport: mode}, false, func(*Config) error {
			return failure
		}, func(*Config) (net.Conn, error) {
			return nil, failure
		})
		if !errors.Is(err, failure) {
			t.Fatalf("%s suppressed authentication failure", mode)
		}
	}
}

func TestQUICStartupUsesTCPOnlyWhenFallbackIsEnabled(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	tcpCalls := 0
	err := authenticateTunnelCarrier(&Config{Transport: "quic"}, true, func(*Config) error {
		return errors.New("QUIC unavailable")
	}, func(*Config) (net.Conn, error) {
		tcpCalls++
		return a, nil
	})
	if err != nil || tcpCalls != 1 {
		t.Fatalf("explicit TCP fallback not honored: calls=%d err=%v", tcpCalls, err)
	}
}

func TestTCPStartupClosesProbeWithoutOpeningQUIC(t *testing.T) {
	for _, mode := range []string{"tcp", "xhttp"} {
		a, b := net.Pipe()
		err := authenticateTunnelCarrier(&Config{Transport: mode}, false, func(*Config) error {
			t.Fatal("TCP startup requested QUIC")
			return nil
		}, func(*Config) (net.Conn, error) { return a, nil })
		if err != nil {
			t.Fatal(err)
		}
		_ = b.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := b.Read(make([]byte, 1)); err == nil {
			t.Fatal("startup probe remains open")
		}
		_ = b.Close()
	}
}

func TestFailedStartupReleasesPrewarmedSocket(t *testing.T) {
	closeQUICClient("test setup")
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	ctx, cancel := context.WithCancel(context.Background())
	quicClientMu.Lock()
	quicClientPacket = packet
	quicClientMu.Unlock()
	mu.Lock()
	isRunning, activeConfig, cancelFunc = true, &Config{runCtx: ctx}, cancel
	mu.Unlock()
	resetFailedVPNStart(cancel)
	if ctx.Err() == nil {
		t.Fatal("failed session was not canceled")
	}
	mu.Lock()
	stale := isRunning || activeConfig != nil || cancelFunc != nil
	mu.Unlock()
	if stale {
		t.Fatal("failed startup kept its running state")
	}
	if _, err := packet.WriteTo([]byte("probe"), packet.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("prewarmed socket survived failed startup: %v", err)
	}
	quicClientMu.Lock()
	defer quicClientMu.Unlock()
	if quicClientPacket != nil || quicClientConn != nil || quicClientTransport != nil {
		t.Fatal("failed carrier remains in the connection pool")
	}
}
