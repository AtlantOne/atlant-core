//go:build linux && atlanttest

package atlant

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClosingMuxCancelsHandshakeWithoutWaitingForMutex(t *testing.T) {
	protectorMu.RLock()
	oldProtector := protector
	protectorMu.RUnlock()
	SetSocketProtector(testSocketProtector{})
	defer SetSocketProtector(oldProtector)
	closeRealitySession()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := &Config{runCtx: ctx, ServerAddr: listener.Addr().String(), SNI: "example.com", User: "alice", PBK: strings.Repeat("01", 32), ServerPubKey: strings.Repeat("02", 32), WireVersion: 7, Fingerprint: "firefox"}
	done := make(chan error, 1)
	go func() { _, err := getYamuxSession(cfg); done <- err }()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(time.Second):
		t.Fatal("handshake did not start")
	}
	closed := make(chan struct{})
	go func() { closeRealitySession(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(200 * time.Millisecond):
		t.Error("close blocked behind handshake mutex")
		cancel()
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("cancelled handshake published a session")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake did not cancel")
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	if session != nil || sessionDialDone != nil {
		t.Error("stale mux state survived close")
	}
}
