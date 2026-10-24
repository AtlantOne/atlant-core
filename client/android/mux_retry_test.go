//go:build android || (linux && atlanttest)

package atlant

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"atlant.local/protocol/wire"
)

func TestConcurrentDNSCarrierFailureDoesNotQueueHandshakes(t *testing.T) {
	protectorMu.RLock()
	previousProtector := protector
	protectorMu.RUnlock()
	SetSocketProtector(testSocketProtector{})
	t.Cleanup(func() { SetSocketProtector(previousProtector) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var attempts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			attempts.Add(1)
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 4096)
			_, _ = c.Read(buf)
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	sessMu.Lock()
	old, dead, connected, cooldown := session, sessionDead, lastConnectTime, sessionDialCooldown
	session, sessionDead = nil, true
	sessionDialCooldown = wire.DialCooldown{}
	sessMu.Unlock()
	t.Cleanup(func() {
		sessMu.Lock()
		session, sessionDead, lastConnectTime, sessionDialCooldown = old, dead, connected, cooldown
		sessMu.Unlock()
	})
	cfg := &Config{ServerAddr: listener.Addr().String(), SNI: "example.org", User: "alice", PBK: strings.Repeat("01", 32), ServerPubKey: strings.Repeat("02", 32), WireVersion: 4, Fingerprint: "chrome"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := getYamuxSession(cfg); err == nil {
				t.Error("broken handshake succeeded")
			}
		}()
	}
	wg.Wait()
	if attempts.Load() != 1 {
		t.Fatalf("failed carrier was retried %d times for simultaneous DNS flows", attempts.Load())
	}
}
