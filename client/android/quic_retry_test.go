//go:build android || (linux && atlanttest)

package atlant

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type countingDeniedProtector struct{ calls atomic.Int32 }

func (p *countingDeniedProtector) Protect(int) bool { p.calls.Add(1); return false }

func TestConcurrentQUICProtectionFailureIsShared(t *testing.T) {
	protectorMu.RLock()
	previous := protector
	protectorMu.RUnlock()
	closeQUICClient("retry test setup")
	denied := &countingDeniedProtector{}
	SetSocketProtector(denied)
	t.Cleanup(func() { closeQUICClient("retry test cleanup"); SetSocketProtector(previous) })
	cfg := &Config{ServerAddr: "127.0.0.1:44330", SNI: "example.org", PBK: strings.Repeat("01", 32), User: "alice", WireVersion: 7, ServerPubKey: strings.Repeat("02", 32)}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := getOrDialQUICClient(cfg); err == nil {
				t.Error("unprotected UDP socket accepted")
			}
		})
	}
	wg.Wait()
	if got := denied.calls.Load(); got != 1 {
		t.Fatalf("queued flows repeated the same carrier failure %d times", got)
	}
}
