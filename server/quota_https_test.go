package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

func TestGlobalQuotaThreeNodesOverVerifiedHTTPS(t *testing.T) {
	s, _ := quotaFixture(t, 13<<20)
	mux := http.NewServeMux()
	mux.HandleFunc("/quota/v1/budget", handleQuotaBudget)
	coordinator := httptest.NewTLSServer(mux)
	defer coordinator.Close()
	client := coordinator.Client() // Only this test CA is trusted; verification stays enabled.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var transferred atomic.Int64
	var calls atomic.Int64
	var wg sync.WaitGroup
	budgets := []*nodeBudget{}
	for _, node := range []string{"eu", "us", "asia"} {
		token := quotaTestNode(t, node, s.ID)
		rpc := remoteQuotaCall(coordinator.URL+"/quota/v1/budget", node, token, client)
		b := &nodeBudget{subscription: s.ID, session: quotaID(), call: func(ctx context.Context, r quotaRequest) (quotaReply, error) { calls.Add(1); return rpc(ctx, r) }}
		budgets = append(budgets, b)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1500; i++ {
				if !b.consume(8192, 8192) {
					break
				}
				transferred.Add(16384)
			}
		}()
	}
	wg.Wait()
	for _, b := range budgets {
		b.mu.Lock()
		err := b.syncLocked(b.grant != "", 0)
		b.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	q, err := readQuota(context.Background(), currentUsersStore.db, s.ID)
	if err != nil || transferred.Load() != 13<<20 || q.Up+q.Down != transferred.Load() || q.Reserved != 0 {
		t.Fatal("distributed HTTPS balance mismatch", q, transferred.Load(), err)
	}
	if calls.Load() >= 100 {
		t.Fatalf("per-packet RPC regression: %d calls for %d bytes", calls.Load(), transferred.Load())
	}
	t.Logf("three TLS-verified nodes: bytes=%d quota_RPCs=%d", transferred.Load(), calls.Load())
}
