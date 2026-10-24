package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quotaFixture(t *testing.T, total int64) (SubscriptionRecord, string) {
	t.Helper()
	s, link := subscriptionFixture(t)
	cfg.Quota = QuotaConfig{Coordinator: true}
	quotaState.Lock()
	old := quotaState.worker
	quotaState.worker = nil
	quotaState.Unlock()
	t.Cleanup(func() { quotaState.Lock(); quotaState.worker = old; quotaState.Unlock() })
	limit := uint64(total)
	s.TotalLimit = &limit
	body, _ := json.Marshal(s)
	w := httptest.NewRecorder()
	handleAPISubscriptions(w, httptest.NewRequest("PUT", "/api/subscriptions", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("configure quota: %d %s", w.Code, w.Body.String())
	}
	// The migration preserves 12+34 existing bytes. Accounting tests start with
	// a fresh fixture balance; a separate test verifies migration preservation.
	if _, err := currentUsersStore.db.Exec(`UPDATE quota_accounts SET up=0,down=0 WHERE subscription_id=?`, s.ID); err != nil {
		t.Fatal(err)
	}
	return s, link
}

func quotaTestNode(t *testing.T, name, sub string) string {
	t.Helper()
	token := strings.Repeat("a", 64)
	h := sha256.Sum256([]byte(token))
	if _, err := currentUsersStore.db.Exec(`INSERT INTO quota_nodes VALUES(?,?,1)`, name, hex.EncodeToString(h[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := currentUsersStore.db.Exec(`INSERT INTO quota_node_subscriptions VALUES(?,?)`, name, sub); err != nil {
		t.Fatal(err)
	}
	return token
}

func testBudget(sub, node string) *nodeBudget {
	db := currentUsersStore.db
	return &nodeBudget{subscription: sub, session: quotaID(), call: func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		return processQuota(ctx, db, node, r, time.Now())
	}}
}

func TestGlobalQuotaThreeNodesConcurrentExactLimit(t *testing.T) {
	s, _ := quotaFixture(t, 13<<20)
	budgets := []*nodeBudget{}
	for _, name := range []string{"node1", "node2", "node3"} {
		quotaTestNode(t, name, s.ID)
		budgets = append(budgets, testBudget(s.ID, name))
	}
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for _, b := range budgets {
		wg.Add(1)
		go func(b *nodeBudget) {
			defer wg.Done()
			for i := 0; i < 1500; i++ {
				if b.consume(8192, 8192) {
					accepted.Add(16384)
				}
			}
		}(b)
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
	if err != nil || q.Up+q.Down != accepted.Load() || accepted.Load() != 13<<20 || q.Reserved != 0 {
		t.Fatalf("overshoot/lost accounting: %+v accepted=%d err=%v", q, accepted.Load(), err)
	}
}

func TestGlobalQuotaLostResponseRetryAndConflictingID(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	b := testBudget(s.ID, "local")
	original := b.call
	lost := true
	b.call = func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		reply, err := original(ctx, r)
		if err == nil && lost {
			lost = false
			return quotaReply{}, io.ErrUnexpectedEOF
		}
		return reply, err
	}
	if b.consume(7, 0) {
		t.Fatal("lost coordinator response authorized bytes")
	}
	if !b.consume(7, 0) {
		t.Fatal("idempotent retry failed")
	}
	var count int
	currentUsersStore.db.QueryRow(`SELECT count(*) FROM quota_grants`).Scan(&count)
	if count != 1 {
		t.Fatal("retry allocated twice")
	}
	r := quotaRequest{ID: quotaID(), Session: quotaID(), Subscription: s.ID, Want: 1, IssuedAt: time.Now().Unix()}
	if _, err := original(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	r.Want = 2
	if _, err := original(context.Background(), r); err == nil {
		t.Fatal("same request ID with changed body accepted")
	}
}

func TestGlobalQuotaCoordinatorRestartAndNodeRestartCannotReuseCredit(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	old := testBudget(s.ID, "local")
	if !old.consume(70, 0) {
		t.Fatal("initial credit missing")
	}
	path := cfg.UsersFile
	closeUsersStore()
	if err := loadUsers(path); err != nil {
		t.Fatal(err)
	}
	// Coordinator restart preserves the reservation, including unreported use.
	fresh := testBudget(s.ID, "local")
	if fresh.consume(1, 0) {
		t.Fatal("new node process reused the old process's reservation")
	}
	old.call = func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		return processQuota(ctx, currentUsersStore.db, "local", r, time.Now())
	}
	old.mu.Lock()
	err := old.syncLocked(true, 0)
	old.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fresh.retryAfter = time.Time{}
	if !fresh.consume(30, 0) || fresh.consume(1, 0) {
		t.Fatal("settled balance not enforced")
	}
}

func TestGlobalQuotaExpiredDisabledAndClock(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	b := testBudget(s.ID, "local")
	if !b.consume(1, 0) {
		t.Fatal("initial failure")
	}
	currentUsersStore.db.Exec(`UPDATE subscriptions SET enabled=0 WHERE id=?`, s.ID)
	b.mu.Lock()
	err := b.syncLocked(false, 0)
	b.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if b.consume(1, 0) || b.valid() {
		t.Fatal("disabled subscription survived refresh")
	}
	r := quotaRequest{ID: quotaID(), Session: quotaID(), Subscription: s.ID, Want: 10, IssuedAt: time.Now().Add(-time.Hour).Unix()}
	if _, err := processQuota(context.Background(), currentUsersStore.db, "local", r, time.Now()); !errors.Is(err, errQuotaClock) {
		t.Fatal("stale allocation request accepted")
	}
	currentUsersStore.db.Exec(`UPDATE subscriptions SET enabled=1,expires_at=? WHERE id=?`, time.Now().Unix()-1, s.ID)
	r.ID = quotaID()
	r.IssuedAt = time.Now().Unix()
	reply, err := processQuota(context.Background(), currentUsersStore.db, "local", r, time.Now())
	if err != nil || reply.Allowed {
		t.Fatal("expired subscription accepted")
	}
}

func TestGlobalQuotaOfflineAuthorizationExpires(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	b := testBudget(s.ID, "local")
	if !b.consume(1, 0) {
		t.Fatal("initial failure")
	}
	b.call = func(context.Context, quotaRequest) (quotaReply, error) { return quotaReply{}, io.ErrUnexpectedEOF }
	b.deadline = time.Now().Add(-time.Millisecond)
	b.authorization.Store(&quotaAuthorization{allowed: true, deadline: b.deadline})
	if b.consume(1, 0) || b.valid() {
		t.Fatal("offline node extended expired authorization")
	}
}

func TestGlobalQuotaRPCScopesTLSAndNodeCredentials(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	token := quotaTestNode(t, "remote", s.ID)
	mux := http.NewServeMux()
	mux.HandleFunc("/quota/v1/budget", handleQuotaBudget)
	tlsServer := httptest.NewTLSServer(mux)
	defer tlsServer.Close()
	request := quotaRequest{ID: quotaID(), Session: quotaID(), Subscription: s.ID, Want: 20, IssuedAt: time.Now().Unix()}
	call := func(node, key string, r quotaRequest) *httptest.ResponseRecorder {
		data, _ := json.Marshal(r)
		req := httptest.NewRequest("POST", "/quota/v1/budget", bytes.NewReader(data))
		req.Header.Set("X-Atlant-Node", node)
		req.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		handleQuotaBudget(w, req)
		return w
	}
	if call("remote", "wrong", request).Code != 404 || call("local", token, request).Code != 404 {
		t.Fatal("anonymous/local identity acquired public quota access")
	}
	if call("remote", token, request).Code != 200 {
		t.Fatal("authorized node rejected")
	}
	request.ID = quotaID()
	request.Subscription = quotaID()
	if call("remote", token, request).Code == 200 {
		t.Fatal("node accessed an unassigned subscription")
	}
	keyFile := filepath.Join(t.TempDir(), "node.key")
	os.WriteFile(keyFile, []byte(token), 0600)
	if _, err := makeQuotaCall(QuotaConfig{Endpoint: "http://example.com", NodeID: "remote", NodeKeyFile: keyFile}, currentUsersStore); err == nil {
		t.Fatal("plaintext coordinator accepted")
	}
	secureCall, err := makeQuotaCall(QuotaConfig{Endpoint: tlsServer.URL, NodeID: "remote", NodeKeyFile: keyFile}, currentUsersStore)
	if err != nil {
		t.Fatal(err)
	}
	request.Subscription = s.ID
	request.ID = quotaID()
	if _, err = secureCall(context.Background(), request); err == nil {
		t.Fatal("untrusted coordinator certificate accepted")
	}
}

func TestGlobalQuotaMigrationAndTwoConnectionsOneSubscription(t *testing.T) {
	s, link := quotaFixture(t, 1000)
	// Re-saving a quota must preserve existing global counters.
	currentUsersStore.db.Exec(`UPDATE quota_accounts SET up=12,down=34 WHERE subscription_id=?`, s.ID)
	if err := initQuotaWorker(cfg.Quota); err != nil {
		t.Fatal(err)
	}
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["phone"] = &userRecord{Name: "phone", PBK: strings.Repeat("bc", 32), Enabled: true, TotalLimit: 1}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"user": "phone", "subscription": s.ID})
	w := httptest.NewRecorder()
	handleAPIQuotaBindings(w, httptest.NewRequest("PUT", "/api/quota/bindings", bytes.NewReader(data)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !recordUserTraffic("alice", 100, 0) || !recordUserTraffic("phone", 0, 200) {
		t.Fatal("shared subscription did not replace per-connection cap")
	}
	usersMu.RLock()
	b := quotaBudgetLocked("alice")
	other := quotaBudgetLocked("phone")
	usersMu.RUnlock()
	if b != other {
		t.Fatal("same subscription received independent budgets")
	}
	b.mu.Lock()
	err := b.syncLocked(false, 0)
	b.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	response := getSubscription(link)
	if response.Code != 200 || response.Header().Get("X-Subscription-Usage-Scope") != "global-subscription" || response.Header().Get("Subscription-Userinfo") != "upload=112; download=234; total=1000; expire=0" {
		t.Fatal("global metadata missing", response.Code, response.Header())
	}
	w = httptest.NewRecorder()
	handleAPIBackup(w, httptest.NewRequest("GET", "/api/backup", nil))
	if w.Code != 409 {
		t.Fatal("partial JSON backup silently omitted quota ledger")
	}
}
