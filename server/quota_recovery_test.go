package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuotaNodeListContainsScopesButNotCredentials(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	token := quotaTestNode(t, "node2", s.ID)
	w := httptest.NewRecorder()
	handleAPIQuotaNodes(w, httptest.NewRequest("GET", "/api/quota/nodes", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var nodes []struct {
		ID            string
		Enabled       bool
		Subscriptions []string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil || len(nodes) != 1 || len(nodes[0].Subscriptions) != 1 || nodes[0].Subscriptions[0] != s.ID {
		t.Fatal("quota scopes missing", err, w.Body.String())
	}
	if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), "token_hash") {
		t.Fatal("quota credential leaked")
	}
}

func TestGlobalQuotaSQLiteSnapshotContainsReservations(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	b := testBudget(s.ID, "local")
	if !b.consume(70, 0) {
		t.Fatal("initial allowance missing")
	}
	w := httptest.NewRecorder()
	handleAPISQLiteBackup(w, httptest.NewRequest("GET", "/api/backup/sqlite", nil))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var snapshot struct {
		Format   string
		Database []byte
	}
	if json.Unmarshal(w.Body.Bytes(), &snapshot) != nil || snapshot.Format != "sqlite3-base64-v1" {
		t.Fatal("bad snapshot")
	}
	path := filepath.Join(t.TempDir(), "copy.db")
	if err := os.WriteFile(path, snapshot.Database, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	q, err := readQuota(context.Background(), db, s.ID)
	if err != nil || q.Reserved != 100 {
		t.Fatal("snapshot lost unreported reservation", q, err)
	}
	var integrity string
	if err = db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("inconsistent SQLite snapshot", err)
	}
}

func TestGlobalQuotaCleanShutdownReturnsUnusedAndPersistsUsage(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	if err := initQuotaWorker(cfg.Quota); err != nil {
		t.Fatal(err)
	}
	if !recordUserTraffic("alice", 7, 9) {
		t.Fatal("initial traffic rejected")
	}
	stopQuotaWorker()
	q, err := readQuota(context.Background(), currentUsersStore.db, s.ID)
	if err != nil || q.Up != 7 || q.Down != 9 || q.Reserved != 0 {
		t.Fatal("graceful shutdown did not settle budget", q, err)
	}
	if recordUserTraffic("alice", 1, 0) {
		t.Fatal("retired budget authorized traffic")
	}
}

func TestGlobalQuotaDeniedTrafficDoesNotSendRPCPerPacket(t *testing.T) {
	s, _ := quotaFixture(t, 1)
	b := testBudget(s.ID, "local")
	original := b.call
	var calls int
	b.call = func(ctx context.Context, r quotaRequest) (quotaReply, error) { calls++; return original(ctx, r) }
	if !b.consume(1, 0) {
		t.Fatal("first byte rejected")
	}
	for i := 0; i < 100; i++ {
		if b.consume(1, 0) {
			t.Fatal("quota exceeded")
		}
	}
	if calls > 3 {
		t.Fatalf("denied packets caused %d RPCs", calls)
	}
}

func TestGlobalQuotaReadAuthorizationDoesNotWaitForNetworkMutex(t *testing.T) {
	b := &nodeBudget{}
	b.authorization.Store(&quotaAuthorization{allowed: true, deadline: time.Now().Add(time.Minute)})
	b.mu.Lock()
	defer b.mu.Unlock()
	done := make(chan bool, 1)
	go func() { done <- b.valid() }()
	select {
	case allowed := <-done:
		if !allowed {
			t.Fatal("valid authorization lost")
		}
	case <-time.After(time.Second):
		t.Fatal("authentication waited for a network operation")
	}
}

func TestGlobalQuotaReducedLimitAndDisabledOwnerRevokeRenewal(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	b := testBudget(s.ID, "local")
	if !b.consume(10, 0) {
		t.Fatal("initial allowance missing")
	}
	if _, err := currentUsersStore.db.Exec(`UPDATE quota_accounts SET total=50 WHERE subscription_id=?`, s.ID); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	err := b.syncLocked(false, 0)
	if err != nil || b.allowed {
		t.Fatal("oversized old reservation renewed", err)
	}
	if err = b.syncLocked(true, 0); err != nil {
		t.Fatal(err)
	}
	if err = b.syncLocked(false, quotaChunk); err != nil || !b.allowed || b.capacity != 40 {
		t.Fatal("remaining reduced quota unavailable", b.capacity, err)
	}
	if _, err = currentUsersStore.db.Exec(`UPDATE users SET enabled=0 WHERE name=?`, s.User); err != nil {
		t.Fatal(err)
	}
	err = b.syncLocked(false, 0)
	b.mu.Unlock()
	if err != nil || b.valid() || b.consume(1, 0) {
		t.Fatal("disabled billing owner retained authorization", err)
	}
}

func TestGlobalQuotaOwnerDeletionCannotEraseLedger(t *testing.T) {
	s, _ := quotaFixture(t, 100)
	usersMu.Lock()
	snapshot := cloneUserDBLocked(usersDB)
	delete(snapshot.Users, s.User)
	err := currentUsersStore.save(context.Background(), snapshot, "")
	usersMu.Unlock()
	if err == nil {
		t.Fatal("owner deletion silently erased global accounting")
	}
	if _, err = readQuota(context.Background(), currentUsersStore.db, s.ID); err != nil {
		t.Fatal("ledger lost after rejected deletion", err)
	}
}
