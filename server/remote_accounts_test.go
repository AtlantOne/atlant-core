package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func remoteAccountFixture() remoteAccountInput {
	return remoteAccountInput{Owner: strings.Repeat("a", 32), Subscription: strings.Repeat("b", 32), Enabled: true, Inbounds: []string{"first"}, Endpoint: "https://coordinator.example.invalid", NodeID: "remote-test", NodeToken: strings.Repeat("c", 64)}
}

func saveRemoteFixture(t *testing.T, store *sqliteUserStore, input remoteAccountInput) *userRecord {
	t.Helper()
	usersMu.Lock()
	defer usersMu.Unlock()
	u, _, err := putRemoteAccount(context.Background(), store, input)
	if err == nil {
		err = reloadQuotaBindingsLocked()
	}
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestRemoteAccountScopeCASAndNoIndependentLedger(t *testing.T) {
	store, _, _ := nativeSubscriberFixture(t)
	input := remoteAccountFixture()
	u := saveRemoteFixture(t, store, input)
	if !inboundUserAllowed("first", u.Name) || inboundUserAllowed("second", u.Name) || !subscriptionRequiresQuota(u.Name) {
		t.Fatal("remote scope not applied")
	}
	if isUserAllowed(u.Name) {
		t.Fatal("unfunded account accepted")
	}
	usersMu.Lock()
	_, _, err := putRemoteAccount(context.Background(), store, input)
	usersMu.Unlock()
	if err == nil {
		t.Fatal("stale revision accepted")
	}
	input.Revision = 1
	input.IPLimit = 3
	input.Inbounds = []string{"second"}
	updated := saveRemoteFixture(t, store, input)
	if updated.PBK != u.PBK || inboundUserAllowed("first", u.Name) || !inboundUserAllowed("second", u.Name) || subscriptionIPLimit(u.Name, 0) != 3 {
		t.Fatal("scope/policy changed credentials or retained old access")
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM quota_accounts`).Scan(&count); err != nil || count != 0 {
		t.Fatal("follower created its own ledger", count, err)
	}
	input.Revision = 2
	input.Enabled = false
	saveRemoteFixture(t, store, input)
	if subscriptionUserAllowed(u.Name) || recordUserTraffic(u.Name, 1, 0) {
		t.Fatal("disabled remote account passed traffic")
	}
	backup, err := store.inboundMigrationBackup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := openSQLiteUsers(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	index := &subscriptionAccessIndex{Users: map[string]subscriptionUserAccess{}}
	if err := loadRemoteAccess(context.Background(), reopened, index); err != nil || index.Users[u.Name].Enabled || !index.Users[u.Name].RequireQuota {
		t.Fatal("remote policy lost in recovery", err)
	}
}

func TestRemoteAccountWithoutWorkerNeverFallsBackToUnlimited(t *testing.T) {
	store, _, _ := nativeSubscriberFixture(t)
	u := saveRemoteFixture(t, store, remoteAccountFixture())
	quotaState.Lock()
	old := quotaState.worker
	quotaState.worker = nil
	quotaState.Unlock()
	if isUserAllowed(u.Name) || recordUserTraffic(u.Name, 1, 0) {
		t.Fatal("missing worker bypassed shared quota")
	}
	quotaState.Lock()
	quotaState.worker = old
	quotaState.Unlock()
	if err := initQuotaWorker(QuotaConfig{}); err != nil {
		t.Fatal("follower cannot reload routes without a local coordinator", err)
	}
	if isUserAllowed(u.Name) {
		t.Fatal("restart reused an unpersisted authorization")
	}
	if budget := quotaBudgetLocked(u.Name); budget == nil || budget.subscription != remoteAccountFixture().Subscription {
		t.Fatal("quota route not rebuilt")
	}
}

func TestRemoteAccountRejectsBadSourcesAndUnknownInbound(t *testing.T) {
	store, _, _ := nativeSubscriberFixture(t)
	for _, change := range []func(*remoteAccountInput){
		func(c *remoteAccountInput) { c.Endpoint = "http://example.com" },
		func(c *remoteAccountInput) { c.Endpoint = "https://user:secret@example.com" },
		func(c *remoteAccountInput) { c.NodeToken = "" },
		func(c *remoteAccountInput) { c.Inbounds = []string{"missing"} },
		func(c *remoteAccountInput) { c.Inbounds = []string{"first", "first"} },
		func(c *remoteAccountInput) { c.Owner = strings.ToUpper(c.Owner) },
	} {
		input := remoteAccountFixture()
		change(&input)
		usersMu.Lock()
		_, _, err := putRemoteAccount(context.Background(), store, input)
		usersMu.Unlock()
		if err == nil {
			t.Fatal("invalid scoped remote account accepted")
		}
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM remote_accounts`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed request persisted an account", count, err)
	}
}

func TestRemoteAccountOwnerIsolationAndHTTPReadRecovery(t *testing.T) {
	store, _, _ := nativeSubscriberFixture(t)
	input := remoteAccountFixture()
	input.Enabled = false
	body, _ := json.Marshal(input)
	w := httptest.NewRecorder()
	handleAPIRemoteAccount(w, httptest.NewRequest(http.MethodPut, "/api/control/remote-account", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var first map[string]any
	if json.Unmarshal(w.Body.Bytes(), &first) != nil {
		t.Fatal("invalid reply")
	}
	w = httptest.NewRecorder()
	handleAPIRemoteAccount(w, httptest.NewRequest(http.MethodGet, "/api/control/remote-account?owner_panel="+input.Owner+"&subscription_id="+input.Subscription, nil))
	var recovered map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &recovered) != nil || recovered["pbk"] != first["pbk"] {
		t.Fatal("cannot recover lost create result", w.Code)
	}
	other := input
	other.Owner = strings.Repeat("d", 32)
	second := saveRemoteFixture(t, store, other)
	if second.Name == first["user"] || second.PBK == first["pbk"] {
		t.Fatal("two controllers share remote credentials")
	}
	w = httptest.NewRecorder()
	handleAPIBackup(w, httptest.NewRequest(http.MethodGet, "/api/backup", nil))
	if w.Code != 409 {
		t.Fatal("JSON export accepted a remote account")
	}
}

func TestRemoteQuotaUsesTheSameLedgerAsLocalTraffic(t *testing.T) {
	primary, _ := quotaFixture(t, 128)
	coordinator := currentUsersStore
	// The quota fixture migrated historical counters; this scenario starts clean.
	if _, err := coordinator.db.Exec(`UPDATE quota_accounts SET up=0,down=0,reserved=0 WHERE subscription_id=?`, primary.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.db.Exec(`INSERT INTO quota_nodes VALUES('follower','unused-test-hash',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.db.Exec(`INSERT INTO quota_node_subscriptions VALUES('follower',?)`, primary.ID); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("c", 64)
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Atlant-Node") != "follower" || r.Header.Get("Authorization") != "Bearer "+token {
			http.NotFound(w, r)
			return
		}
		var request quotaRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "invalid", 400)
			return
		}
		reply, err := processQuota(r.Context(), coordinator.db, "follower", request, time.Now())
		if err != nil {
			http.Error(w, "rejected", 409)
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer endpoint.Close()
	store, _, _ := nativeSubscriberFixture(t)
	input := remoteAccountFixture()
	input.Subscription = primary.ID
	input.Endpoint = endpoint.URL
	input.NodeID = "follower"
	u := saveRemoteFixture(t, store, input)
	budget := quotaBudgetLocked(u.Name)
	// Explicitly trust this test certificate, without disabling TLS verification.
	budget.call = remoteQuotaCall(endpoint.URL+"/quota/v1/budget", "follower", token, endpoint.Client())
	if !recordUserTraffic(u.Name, 80, 0) {
		t.Fatal("funded remote traffic rejected")
	}
	local := &nodeBudget{subscription: primary.ID, session: quotaID(), call: func(ctx context.Context, r quotaRequest) (quotaReply, error) {
		return processQuota(ctx, coordinator.db, "local", r, time.Now())
	}}
	if local.consume(1, 0) {
		t.Fatal("local traffic spent credit reserved by remote")
	}
	if !recordUserTraffic(u.Name, 48, 0) || recordUserTraffic(u.Name, 1, 0) {
		t.Fatal("remote limit did not stop at shared total")
	}
	budget.mu.Lock()
	var err error
	if budget.grant != "" {
		err = budget.syncLocked(true, 0)
	}
	budget.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := readQuota(context.Background(), coordinator.db, primary.ID)
	if err != nil || snapshot.Up != 128 || snapshot.Reserved != 0 {
		t.Fatal("shared ledger mismatch", snapshot, err)
	}
}
