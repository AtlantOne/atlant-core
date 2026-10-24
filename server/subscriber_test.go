package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func nativeSubscriberFixture(t *testing.T) (*sqliteUserStore, inboundCatalog, string) {
	t.Helper()
	store := initializedInboundAPIFixture(t)
	ctx := context.Background()
	for i, id := range []string{"first", "second"} {
		spec := inboundFixture(id, freeInboundAddress(t))
		spec.AdvertiseAddr = spec.Listen
		spec.SNI = "localhost."
		if _, _, err := store.putInbound(ctx, spec, int64(i+1), true); err != nil {
			t.Fatal(err)
		}
	}
	catalog, err := store.readInboundCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.saveAppliedInboundCatalog(ctx, catalog); err != nil {
		t.Fatal(err)
	}
	serverID, err := localControlServerID(ctx, store.db)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Quota = QuotaConfig{Coordinator: true}
	cfg.Subscriptions.PublicURL = "https://192.0.2.8"
	quotaState.Lock()
	old := quotaState.worker
	quotaState.worker = nil
	quotaState.Unlock()
	t.Cleanup(func() { quotaState.Lock(); quotaState.worker = old; quotaState.Unlock() })
	if err := initQuotaWorker(cfg.Quota); err != nil {
		t.Fatal(err)
	}
	return store, catalog, serverID
}

func subscriptionRequest(t *testing.T, method string, s SubscriptionRecord) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleAPISubscriptions(w, httptest.NewRequest(method, "/api/subscriptions", bytes.NewReader(body)))
	return w
}

func createNativeSubscriber(t *testing.T, serverID string) (SubscriptionRecord, string) {
	t.Helper()
	limit := uint64(107374182)
	s := SubscriptionRecord{Title: "Subscriber", Enabled: true, UpdateHours: 1, TotalLimit: &limit, InboundRefs: []SubscriptionInboundRef{{ServerID: serverID, InboundID: "first"}, {ServerID: serverID, InboundID: "second"}}}
	w := subscriptionRequest(t, http.MethodPost, s)
	var response struct {
		Subscription SubscriptionRecord `json:"subscription"`
		URL          string             `json:"url"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal("native subscriber creation failed", w.Code)
	}
	return response.Subscription, response.URL
}

func TestSubscriberCreatesAccountAndReferencesAtomically(t *testing.T) {
	store, _, serverID := nativeSubscriberFixture(t)
	s, link := createNativeSubscriber(t, serverID)
	if !strings.HasPrefix(s.User, "sub-") || len(usersDB.Users) != 1 || usersDB.Users[s.User] == nil {
		t.Fatal("account was not created automatically")
	}
	if key, ok := usersStorage.GetUserPBK(s.User); !ok || key != usersDB.Users[s.User].PBK {
		t.Fatal("new account missing from authentication cache")
	}
	w := getSubscription(link)
	lines := strings.Split(w.Body.String(), "\n")
	if w.Code != 200 || len(lines) != 2 {
		t.Fatal("one profile per inbound was not exported", w.Code, len(lines))
	}
	for _, line := range lines {
		uri, err := url.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		query := uri.Query()
		if query.Get("user") != s.User || query.Get("server_id") != serverID || query.Get("path") != "/sync" || query.Get("transports") != "tcp,xhttp,quic" {
			t.Fatal("profile lost stable identity or transport settings")
		}
	}
	if !inboundUserAllowed("first", s.User) || inboundUserAllowed("third", s.User) || inboundUserAllowed("", s.User) {
		t.Fatal("subscription account not scoped to its inbounds")
	}
	if _, err := store.db.Exec(`UPDATE quota_accounts SET up=100,down=200 WHERE subscription_id=?`, s.ID); err != nil {
		t.Fatal(err)
	}
	if header := getSubscription(link).Header().Get("Subscription-Userinfo"); header != "upload=100; download=200; total=107374182; expire=0" {
		t.Fatal("shared usage duplicated across profiles", header)
	}
	if _, err := store.deleteInbound(context.Background(), "first", 3); err != errInboundReferenced {
		t.Fatal("referenced inbound could be deleted", err)
	}
}

func TestSubscriberReferenceRevocationClosesSessionsAndBlocksOldProfiles(t *testing.T) {
	store, _, serverID := nativeSubscriberFixture(t)
	s, link := createNativeSubscriber(t, serverID)
	var closed atomic.Bool
	cleanup := trackUserSession(s.User, "127.0.0.1:1234", func() { closed.Store(true) })
	defer cleanup()
	s.InboundRefs = s.InboundRefs[1:]
	w := subscriptionRequest(t, http.MethodPut, s)
	if w.Code != 200 || !closed.Load() || inboundUserAllowed("first", s.User) || !inboundUserAllowed("second", s.User) {
		t.Fatal("reference removal did not revoke existing access", w.Code)
	}
	list, err := readSubscriptions(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	s = list[0]
	s.Enabled = false
	w = subscriptionRequest(t, http.MethodPut, s)
	if w.Code != 200 || isUserAllowed(s.User) || inboundUserAllowed("second", s.User) || getSubscription(link).Code != 404 {
		t.Fatal("disabled subscription left credentials usable", w.Code)
	}
}

func TestSubscriberFailedTransactionDoesNotLeakInternalAccount(t *testing.T) {
	store, _, serverID := nativeSubscriberFixture(t)
	if _, err := store.db.Exec(`CREATE TRIGGER fail_native_refs BEFORE INSERT ON subscription_inbound_refs BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	limit := uint64(0)
	w := subscriptionRequest(t, http.MethodPost, SubscriptionRecord{Title: "No partial account", Enabled: true, UpdateHours: 1, TotalLimit: &limit, InboundRefs: []SubscriptionInboundRef{{ServerID: serverID, InboundID: "first"}}})
	if w.Code != 500 || len(usersDB.Users) != 0 {
		t.Fatal("failed commit leaked an account to memory", w.Code)
	}
	for _, table := range []string{"users", "subscriptions", "quota_accounts", "quota_bindings", "subscription_native_owners"} {
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial transaction persisted", table, count, err)
		}
	}
}

func TestSubscriberFeedUsesAppliedNotPendingInboundSettings(t *testing.T) {
	store, catalog, serverID := nativeSubscriberFixture(t)
	_, link := createNativeSubscriber(t, serverID)
	spec := catalog.Inbounds[0].Settings
	spec.SNI = "pending.example.com"
	if _, _, err := store.putInbound(context.Background(), spec, 3, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(getSubscription(link).Body.String(), spec.SNI) {
		t.Fatal("feed exposed unapplied SNI")
	}
	updated, err := store.readInboundCatalog(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.saveAppliedInboundCatalog(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(getSubscription(link).Body.String(), spec.SNI) {
		t.Fatal("feed retained copied SNI after apply")
	}
}
