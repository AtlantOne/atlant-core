package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSubscriberPolicyPersistsAndRestrictsConcurrentIPs(t *testing.T) {
	store, _, serverID := nativeSubscriberFixture(t)
	s, _ := createNativeSubscriber(t, serverID)
	s.IPLimit, s.Note = 1, "Personal device"
	w := subscriptionRequest(t, http.MethodPut, s)
	if w.Code != 200 {
		t.Fatal("policy update failed", w.Code, w.Body.String())
	}
	list, err := readSubscriptions(context.Background(), store)
	if err != nil || len(list) != 1 || list[0].IPLimit != 1 || list[0].Note != s.Note {
		t.Fatal("policy not persisted", err)
	}
	if list[0].Revision == s.Revision {
		t.Fatal("policy missing from CAS revision")
	}
	if err := reloadSubscriptionAccessLocked(); err != nil {
		t.Fatal(err)
	}
	if subscriptionIPLimit(s.User, 99) != 1 || subscriptionIPLimit("legacy", 3) != 3 {
		t.Fatal("wrong effective IP policy")
	}
	var closed atomic.Int32
	cleanup, err := reserveUserSession(s.User, "192.0.2.1:1234", func() { closed.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	same, err := reserveUserSession(s.User, "192.0.2.1:5678", func() {})
	if err != nil {
		t.Fatal("same IP consumed another slot", err)
	}
	defer same()
	if release, err := reserveUserSession(s.User, "192.0.2.2:1234", func() {}); err == nil {
		release()
		t.Fatal("extra IP admitted")
	}
	stale := subscriptionRequest(t, http.MethodPut, s)
	if stale.Code != http.StatusConflict {
		t.Fatal("stale policy revision accepted", stale.Code)
	}
	current := list[0]
	current.IPLimit = 2
	if w := subscriptionRequest(t, http.MethodPut, current); w.Code != 200 {
		t.Fatal("new limit rejected", w.Code)
	}
	if closed.Load() != 1 {
		t.Fatal("existing session not revoked on policy change")
	}
}

func TestSubscriberPolicyFailureIsAtomicAndTrailingJSONRejected(t *testing.T) {
	store, _, serverID := nativeSubscriberFixture(t)
	s, _ := createNativeSubscriber(t, serverID)
	if _, err := store.db.Exec(`CREATE TRIGGER fail_policy BEFORE INSERT ON subscription_client_policy BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	s.IPLimit, s.Note = 2, "Must roll back"
	w := subscriptionRequest(t, http.MethodPut, s)
	if w.Code != 500 {
		t.Fatal("SQL error ignored", w.Code)
	}
	list, err := readSubscriptions(context.Background(), store)
	if err != nil || list[0].IPLimit != 0 || list[0].Note != "" || subscriptionIPLimit(s.User, 0) != 0 {
		t.Fatal("failed policy leaked into storage/cache", err)
	}
	data, _ := json.Marshal(s)
	w = httptest.NewRecorder()
	handleAPISubscriptions(w, httptest.NewRequest(http.MethodPut, "/api/subscriptions", strings.NewReader(string(data)+` {}`)))
	if w.Code != 400 {
		t.Fatal("trailing JSON accepted", w.Code)
	}
}

func TestSubscriberKeyRotationRefreshesFeedWithoutLosingPolicy(t *testing.T) {
	store, _, serverID := nativeSubscriberFixture(t)
	s, link := createNativeSubscriber(t, serverID)
	s.IPLimit, s.Note = 2, "Keep policy"
	if w := subscriptionRequest(t, http.MethodPut, s); w.Code != 200 {
		t.Fatal(w.Code)
	}
	old := usersDB.Users[s.User].PBK
	w := httptest.NewRecorder()
	handleAPIUserRegenerateKey(w, httptest.NewRequest(http.MethodPost, "/api/user/regenerate-key?name="+s.User, nil))
	if w.Code != 200 {
		t.Fatal("key rotation failed", w.Code)
	}
	if usersDB.Users[s.User].PBK == old {
		t.Fatal("key not replaced")
	}
	feed := getSubscription(link)
	if feed.Code != 200 || strings.Contains(feed.Body.String(), old) || !strings.Contains(feed.Body.String(), usersDB.Users[s.User].PBK) {
		t.Fatal("subscription feed did not refresh key")
	}
	list, err := readSubscriptions(context.Background(), store)
	if err != nil || list[0].IPLimit != 2 || list[0].Note != "Keep policy" {
		t.Fatal("key rotation lost policy", err)
	}
}
