package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func subscriptionAccountFixture(t *testing.T) (SubscriptionRecord, string) {
	t.Helper()
	s, link := quotaFixture(t, 1000)
	previous := serverStaticPubHexStr
	serverStaticPubHexStr = s.Nodes[0].ServerPubKey
	t.Cleanup(func() { serverStaticPubHexStr = previous })
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["bob"] = &userRecord{Name: "bob", PBK: strings.Repeat("45", 32), Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := initQuotaWorker(cfg.Quota); err != nil {
		t.Fatal(err)
	}
	return s, link
}

func attachAccount(sid, user string, node int) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"subscription": sid, "user": user, "node": node})
	w := httptest.NewRecorder()
	handleAPISubscriptionAccount(w, httptest.NewRequest("POST", "/api/subscription-account", bytes.NewReader(body)))
	return w
}

func TestSubscriptionAttachAccountAtomicAndIdempotent(t *testing.T) {
	s, link := subscriptionAccountFixture(t)
	for i := 0; i < 2; i++ {
		if w := attachAccount(s.ID, "bob", 1); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	var bound string
	if err := currentUsersStore.db.QueryRow(`SELECT subscription_id FROM quota_bindings WHERE user_name='bob'`).Scan(&bound); err != nil || bound != s.ID {
		t.Fatal("account was not bound", bound, err)
	}
	records, err := readSubscriptions(context.Background(), currentUsersStore)
	if err != nil || len(records[0].Nodes) != len(s.Nodes)+1 {
		t.Fatal("profile missing or duplicated", err)
	}
	w := getSubscription(link)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "user=bob") {
		t.Fatal("attached user absent from public subscription", w.Code)
	}
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["bob"].PBK = strings.Repeat("67", 32)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(getSubscription(link).Body.String(), "\n") {
		profile, _ := url.Parse(line)
		if profile.Query().Get("user") == "bob" && profile.Query().Get("pbk") != strings.Repeat("67", 32) {
			t.Fatal("rotated credentials not reflected in subscription")
		}
	}
}

func TestSubscriptionAttachAccountRejectsForeignEndpointAndRollsBackFailure(t *testing.T) {
	s, _ := subscriptionAccountFixture(t)
	if w := attachAccount(s.ID, "bob", 3); w.Code != 409 {
		t.Fatal("foreign server accepted", w.Code)
	}
	if _, err := currentUsersStore.db.Exec(`CREATE TRIGGER reject_attached_profile BEFORE INSERT ON subscription_nodes WHEN NEW.user_name='bob' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if w := attachAccount(s.ID, "bob", 1); w.Code != 500 {
		t.Fatal("injected failure unexpectedly committed", w.Code)
	}
	var count int
	if err := currentUsersStore.db.QueryRow(`SELECT count(*) FROM quota_bindings WHERE user_name='bob'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("binding survived failed profile transaction", count, err)
	}
	if err := currentUsersStore.db.QueryRow(`SELECT count(*) FROM subscription_nodes WHERE subscription_id=?`, s.ID).Scan(&count); err != nil || count != len(s.Nodes) {
		t.Fatal("original profiles lost on rollback", count, err)
	}
}

func TestSubscriptionAttachAccountCannotMoveAnotherSubscriptionOwner(t *testing.T) {
	s, _ := subscriptionAccountFixture(t)
	other := s
	other.User = "bob"
	body, _ := json.Marshal(other)
	w := httptest.NewRecorder()
	handleAPISubscriptions(w, httptest.NewRequest("POST", "/api/subscriptions", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = attachAccount(s.ID, "bob", 1); w.Code != 409 {
		t.Fatal("existing binding silently reassigned", w.Code)
	}
}
