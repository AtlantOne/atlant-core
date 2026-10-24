package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func subscriptionFixture(t *testing.T) (SubscriptionRecord, string) {
	t.Helper()
	isolateUsers(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: strings.Repeat("ab", 32), Enabled: true, UpBytes: 12, DownBytes: 34, TotalLimit: 1000}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cfg.Subscriptions.PublicURL = "https://198.51.100.20:8443"
	s := SubscriptionRecord{User: "alice", Title: "Личный VPN", Enabled: true, UpdateHours: 2, Nodes: []SubscriptionNode{
		{Name: "TCP", Server: "198.51.100.20:443", SNI: "example.com", ServerPubKey: strings.Repeat("cd", 32), Transport: "reality", WireVersion: 3},
		{Name: "QUIC", Server: "198.51.100.20:443", SNI: "example.com", ServerPubKey: strings.Repeat("cd", 32), Transport: "quic", WireVersion: 3},
		{Name: "Другой VDS", Server: "[2001:db8::1]:10443", SNI: "example.org", ServerPubKey: strings.Repeat("ef", 32), User: "remote", PBK: strings.Repeat("12", 32), Transport: "xhttp", WireVersion: 2},
	}}
	body, _ := json.Marshal(s)
	w := httptest.NewRecorder()
	handleAPISubscriptions(w, httptest.NewRequest(http.MethodPost, "/api/subscriptions", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatal("create subscription", w.Code, w.Body.String())
	}
	var response struct {
		Subscription SubscriptionRecord `json:"subscription"`
		URL          string             `json:"url"`
	}
	if json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal("bad response")
	}
	return response.Subscription, response.URL
}

func getSubscription(link string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	publicSubscriptionHandler(w, httptest.NewRequest(http.MethodGet, link, nil))
	return w
}

func TestSubscriptionMultiServerMetadataAndTokenRotation(t *testing.T) {
	s, link := subscriptionFixture(t)
	w := getSubscription(link)
	if w.Code != 200 || len(strings.Split(w.Body.String(), "\n")) != 3 {
		t.Fatal("multiple profiles lost", w.Code)
	}
	if w.Header().Get("Subscription-Userinfo") != "upload=12; download=34; total=1000; expire=0" || !strings.HasPrefix(w.Header().Get("Profile-Title"), "base64:") || w.Header().Get("Profile-Update-Interval") != "2" {
		t.Fatal("metadata missing")
	}
	for _, line := range strings.Split(w.Body.String(), "\n") {
		u, err := url.Parse(line)
		if err != nil || u.Query().Get("wire_version") == "" || u.Query().Get("server_pub_key") == "" {
			t.Fatal("invalid profile")
		}
	}
	parsed, _ := url.Parse(link)
	token := strings.TrimPrefix(parsed.Path, "/sub/")
	var stored string
	if err := currentUsersStore.db.QueryRow(`SELECT token_hash FROM subscriptions WHERE id=?`, s.ID).Scan(&stored); err != nil || strings.Contains(stored, token) || len(stored) != 64 {
		t.Fatal("URL secret persisted as cleartext")
	}
	body, _ := json.Marshal(struct {
		SubscriptionRecord
		Rotate bool `json:"rotate"`
	}{s, true})
	w = httptest.NewRecorder()
	handleAPISubscriptions(w, httptest.NewRequest(http.MethodPut, "/api/subscriptions", bytes.NewReader(body)))
	if w.Code != 200 {
		t.Fatal("rotate failed", w.Code, w.Body.String())
	}
	if getSubscription(link).Code != 404 {
		t.Fatal("revoked token accepted")
	}
	for _, suffix := range []string{"invalid", "../secret", token + "="} {
		if getSubscription("https://example.com/sub/"+suffix).Code != 404 {
			t.Fatal("invalid token accepted")
		}
	}
}

func TestSubscriptionBackupRestoreAndSubsequentStatsDoNotOverwriteTables(t *testing.T) {
	s, link := subscriptionFixture(t)
	w := httptest.NewRecorder()
	handleAPIBackup(w, httptest.NewRequest(http.MethodGet, "/api/backup", nil))
	backup := append([]byte(nil), w.Body.Bytes()...)
	if w.Code != 200 || !bytes.Contains(backup, []byte(`"subscriptions"`)) {
		t.Fatal("backup omitted extensions")
	}
	if _, err := currentUsersStore.db.Exec(`DELETE FROM subscriptions WHERE id=?`, s.ID); err != nil {
		t.Fatal(err)
	}
	if getSubscription(link).Code != 404 {
		t.Fatal("delete not applied")
	}
	w = httptest.NewRecorder()
	handleAPIRestore(w, httptest.NewRequest(http.MethodPost, "/api/restore", bytes.NewReader(backup)))
	if w.Code != 200 {
		t.Fatal("restore failed", w.Code, w.Body.String())
	}
	if getSubscription(link).Code != 200 {
		t.Fatal("restored token unusable")
	}
	if _, err := currentUsersStore.db.Exec(`UPDATE subscriptions SET title='new-title' WHERE id=?`, s.ID); err != nil {
		t.Fatal(err)
	}
	recordUserTraffic("alice", 1, 2)
	if err := saveUsers(cfg.UsersFile); err != nil {
		t.Fatal(err)
	}
	list, err := readSubscriptions(context.Background(), currentUsersStore)
	if err != nil || len(list) != 1 || list[0].Title != "new-title" {
		t.Fatal("RAM stats overwrote subscriptions")
	}
}

func TestSubscriptionWriteFailureIsAtomicAndUserDeletionCascades(t *testing.T) {
	s, link := subscriptionFixture(t)
	if _, err := currentUsersStore.db.Exec(`CREATE TRIGGER reject_node BEFORE INSERT ON subscription_nodes BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	s.Title = "should-not-publish"
	body, _ := json.Marshal(s)
	w := httptest.NewRecorder()
	handleAPISubscriptions(w, httptest.NewRequest(http.MethodPut, "/api/subscriptions", bytes.NewReader(body)))
	if w.Code != 500 {
		t.Fatal("SQL error hidden")
	}
	if getSubscription(link).Code != 200 {
		t.Fatal("transaction lost old nodes")
	}
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error { delete(db.Users, "alice"); return nil }); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := currentUsersStore.db.QueryRow(`SELECT count(*) FROM subscriptions`).Scan(&count); err != nil || count != 0 {
		t.Fatal("user deletion left secret subscription")
	}
}

func TestSubscriptionRevisionRejectsStaleEditorAndDoesNotChangeWithTraffic(t *testing.T) {
	s, _ := subscriptionFixture(t)
	if len(s.Revision) != 64 {
		t.Fatal("creation did not return a configuration revision")
	}
	before, err := readSubscriptions(context.Background(), currentUsersStore)
	if err != nil || len(before) != 1 || before[0].Revision != s.Revision {
		t.Fatal("creation and read revisions differ", err)
	}
	recordUserTraffic("alice", 20, 40)
	after, _ := readSubscriptions(context.Background(), currentUsersStore)
	if after[0].Revision != s.Revision {
		t.Fatal("live traffic invalidated an unrelated configuration editor")
	}
	update := func(input SubscriptionRecord) *httptest.ResponseRecorder {
		body, _ := json.Marshal(input)
		w := httptest.NewRecorder()
		handleAPISubscriptions(w, httptest.NewRequest(http.MethodPut, "/api/subscriptions", bytes.NewReader(body)))
		return w
	}
	s.Title = "First editor"
	if w := update(s); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	s.Title = "Stale editor"
	if w := update(s); w.Code != 409 {
		t.Fatal("stale editor overwrote a newer configuration", w.Code)
	}
	s.Revision = ""
	if w := update(s); w.Code != 409 {
		t.Fatal("missing revision bypassed concurrency protection", w.Code)
	}
	latest, _ := readSubscriptions(context.Background(), currentUsersStore)
	if latest[0].Title != "First editor" || latest[0].Nodes[2].PBK != strings.Repeat("12", 32) {
		t.Fatal("stale update changed metadata or remote credentials")
	}
}
