package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func legacyMigrationFixture(t *testing.T) (*sqliteUserStore, SubscriptionRecord, string) {
	t.Helper()
	store, catalog, _ := nativeSubscriberFixture(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: strings.Repeat("ab", 32), Enabled: true, UpBytes: 123, DownBytes: 456, TotalLimit: 100000, IPLimit: 2, Note: "Keep this note"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r := catalog.Inbounds[0]
	n := SubscriptionNode{Name: "Local TCP", Server: r.Settings.AdvertiseAddr, SNI: r.Settings.SNI, ServerPubKey: r.PublicKey, Transport: "reality", WireVersion: 7}
	q := n
	q.Name = "Local QUIC"
	q.Transport = "quic"
	remote := SubscriptionNode{Name: "Remote", Server: "192.0.2.9:443", SNI: "remote.example", ServerPubKey: strings.Repeat("cd", 32), Transport: "xhttp", WireVersion: 7, User: "remote", PBK: strings.Repeat("ef", 32), XHTTPPath: "/remote"}
	s := SubscriptionRecord{User: "alice", Title: "Legacy subscription", Enabled: true, UpdateHours: 1, Nodes: []SubscriptionNode{n, q, remote}}
	w := subscriptionRequest(t, http.MethodPost, s)
	var response struct {
		Subscription SubscriptionRecord `json:"subscription"`
		URL          string             `json:"url"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal("legacy fixture failed", w.Code)
	}
	private, err := readSubscriptions(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range private {
		if record.ID == response.Subscription.ID {
			response.Subscription = record
		}
	}
	return store, response.Subscription, response.URL
}

func applyMigrationRequest(t *testing.T, plan subscriptionMigrationPlan, ids ...string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"revision": plan.Revision, "ids": ids})
	w := httptest.NewRecorder()
	handleAPISubscriptionMigration(w, httptest.NewRequest(http.MethodPost, "/api/subscriptions/migrate", bytes.NewReader(body)))
	return w
}

func TestSubscriptionMigrationPreservesLinksKeysUsageAndRemoteProfiles(t *testing.T) {
	store, s, link := legacyMigrationFixture(t)
	var closed atomic.Int32
	cleanup := trackUserSession(s.User, "192.0.2.1:1234", func() { closed.Add(1) })
	defer cleanup()
	plan, err := planSubscriptionMigration(context.Background(), store)
	if err != nil || len(plan.Items) != 1 || !plan.Items[0].Eligible || plan.Items[0].Converted != 2 || plan.Items[0].Preserved != 1 {
		t.Fatal("unexpected migration plan", err, plan.Items)
	}
	encoded, _ := json.Marshal(plan)
	if strings.Contains(string(encoded), usersDB.Users[s.User].PBK) || strings.Contains(string(encoded), s.TokenHash) || strings.Contains(string(encoded), "remote.example") {
		t.Fatal("plan exposed private profile data")
	}
	w := applyMigrationRequest(t, plan, s.ID)
	if w.Code != 200 {
		t.Fatal("migration failed", w.Code, w.Body.String())
	}
	if closed.Load() != 1 {
		t.Fatal("legacy session survived introduction of per-inbound policy")
	}
	var result struct {
		Backup string `json:"safety_backup"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Backup != "" {
		t.Fatal("migration created an automatic backup")
	}
	list, err := readSubscriptions(context.Background(), store)
	if err != nil || len(list) != 1 || !list[0].Managed || len(list[0].InboundRefs) != 1 || len(list[0].Nodes) != 1 {
		t.Fatal("wrong migrated structure", err)
	}
	got := list[0]
	if got.TokenHash != s.TokenHash || !reflect.DeepEqual(got.Nodes[0], s.Nodes[2]) || got.IPLimit != 2 || got.Note != "Keep this note" {
		t.Fatal("migration lost token, remote profile or policy")
	}
	if got.GlobalQuota == nil || got.GlobalQuota.Total != 100000 || got.GlobalQuota.Up != 123 || got.GlobalQuota.Down != 456 {
		t.Fatal("migration lost quota counters", got.GlobalQuota)
	}
	if usersDB.Users[s.User].PBK != strings.Repeat("ab", 32) || usersDB.Users[s.User].TotalLimit != 0 || usersDB.Users[s.User].UpBytes != 123 {
		t.Fatal("migration changed key or reset traffic")
	}
	if feed := getSubscription(link); feed.Code != 200 || strings.Count(strings.TrimSpace(feed.Body.String()), "\n") != 1 {
		t.Fatal("old link broken or redundant transport copies retained", feed.Code)
	}
	if w := applyMigrationRequest(t, plan, s.ID); w.Code != 409 {
		t.Fatal("migration replay accepted", w.Code)
	}
}

func TestSubscriptionMigrationDoesNotSilentlyBreakUnmatchedLocalProfile(t *testing.T) {
	store, s, _ := legacyMigrationFixture(t)
	extra := s.Nodes[0]
	extra.WireVersion = 6
	s.Nodes = append(s.Nodes, extra)
	if w := subscriptionRequest(t, http.MethodPut, s); w.Code != 200 {
		t.Fatal(w.Code)
	}
	plan, err := planSubscriptionMigration(context.Background(), store)
	if err != nil || len(plan.Items) != 1 || plan.Items[0].Eligible {
		t.Fatal("unmapped local access would be revoked silently", err)
	}
	found := false
	for _, reason := range plan.Items[0].Blockers {
		if reason == "migration_unmatched_local" {
			found = true
		}
	}
	if !found {
		t.Fatal("unmatched local profile not explained")
	}
}

func TestSubscriptionMigrationStaleAndFailedTransactionsDoNotPartiallyConvert(t *testing.T) {
	store, s, _ := legacyMigrationFixture(t)
	plan, err := planSubscriptionMigration(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.db.Exec(`CREATE TRIGGER reject_migration BEFORE INSERT ON subscription_inbound_refs BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if w := applyMigrationRequest(t, plan, s.ID); w.Code != 500 {
		t.Fatal("SQL failure ignored", w.Code)
	}
	list, _ := readSubscriptions(context.Background(), store)
	if list[0].Managed || len(list[0].Nodes) != 3 || len(list[0].InboundRefs) != 0 || usersDB.Users[s.User].TotalLimit != 100000 {
		t.Fatal("partial migration escaped transaction")
	}
	var count int
	store.db.QueryRow(`SELECT count(*) FROM quota_accounts`).Scan(&count)
	if count != 0 {
		t.Fatal("failed migration created ledger")
	}
	usersMu.Lock()
	usersDB.Users[s.User].PBK = strings.Repeat("12", 32)
	usersMu.Unlock()
	if w := applyMigrationRequest(t, plan, s.ID); w.Code != 409 {
		t.Fatal("private owner change did not invalidate plan", w.Code)
	}
}

func TestSubscriptionMigrationDoesNotTakeOverSharedLegacyOwner(t *testing.T) {
	store, s, _ := legacyMigrationFixture(t)
	s.ID = ""
	s.TokenHash = ""
	s.Title = "Second subscription"
	if w := subscriptionRequest(t, http.MethodPost, s); w.Code != 200 {
		t.Fatal(w.Code)
	}
	plan, err := planSubscriptionMigration(context.Background(), store)
	if err != nil || len(plan.Items) != 2 {
		t.Fatal("missing shared owner plan", err)
	}
	for _, item := range plan.Items {
		if item.Eligible || len(item.Blockers) == 0 {
			t.Fatal("ambiguous owner automatically converted")
		}
	}
}

func TestSubscriptionMigrationDoesNotDependOnBackupDirectory(t *testing.T) {
	store, s, _ := legacyMigrationFixture(t)
	plan, err := planSubscriptionMigration(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	previousPath, previousConfig := store.path, cfg.UsersFile
	store.path = filepath.Join(t.TempDir(), "missing", "users.db")
	cfg.UsersFile = store.path
	w := applyMigrationRequest(t, plan, s.ID)
	store.path, cfg.UsersFile = previousPath, previousConfig
	if w.Code != 200 {
		t.Fatal("migration still depends on backup directory", w.Code, w.Body.String())
	}
	list, err := readSubscriptions(context.Background(), store)
	if err != nil || !list[0].Managed {
		t.Fatal("migration did not commit", err)
	}
}

func TestSubscriptionMigrationPreservesPreviouslyUncappedUsage(t *testing.T) {
	store, s, _ := legacyMigrationFixture(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error { db.Users[s.User].TotalLimit = 0; return nil }); err != nil {
		t.Fatal(err)
	}
	plan, err := planSubscriptionMigration(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if w := applyMigrationRequest(t, plan, s.ID); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	list, err := readSubscriptions(context.Background(), store)
	if err != nil || list[0].GlobalQuota == nil || list[0].GlobalQuota.Total != 0 || list[0].GlobalQuota.Up != 123 || list[0].GlobalQuota.Down != 456 {
		t.Fatal("uncapped traffic history was reset", err)
	}
}

func TestSubscriptionMigrationDoesNotSilentlyWidenDifferentLegacyQuota(t *testing.T) {
	store, s, _ := legacyMigrationFixture(t)
	limit := uint64(200000)
	s.TotalLimit = &limit
	if w := subscriptionRequest(t, http.MethodPut, s); w.Code != 200 {
		t.Fatal(w.Code)
	}
	plan, err := planSubscriptionMigration(context.Background(), store)
	if err != nil || len(plan.Items) != 1 || plan.Items[0].Eligible {
		t.Fatal("inconsistent legacy/global caps accepted", err)
	}
	found := false
	for _, reason := range plan.Items[0].Blockers {
		if reason == "migration_conflicting_quota" {
			found = true
		}
	}
	if !found {
		t.Fatal("conflicting quota not explained")
	}
}
