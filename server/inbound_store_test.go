package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func inboundStoreFixture(t *testing.T) (*sqliteUserStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.db")
	store, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, path
}

func TestInboundMigrationKeepsIdentityUsersCountersAndSubscriptions(t *testing.T) {
	store, path := inboundStoreFixture(t)
	ctx := context.Background()
	original := sqliteFixture()
	original.Subscriptions = []SubscriptionRecord{{ID: strings.Repeat("a", 32), User: "alice", Title: "Existing subscription", Enabled: true, UpdateHours: 12, TokenHash: strings.Repeat("b", 64)}}
	if err := store.save(ctx, original, ""); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spec := inboundFixture("default", ":1026")
	backup, err := store.initializeInboundCatalog(ctx, &spec, key)
	if err != nil || backup != "" {
		t.Fatalf("migration: %v", err)
	}
	catalog, err := store.readInboundCatalog(ctx)
	if err != nil || !catalog.Initialized || catalog.Revision != 1 || len(catalog.Inbounds) != 1 {
		t.Fatalf("catalog: %#v %v", catalog, err)
	}
	if !bytes.Equal(catalog.Inbounds[0].identity.Bytes(), key.Bytes()) || catalog.Inbounds[0].PublicKey != hex.EncodeToString(key.PublicKey().Bytes()) {
		t.Fatal("migration rotated the old identity")
	}
	if !reflect.DeepEqual(catalog.Inbounds[0].Settings, spec) {
		t.Fatal("migration changed connection settings")
	}
	got, err := store.load(ctx)
	if err != nil || !reflect.DeepEqual(got.Users, original.Users) {
		t.Fatal("migration changed user records/counters", err)
	}
	var token string
	if err := store.db.QueryRow(`SELECT token_hash FROM subscriptions`).Scan(&token); err != nil || token != original.Subscriptions[0].TokenHash {
		t.Fatal("subscription link changed", err)
	}
	if copies, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".atlant-pre-inbounds-*")); len(copies) != 0 {
		t.Fatal("migration created an automatic backup")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.readInboundCatalog(ctx)
	if err != nil || after.Inbounds[0].PublicKey != catalog.Inbounds[0].PublicKey {
		t.Fatal("restart rotated identity", err)
	}
	changed := spec
	changed.SNI = "other.example.com"
	if duplicate, err := reopened.initializeInboundCatalog(ctx, &changed, nil); err != nil || duplicate != "" {
		t.Fatal("restart reimported config", err)
	}
	after, _ = reopened.readInboundCatalog(ctx)
	if after.Inbounds[0].Settings.SNI != spec.SNI {
		t.Fatal("old config overwrote migrated catalog")
	}
	serialized, err := json.Marshal(after)
	if err != nil || bytes.Contains(serialized, []byte(hex.EncodeToString(key.Bytes()))) || bytes.Contains(serialized, []byte("private_key")) || bytes.Contains(serialized, []byte("identity")) {
		t.Fatal("public catalog exposes identity", err)
	}
}

func TestInboundEditsKeepKeysRejectStaleAndValidateWholeSet(t *testing.T) {
	store, _ := inboundStoreFixture(t)
	ctx := context.Background()
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	first := inboundFixture("first", "127.0.0.1:1026")
	record, revision, err := store.putInbound(ctx, first, 1, true)
	if err != nil || revision != 2 {
		t.Fatal("create", err)
	}
	if _, _, err := store.putInbound(ctx, first, revision, true); !errors.Is(err, errInboundExists) {
		t.Fatal("duplicate create accepted", err)
	}
	first.SNI = "updated.example.com"
	updated, revision, err := store.putInbound(ctx, first, revision, false)
	if err != nil || revision != 3 || updated.PublicKey != record.PublicKey {
		t.Fatal("edit rotated key", err)
	}
	if _, _, err := store.putInbound(ctx, first, 2, false); !errors.Is(err, errInboundConflict) {
		t.Fatal("stale edit accepted", err)
	}
	second := inboundFixture("second", ":1026")
	if _, _, err := store.putInbound(ctx, second, revision, true); err == nil {
		t.Fatal("conflicting listener persisted")
	}
	second.Listen = "127.0.0.1:1027"
	if _, _, err := store.putInbound(ctx, second, revision, false); !errors.Is(err, errInboundNotFound) {
		t.Fatal("edit silently created a new inbound", err)
	}
	secondRecord, _, err := store.putInbound(ctx, second, revision, true)
	if err != nil {
		t.Fatal("failed edit changed revision", err)
	}
	if secondRecord.PublicKey == record.PublicKey {
		t.Fatal("different inbound reused an identity")
	}
	if _, err := store.deleteInbound(ctx, first.ID, revision); !errors.Is(err, errInboundConflict) {
		t.Fatal("stale delete accepted", err)
	}
}

func TestInboundEmptyCatalogDoesNotResurrectLegacyListener(t *testing.T) {
	store, path := inboundStoreFixture(t)
	ctx := context.Background()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spec := inboundFixture("default", ":1026")
	if _, err := store.initializeInboundCatalog(ctx, &spec, key); err != nil {
		t.Fatal(err)
	}
	if revision, err := store.deleteInbound(ctx, spec.ID, 1); err != nil || revision != 2 {
		t.Fatal(err)
	}
	store.Close()
	reopened, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if backup, err := reopened.initializeInboundCatalog(ctx, &spec, key); err != nil || backup != "" {
		t.Fatal("deleted listener reimported", err)
	}
	catalog, err := reopened.readInboundCatalog(ctx)
	if err != nil || !catalog.Initialized || catalog.Revision != 2 || len(catalog.Inbounds) != 0 {
		t.Fatal("empty initialized catalog lost", err)
	}
}

func TestInboundMigrationBackupAndSQLFailuresLeaveNoPartialCatalog(t *testing.T) {
	store, _ := inboundStoreFixture(t)
	ctx := context.Background()
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	spec := inboundFixture("default", ":1026")
	if _, err := store.db.Exec(`CREATE TRIGGER fail_inbound_insert BEFORE INSERT ON inbounds BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.initializeInboundCatalog(ctx, &spec, key); err == nil {
		t.Fatal("migration ignored SQL failure")
	}
	catalog, err := store.readInboundCatalog(ctx)
	if err != nil || catalog.Initialized || catalog.Revision != 0 || len(catalog.Inbounds) != 0 {
		t.Fatal("partial migration committed", err)
	}
	if _, err := store.db.Exec(`DROP TRIGGER fail_inbound_insert`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.initializeInboundCatalog(ctx, &spec, key); err != nil {
		t.Fatal("migration could not retry", err)
	}
}

func TestConcurrentInboundEditsHaveOneRevisionWinner(t *testing.T) {
	store, _ := inboundStoreFixture(t)
	ctx := context.Background()
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{"first", "second"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			spec := inboundFixture(id, "127.0.0.1:1026")
			_, _, err := store.putInbound(ctx, spec, 1, true)
			results <- err
		}(id)
	}
	wg.Wait()
	close(results)
	winners, conflicts := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, errInboundConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("concurrent edits did not serialize")
	}
}

func TestLegacyInboundConversionPreservesEffectiveSettingsWithoutDowngrade(t *testing.T) {
	c := DefaultConfig()
	c.WireVersion = 7
	c.ServerAddr, c.Path, c.AdvertiseAddr = "1026", "/custom", "192.0.2.1:1026"
	c.UpMbps, c.Bandwidth.UpMbps = 10, 20
	spec, err := legacyInboundSpec(c)
	if err != nil || spec.Listen != ":1026" || spec.UpMbps != 20 || spec.XHTTPPath != "/custom" || spec.SNI != c.SNI || spec.AdvertiseAddr != c.AdvertiseAddr {
		t.Fatal("legacy settings changed", err)
	}
	c.WireVersion = 6
	if _, err := legacyInboundSpec(c); err == nil {
		t.Fatal("legacy wire silently upgraded")
	}
	c.WireVersion, c.LegacyWire = 7, true
	if _, err := legacyInboundSpec(c); err == nil {
		t.Fatal("legacy admission silently dropped")
	}
}

func TestInboundCatalogBackupIsCompleteAndJSONRecoveryIsRejected(t *testing.T) {
	isolateUsers(t)
	ctx := context.Background()
	usersMu.Lock()
	store, err := usersStoreLocked(cfg.UsersFile)
	if err != nil {
		usersMu.Unlock()
		t.Fatal(err)
	}
	if _, err = store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		usersMu.Unlock()
		t.Fatal(err)
	}
	record, _, err := store.putInbound(ctx, inboundFixture("first", "127.0.0.1:1026"), 1, true)
	usersMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handleAPIBackup(w, httptest.NewRequest(http.MethodGet, "/api/backup", nil))
	if w.Code != http.StatusConflict {
		t.Fatal("incomplete JSON backup accepted", w.Code)
	}
	w = httptest.NewRecorder()
	handleAPIRestore(w, httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(`{"version":1,"users":{}}`)))
	if w.Code != http.StatusConflict {
		t.Fatal("JSON restore could lose native catalog", w.Code)
	}
	w = httptest.NewRecorder()
	handleAPISQLiteBackup(w, httptest.NewRequest(http.MethodGet, "/api/backup/sqlite", nil))
	if w.Code != http.StatusOK {
		t.Fatal("SQLite backup failed", w.Code, w.Body.String())
	}
	var snapshot struct {
		Format   string `json:"format"`
		Database []byte `json:"database"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &snapshot); err != nil || snapshot.Format != "sqlite3-base64-v1" {
		t.Fatal("invalid SQLite envelope", err)
	}
	path := filepath.Join(t.TempDir(), "recovery.db")
	if err := os.WriteFile(path, snapshot.Database, 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	catalog, err := recovered.readInboundCatalog(ctx)
	if err != nil || catalog.Revision != 2 || len(catalog.Inbounds) != 1 {
		t.Fatal("backup lost catalog", err)
	}
	if catalog.Inbounds[0].PublicKey != record.PublicKey || !bytes.Equal(catalog.Inbounds[0].identity.Bytes(), record.identity.Bytes()) {
		t.Fatal("backup did not preserve private identity")
	}
}

func TestInboundSQLFailureRollsBackSettingsAndRevision(t *testing.T) {
	store, _ := inboundStoreFixture(t)
	ctx := context.Background()
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	spec := inboundFixture("first", "127.0.0.1:1026")
	original, _, err := store.putInbound(ctx, spec, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE TRIGGER fail_inbound_revision BEFORE UPDATE ON inbound_catalog_meta WHEN OLD.initialized=1 BEGIN SELECT RAISE(ABORT,'fixture'); END`); err != nil {
		t.Fatal(err)
	}
	spec.SNI = "not-committed.example.com"
	if _, _, err := store.putInbound(ctx, spec, 2, false); err == nil {
		t.Fatal("failed transaction accepted")
	}
	catalog, err := store.readInboundCatalog(ctx)
	if err != nil || catalog.Revision != 2 || catalog.Inbounds[0].Settings.SNI != original.Settings.SNI || catalog.Inbounds[0].PublicKey != original.PublicKey {
		t.Fatal("failed revision update partially committed", err)
	}
}

func TestCorruptStoredInboundSettingsFailClosed(t *testing.T) {
	store, _ := inboundStoreFixture(t)
	ctx := context.Background()
	if _, err := store.initializeInboundCatalog(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	spec := inboundFixture("first", "127.0.0.1:1026")
	if _, _, err := store.putInbound(ctx, spec, 1, true); err != nil {
		t.Fatal(err)
	}
	valid, _ := json.Marshal(spec)
	spec.WireVersion = 4
	downgrade, _ := json.Marshal(spec)
	for _, settings := range [][]byte{
		[]byte(`{"id":"other"}`),
		append(append([]byte{}, valid...), []byte(` {}`)...),
		[]byte(strings.Replace(string(valid), `"id":"first"`, `"unknown":true,"id":"first"`, 1)),
		downgrade,
	} {
		if _, err := store.db.Exec(`UPDATE inbounds SET settings=? WHERE id='first'`, settings); err != nil {
			t.Fatal(err)
		}
		if _, err := store.readInboundCatalog(ctx); err == nil {
			t.Fatal("corrupt/downgraded stored inbound accepted")
		}
	}
}
