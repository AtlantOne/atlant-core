package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sqliteFixture() *userDB {
	return &userDB{Version: 1, Users: map[string]*userRecord{
		"alice":    {Name: "alice", PBK: strings.Repeat("ab", 32), Enabled: true, UpBytes: math.MaxUint64, DownBytes: 1, TotalLimit: math.MaxUint64, CreatedAt: 100, ExpiresAt: 200, LastSeen: 150, LastIP: "192.0.2.1", Note: "test ' ; -- заметка", IPLimit: 3},
		"disabled": {Name: "disabled", PBK: strings.Repeat("cd", 32), Enabled: false, UpBytes: 42, DownBytes: 99, Note: "disabled stays disabled"},
	}}
}

func TestSQLiteImportRoundTripPreservesEveryFieldAndUnsignedCounters(t *testing.T) {
	legacy := filepath.Join(t.TempDir(), "users.json")
	original := sqliteFixture()
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(legacy, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := openSQLiteUsers(legacy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatal("migration altered user fields")
	}
	for _, path := range []string{legacy, legacy + ".pre-sqlite"} {
		b, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatal("migration modified source or backup")
		}
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	// A stale legacy file must never resurrect users or rotate committed keys.
	if err = os.WriteFile(legacy, []byte(`{"version":1,"users":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err = openSQLiteUsers(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err = store.load(context.Background())
	if err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("restart reimported legacy JSON or lost committed users")
	}
	var result string
	if err = store.db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil || result != "ok" {
		t.Fatal("database integrity check failed")
	}
	var engine string
	if err = store.db.QueryRow("SELECT sqlite_version()").Scan(&engine); err != nil {
		t.Fatal(err)
	}
	t.Logf("SQLite engine %s; exact uint64 roundtrip and integrity_check OK", engine)
}

func TestSQLiteRejectsBadLegacyAndDoesNotInitializeEmptyUsers(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"version":2,"users":{}}`, `{"version":1,"users":{"bad":null}}`, `{"version":1,"users":{"bad":{"pbk":""}}}`, `broken`} {
		t.Run(body, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				store, err := openSQLiteUsers(path)
				if err == nil {
					store.Close()
					t.Fatal("accepted bad JSON or skipped failed migration on restart")
				}
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != body {
				t.Fatal("damaged source on migration failure")
			}
		})
	}
	if store, err := openSQLiteUsers(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		store.Close()
		t.Fatal("missing legacy source became empty database")
	}
}

func TestSQLiteWriterLockAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.db")
	first, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := openSQLiteUsers(path)
	if err == nil {
		second.Close()
		first.Close()
		t.Fatal("two owners can overwrite each other's cache")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal("lock survived normal close:", err)
	}
	defer third.Close()
}

func TestSQLiteURIWithSpacesUnicodeAndReservedCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users привет # 100%.db")
	store, err := openSQLiteUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatal("URI opened a different path")
	}
}

func TestSQLiteFailedTransactionKeepsPreviousRows(t *testing.T) {
	s, err := openSQLiteUsers(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	original := sqliteFixture()
	if err = s.save(context.Background(), original, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_bad BEFORE INSERT ON users WHEN NEW.name='bad' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	bad := &userDB{Version: 1, Users: map[string]*userRecord{"bad": {Name: "bad", PBK: "test", Enabled: true}}}
	if err = s.save(context.Background(), bad, ""); err == nil {
		t.Fatal("injected write succeeded")
	}
	got, err := s.load(context.Background())
	if err != nil || !reflect.DeepEqual(got, original) {
		t.Fatal("partial save deleted committed users")
	}
}

func TestSQLiteRejectsCorruptionAndUnrelatedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.db")
	bad := []byte("not an sqlite database")
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := openSQLiteUsers(path); err == nil {
		s.Close()
		t.Fatal("corruption accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, bad) {
		t.Fatal("corrupt database overwritten")
	}
	other := filepath.Join(t.TempDir(), "panel.db")
	db, err := sql.Open("sqlite", other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE unrelated(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := openSQLiteUsers(other); err == nil {
		s.Close()
		t.Fatal("opened unrelated panel database")
	}
}

func TestSQLiteAPIMutationFailureDoesNotPublishCredentialsOrDeleteUsers(t *testing.T) {
	isolateUsers(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: strings.Repeat("ab", 32), Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := currentUsersStore.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []http.HandlerFunc{handleAPIUserUpdate, handleAPIUserDisable, handleAPIUserRegenerateKey, handleAPIUserDelete, handleAPIUserResetTraffic, handleAPIBulkDelete, handleAPIBulkDisable} {
		r := httptest.NewRequest(http.MethodPost, "/api/user?name=alice", strings.NewReader(`{"name":"alice","pbk":"`+strings.Repeat("cd", 32)+`","names":["alice"]}`))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("write failure reported HTTP %d", w.Code)
		}
		if usersDB.Users["alice"] == nil || !usersDB.Users["alice"].Enabled || usersDB.Users["alice"].PBK != strings.Repeat("ab", 32) {
			t.Fatal("failed mutation published in memory")
		}
		if key, ok := usersStorage.GetUserPBK("alice"); !ok || key != strings.Repeat("ab", 32) {
			t.Fatal("failed mutation published authentication cache")
		}
	}
	w := httptest.NewRecorder()
	handleAPIUserAdd(w, httptest.NewRequest(http.MethodPost, "/api/user/add", strings.NewReader(`{"name":"new","pbk":"`+strings.Repeat("cd", 32)+`"}`)))
	if w.Code != 500 || usersDB.Users["new"] != nil {
		t.Fatal("failed creation became usable")
	}
}

func TestSQLiteStatsWriteFailureRetainsDirtyAndRetries(t *testing.T) {
	isolateUsers(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: "test", Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	recordUserTraffic("alice", 13, 29)
	if _, err := currentUsersStore.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if err := saveUsers(cfg.UsersFile); err == nil || !usersDirty.Load() {
		t.Fatal("failed statistics save discarded dirty state")
	}
	if _, err := currentUsersStore.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	if err := saveUsers(cfg.UsersFile); err != nil || usersDirty.Load() {
		t.Fatal("retry failed", err)
	}
	got, err := currentUsersStore.load(context.Background())
	if err != nil || got.Users["alice"].UpBytes != 13 || got.Users["alice"].DownBytes != 29 {
		t.Fatal("retry lost counters")
	}
}
