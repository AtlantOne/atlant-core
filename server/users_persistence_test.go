package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func isolateUsers(t *testing.T) {
	t.Helper()
	usersMu.Lock()
	previousDB, previousStorage, previousMTime := usersDB, usersStorage, lastUsersMTime
	previousStore := currentUsersStore
	previousAccess := subscriptionAccess.Swap(nil)
	previousDirty := usersDirty.Load()
	currentUsersStore = nil
	usersDirty.Store(false)
	previousConfig := cfg
	usersDB = &userDB{Version: 1, Users: map[string]*userRecord{}}
	usersStorage = &MemoryCachedStorage{}
	cfg = DefaultConfig()
	cfg.WireVersion, cfg.LegacyWire = 2, true // Explicit legacy fixture, not the production default.
	cfg.UsersFile = filepath.Join(t.TempDir(), "users.db")
	usersMu.Unlock()
	t.Cleanup(func() {
		usersMu.Lock()
		if currentUsersStore != nil {
			_ = currentUsersStore.Close()
		}
		currentUsersStore = previousStore
		subscriptionAccess.Store(previousAccess)
		usersDirty.Store(previousDirty)
		usersDB, usersStorage, lastUsersMTime = previousDB, previousStorage, previousMTime
		cfg = previousConfig
		usersMu.Unlock()
	})
}

func TestFirstUsersFileCreationDoesNotDeadlock(t *testing.T) {
	isolateUsers(t)
	done := make(chan struct{})
	go func() { loadUsers(cfg.UsersFile); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("initial database creation deadlocked")
	}
	data, err := os.ReadFile(cfg.UsersFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 16 || string(data[:16]) != "SQLite format 3\x00" {
		t.Fatal("not a SQLite database")
	}
}

func TestRestoreRejectsInvalidDatabaseWithoutReplacingUsers(t *testing.T) {
	isolateUsers(t)
	previous := usersDB
	for _, body := range []string{`null`, `{}`, `{"version":1,"users":{"bad":null}}`, `{"version":2,"users":{}}`, `{"version":1,"users":{"bad":{"name":"other","pbk":"key"}}}`} {
		response := httptest.NewRecorder()
		handleAPIRestore(response, httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid backup accepted: %s (%d)", body, response.Code)
		}
		if usersDB != previous {
			t.Fatal("invalid restore replaced live users")
		}
	}
}

func TestRestoreRemovesStaleCredentials(t *testing.T) {
	isolateUsers(t)
	usersDB.Users["removed"] = &userRecord{Name: "removed", PBK: "old-key"}
	_ = usersStorage.AddUser("removed", "old-key")
	response := httptest.NewRecorder()
	handleAPIRestore(response, httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(`{"version":1,"users":{}}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("restore failed: %s", response.Body.String())
	}
	if _, ok := usersStorage.GetUserPBK("removed"); ok {
		t.Fatal("removed credentials survived restore")
	}
}

func TestLoadingLegacyUsersPreservesExplicitDisabledState(t *testing.T) {
	isolateUsers(t)
	response := httptest.NewRecorder()
	body := `{"version":1,"users":{"disabled":{"pbk":"key","enabled":false},"legacy":{"pbk":"key"}}}`
	handleAPIRestore(response, httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	loadUsers(cfg.UsersFile)
	if usersDB.Users["disabled"].Enabled {
		t.Fatal("reload re-enabled a disabled user")
	}
	if !usersDB.Users["legacy"].Enabled {
		t.Fatal("legacy default for enabled was lost")
	}
}

func TestSaveFailureDoesNotDeleteExistingTarget(t *testing.T) {
	isolateUsers(t)
	target := filepath.Join(t.TempDir(), "directory-is-not-a-database")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveUsers(target); err == nil {
		t.Fatal("replaced a directory with a database")
	}
	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		t.Fatal("failed save removed original target")
	}
}

func TestSaveAndBackupDuringTrafficUpdates(t *testing.T) {
	isolateUsers(t)
	usersDB.Users["tester"] = &userRecord{Name: "tester", PBK: "test-key", Enabled: true}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 1000; i++ {
			recordUserTraffic("tester", 1, 2)
		}
	}()
	for i := 0; i < 5; i++ {
		if err := saveUsers(cfg.UsersFile); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handleAPIBackup(response, httptest.NewRequest(http.MethodGet, "/api/backup", nil))
		if response.Code != http.StatusOK {
			t.Fatal("backup failed")
		}
	}
	workers.Wait()
}
