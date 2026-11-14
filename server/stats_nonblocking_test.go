package main

import (
	"context"
	"testing"
	"time"
)

func TestStatisticsFlushDoesNotBlockTraffic(t *testing.T) {
	isolateUsers(t)
	usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: "test", Enabled: true}
	if err := saveUsers(cfg.UsersFile); err != nil {
		t.Fatal(err)
	}
	store := currentUsersStore
	occupied, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	waits := store.db.Stats().WaitCount
	done := make(chan error, 1)
	go func() { done <- saveUsers(cfg.UsersFile) }()
	deadline := time.Now().Add(time.Second)
	for store.db.Stats().WaitCount == waits && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if store.db.Stats().WaitCount == waits {
		t.Fatal("flush did not reach database wait")
	}
	traffic := make(chan bool, 1)
	started := time.Now()
	go func() { traffic <- recordUserTraffic("alice", 1400, 700) }()
	select {
	case ok := <-traffic:
		if !ok {
			t.Error("traffic rejected")
		}
		t.Logf("traffic during blocked SQLite flush: %s", time.Since(started))
	case <-time.After(200 * time.Millisecond):
		t.Error("traffic blocked behind database")
	}
	occupied.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !usersDirty.Load() {
		t.Fatal("in-flight traffic lost dirty state")
	}
	if err := saveUsers(cfg.UsersFile); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Users["alice"].UpBytes != 1400 || loaded.Users["alice"].DownBytes != 700 {
		t.Fatal("in-flight counters lost")
	}
}

func TestQueuedStatisticsCannotUndoResetOrDeletion(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "reset", true: "delete"}[remove], func(t *testing.T) {
			isolateUsers(t)
			usersDB.Users["alice"] = &userRecord{Name: "alice", PBK: "test", Enabled: true, UpBytes: 100}
			if err := saveUsers(cfg.UsersFile); err != nil {
				t.Fatal(err)
			}
			store := currentUsersStore
			usersMu.Lock()
			snapshot, revision := cloneUserDBLocked(usersDB), store.revision.Load()
			usersMu.Unlock()
			if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
				if remove {
					delete(db.Users, "alice")
				} else {
					db.Users["alice"].UpBytes = 0
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.saveUnchanged(context.Background(), snapshot, revision); err != errUsersSnapshotChanged {
				t.Fatalf("stale snapshot accepted: %v", err)
			}
			loaded, err := store.load(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if u := loaded.Users["alice"]; remove && u != nil || !remove && (u == nil || u.UpBytes != 0) {
				t.Fatal("administrative update overwritten")
			}
		})
	}
}
