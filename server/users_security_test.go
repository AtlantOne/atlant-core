package main

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestUserQuotaCannotWrapUnsignedTotal(t *testing.T) {
	for _, test := range []struct {
		up, down, limit uint64
		want            bool
	}{
		{1, 2, 0, false}, {1, 2, 4, false}, {1, 2, 3, true}, {math.MaxUint64, 1, math.MaxUint64, true}, {math.MaxUint64/2 + 1, math.MaxUint64/2 + 1, math.MaxUint64, true},
	} {
		if got := trafficLimitReached(test.up, test.down, test.limit); got != test.want {
			t.Fatalf("quota up=%d down=%d limit=%d got=%v", test.up, test.down, test.limit, got)
		}
	}
	if totalTraffic(math.MaxUint64, 1) != math.MaxUint64 {
		t.Fatal("UI total wraps instead of saturating")
	}
}

func TestTrafficCountersSaturateUnderConcurrentUpdates(t *testing.T) {
	counter := uint64(math.MaxUint64 - 100)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); addTrafficCounter(&counter, 17) }()
	}
	wg.Wait()
	if counter != math.MaxUint64 {
		t.Fatal("counter wrapped or lost saturation")
	}
}

func TestUserWriteEndpointsRejectReadMethods(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		called := false
		w := httptest.NewRecorder()
		apiWrite(func(http.ResponseWriter, *http.Request) { called = true })(w, httptest.NewRequest(method, "/api/user/disable?name=alice", nil))
		if called || w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s mutated a user", method)
		}
	}
}

func TestUserShutdownCheckpointPreservesFinalCounters(t *testing.T) {
	isolateUsers(t)
	if err := updateUsers(cfg.UsersFile, func(db *userDB) error {
		db.Users["alice"] = &userRecord{Name: "alice", PBK: "test", Enabled: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	recordUserTraffic("alice", 31, 79)
	if err := checkpointUsersOnShutdown(cfg.UsersFile); err != nil {
		t.Fatal(err)
	}
	if currentUsersStore != nil {
		t.Fatal("shutdown left database owner locked")
	}
	store, err := openSQLiteUsers(cfg.UsersFile)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := store.load(context.Background())
	if err != nil || snapshot.Users["alice"].UpBytes != 31 || snapshot.Users["alice"].DownBytes != 79 {
		t.Fatal("shutdown lost final counters")
	}
}
